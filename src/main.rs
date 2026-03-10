mod compress;
mod delta;

use compress::{Compressor, ZstdCompressor};
use indicatif::{ProgressBar, ProgressStyle};
use sha1::{Digest, Sha1};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::Instant;

const MAGIC: &[u8; 4] = b"EDLT";
const FORMAT_VERSION: u8 = 2;

fn fnv1a(data: &[u8]) -> u32 {
    let mut h: u32 = 0x811c_9dc5;
    for &b in data {
        h ^= b as u32;
        h = h.wrapping_mul(0x0100_0193);
    }
    h
}

fn read_file(path: &str) -> io::Result<Vec<u8>> {
    std::fs::read(path)
}

// ── Endianness detection from executable headers ────────────────────────────

/// Sniff endianness from ELF, Mach-O, or PE headers.
/// Returns Some(true) for LE, Some(false) for BE, None if unknown.
fn sniff_endianness(data: &[u8]) -> Option<bool> {
    if data.len() < 6 {
        return None;
    }

    // ELF: \x7fELF at bytes 0-3, byte 5 = 1 (LE) or 2 (BE)
    if data[..4] == *b"\x7fELF" {
        return match data[5] {
            1 => Some(true),
            2 => Some(false),
            _ => None,
        };
    }

    // Mach-O / fat binary
    if data.len() >= 4 {
        let m = u32::from_be_bytes([data[0], data[1], data[2], data[3]]);
        match m {
            0xFEED_FACE | 0xFEED_FACF | 0xCAFE_BABE => return Some(false),
            0xCEFA_EDFE | 0xCFFA_EDFE | 0xBEBA_FECA => return Some(true),
            _ => {}
        }
    }

    // PE (MZ header) — always little-endian
    if data[..2] == *b"MZ" {
        return Some(true);
    }

    None
}

/// Resolve endianness: manual override wins, then sniff from file data, then
/// fall back to little-endian.
fn resolve_endianness(override_le: Option<bool>, data: &[u8]) -> bool {
    if let Some(le) = override_le {
        return le;
    }
    if let Some(le) = sniff_endianness(data) {
        return le;
    }
    true // default: little-endian
}

// ── delta / patch on raw bytes ──────────────────────────────────────────────

fn encode_patch(
    base: &[u8],
    version: &[u8],
    little_endian: bool,
    compressor: &dyn Compressor,
) -> io::Result<Vec<u8>> {
    let raw_patch = delta::diff(base, version, little_endian);

    let mut payload = Vec::new();
    payload.extend_from_slice(&fnv1a(base).to_be_bytes());
    payload.extend_from_slice(&fnv1a(version).to_be_bytes());
    payload.extend_from_slice(&raw_patch);

    let compressed = compressor.compress(&payload)?;

    let mut out = Vec::with_capacity(5 + compressed.len());
    out.extend_from_slice(MAGIC);
    out.push(FORMAT_VERSION);
    out.extend_from_slice(&compressed);
    Ok(out)
}

fn decode_patch(
    base: &[u8],
    patch_file: &[u8],
    little_endian: bool,
    compressor: &dyn Compressor,
) -> io::Result<Vec<u8>> {
    if patch_file.len() < 5 || &patch_file[..4] != MAGIC {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "not an edelta patch file",
        ));
    }
    if patch_file[4] != FORMAT_VERSION {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "unsupported patch version {} (expected {})",
                patch_file[4], FORMAT_VERSION
            ),
        ));
    }

    let payload = compressor.decompress(&patch_file[5..])?;
    if payload.len() < 8 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "patch payload too short",
        ));
    }

    let base_hash = u32::from_be_bytes([payload[0], payload[1], payload[2], payload[3]]);
    let ver_hash = u32::from_be_bytes([payload[4], payload[5], payload[6], payload[7]]);

    let actual_base_hash = fnv1a(base);
    if actual_base_hash != base_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "base checksum mismatch (expected {base_hash:#010x}, got {actual_base_hash:#010x})"
            ),
        ));
    }

    let result = delta::patch(base, &payload[8..], little_endian)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let actual_ver_hash = fnv1a(&result);
    if actual_ver_hash != ver_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "output checksum mismatch (expected {ver_hash:#010x}, got {actual_ver_hash:#010x})"
            ),
        ));
    }

    Ok(result)
}

// ── CLI subcommands ─────────────────────────────────────────────────────────

fn do_diff(
    base_path: &str,
    version_path: &str,
    patch_out: Option<&str>,
    endian_override: Option<bool>,
    compressor: &dyn Compressor,
) -> io::Result<()> {
    let base = read_file(base_path)?;
    let version = read_file(version_path)?;

    let le = resolve_endianness(endian_override, &version);
    let out_data = encode_patch(&base, &version, le, compressor)?;

    match patch_out {
        Some(path) => std::fs::write(path, &out_data)?,
        None => io::stdout().write_all(&out_data)?,
    }

    eprintln!(
        "base {} bytes, version {} bytes, patch {} bytes ({})",
        base.len(),
        version.len(),
        out_data.len(),
        if le { "LE" } else { "BE" },
    );
    Ok(())
}

fn do_patch(
    base_path: &str,
    output_path: &str,
    patch_in: Option<&str>,
    endian_override: Option<bool>,
    compressor: &dyn Compressor,
) -> io::Result<()> {
    let base = read_file(base_path)?;

    let patch_file = match patch_in {
        Some(path) => read_file(path)?,
        None => {
            let mut buf = Vec::new();
            io::stdin().read_to_end(&mut buf)?;
            buf
        }
    };

    let le = resolve_endianness(endian_override, &base);
    let result = decode_patch(&base, &patch_file, le, compressor)?;

    std::fs::write(output_path, &result)?;
    eprintln!("patched {} bytes -> {} bytes", base.len(), result.len());
    Ok(())
}

// ── formatting helpers ───────────────────────────────────────────────────────

fn fmt_size(bytes: usize) -> String {
    if bytes < 1024 {
        format!("{bytes} B")
    } else if bytes < 1024 * 1024 {
        format!("{:.1} KiB", bytes as f64 / 1024.0)
    } else {
        format!("{:.1} MiB", bytes as f64 / (1024.0 * 1024.0))
    }
}

// ── push: incremental deploy to a remote host via ssh ───────────────────────

fn cache_dir() -> PathBuf {
    let home = std::env::var("HOME").unwrap_or_else(|_| ".".into());
    Path::new(&home).join(".edelta").join("cache")
}

const CACHE_MAX_FILES: usize = 5;
const CACHE_MAX_BYTES: u64 = 1_000_000_000; // 1 GB

fn save_to_cache(hash: &str, data: &[u8]) -> io::Result<()> {
    let dir = cache_dir();
    std::fs::create_dir_all(&dir)?;
    std::fs::write(dir.join(hash), data)?;
    evict_cache(&dir)
}

fn touch(path: &Path) {
    let now = filetime::FileTime::now();
    let _ = filetime::set_file_mtime(path, now);
}

fn evict_cache(dir: &Path) -> io::Result<()> {
    let mut entries: Vec<(PathBuf, u64, std::time::SystemTime)> = Vec::new();
    for e in std::fs::read_dir(dir)? {
        let e = e?;
        let meta = e.metadata()?;
        if meta.is_file() {
            let mtime = meta.modified().unwrap_or(std::time::UNIX_EPOCH);
            entries.push((e.path(), meta.len(), mtime));
        }
    }
    // Sort newest first
    entries.sort_by(|a, b| b.2.cmp(&a.2));

    let mut total: u64 = 0;
    for (i, (path, size, _)) in entries.iter().enumerate() {
        total += size;
        if i >= CACHE_MAX_FILES || total > CACHE_MAX_BYTES {
            let _ = std::fs::remove_file(path);
        }
    }
    Ok(())
}

fn sha1_digest(data: &[u8]) -> sha1::digest::Output<Sha1> {
    Sha1::digest(data)
}

fn sha1_hex(digest: &[u8]) -> String {
    digest.iter().map(|b| format!("{b:02x}")).collect()
}

fn remote_sha1(host: &str, path: &str) -> io::Result<Option<String>> {
    let output = Command::new("ssh")
        .args([host, &format!("shasum {path}")])
        .stdout(Stdio::piped())
        .stderr(Stdio::null())
        .output()?;
    if !output.status.success() {
        return Ok(None);
    }
    let stdout = String::from_utf8_lossy(&output.stdout);
    Ok(stdout.split_whitespace().next().map(|s| s.to_string()))
}

fn parse_remote(spec: &str) -> Option<(&str, &str)> {
    let colon = spec.find(':')?;
    if colon == 0 {
        return None;
    }
    Some((&spec[..colon], &spec[colon + 1..]))
}

fn ssh_upload(
    data: &[u8],
    host: &str,
    remote_path: &str,
    sha1: &[u8],
    pb: &ProgressBar,
) -> io::Result<()> {
    pb.set_message(format!("uploading to {host}:{remote_path}…"));
    let mut child = Command::new("ssh")
        .args([host, "edelta", "receive", remote_path])
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let stdin = child.stdin.take().unwrap();
    let mut encoder = zstd::Encoder::new(stdin, 19)?;
    encoder.write_all(data)?;
    let mut stdin = encoder.finish()?;
    stdin.write_all(sha1)?;
    drop(stdin);

    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "ssh upload failed",
        ))
    }
}

fn temp_path(target: &Path) -> io::Result<PathBuf> {
    let dir = target.parent().unwrap_or(Path::new("."));
    let name = target.file_name().unwrap_or_default().to_string_lossy();
    let mut rng = [0u8; 8];
    std::fs::File::open("/dev/urandom")?.read_exact(&mut rng)?;
    let suffix: String = rng.iter().map(|b| format!("{b:02x}")).collect();
    Ok(dir.join(format!(".{name}.{suffix}.tmp")))
}

fn write_and_verify(
    tmp: &Path,
    payload: &[u8],
    expected_sha1: &[u8],
    base_path: Option<&str>,
) -> io::Result<()> {
    let actual = if let Some(base) = base_path {
        let base_data = read_file(base)?;
        let le = resolve_endianness(None, &base_data);
        let compressor = ZstdCompressor::default();
        let result = decode_patch(&base_data, payload, le, &compressor)?;
        let sha1 = sha1_digest(&result);
        std::fs::write(tmp, &result)?;
        sha1
    } else {
        let mut decoder = zstd::Decoder::new(io::Cursor::new(payload))?;
        let mut hasher = Sha1::new();
        let mut file = std::fs::File::create(tmp)?;
        let mut buf = [0u8; 65536];
        loop {
            let n = decoder.read(&mut buf)?;
            if n == 0 {
                break;
            }
            hasher.update(&buf[..n]);
            file.write_all(&buf[..n])?;
        }
        hasher.finalize()
    };

    if actual.as_slice() != expected_sha1 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "SHA1 mismatch (expected {}, got {})",
                sha1_hex(expected_sha1),
                sha1_hex(actual.as_slice()),
            ),
        ));
    }
    Ok(())
}

fn do_receive(output_path: &str, base_path: Option<&str>) -> io::Result<()> {
    let mut input = Vec::new();
    io::stdin().read_to_end(&mut input)?;

    if input.len() < 20 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input too short (missing SHA1 trailer)",
        ));
    }

    let (payload, expected_sha1) = input.split_at(input.len() - 20);
    let tmp = temp_path(Path::new(output_path))?;

    match write_and_verify(&tmp, payload, expected_sha1, base_path) {
        Ok(()) => std::fs::rename(&tmp, output_path),
        Err(e) => {
            let _ = std::fs::remove_file(&tmp);
            Err(e)
        }
    }
}

fn do_push(
    local_path: &str,
    remote_spec: &str,
    endian_override: Option<bool>,
    compressor: &dyn Compressor,
) -> io::Result<()> {
    let (host, remote_path) = parse_remote(remote_spec).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid remote spec '{remote_spec}', expected host:path"),
        )
    })?;

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let local_data = read_file(local_path)?;
    let le = resolve_endianness(endian_override, &local_data);
    let file_size = local_data.len();
    let local_sha1 = sha1_digest(&local_data);
    let local_hash = sha1_hex(local_sha1.as_slice());

    // Ask the remote for the current file's SHA1
    pb.set_message(format!("querying {host}:{remote_path}…"));
    let remote_hash = remote_sha1(host, remote_path)?;

    // Skip if unchanged
    if remote_hash.as_deref() == Some(local_hash.as_str()) {
        pb.finish_and_clear();
        eprintln!("\x1b[90m{local_path}: unchanged, skipping\x1b[0m");
        return Ok(());
    }

    // Try delta if we have the remote's version cached locally
    if let Some(ref rh) = remote_hash {
        let base_path = cache_dir().join(rh);
        if base_path.exists() {
            let base_data = std::fs::read(&base_path)?;
            touch(&base_path);

            pb.set_message(format!("computing delta for {local_path}…"));
            let t0 = Instant::now();
            let patch_data = encode_patch(&base_data, &local_data, le, compressor)?;
            let delta_time = t0.elapsed();

            pb.set_message(format!("patching {host}:{remote_path}…"));
            let t0 = Instant::now();
            let ssh_ok = (|| -> io::Result<bool> {
                let mut child = Command::new("ssh")
                    .args([host, "edelta", "receive", remote_path, remote_path])
                    .stdin(Stdio::piped())
                    .stderr(Stdio::null())
                    .spawn()?;

                let mut stdin_pipe = child.stdin.take().unwrap();
                stdin_pipe.write_all(&patch_data)?;
                stdin_pipe.write_all(local_sha1.as_slice())?;
                drop(stdin_pipe);

                let status = child.wait()?;
                Ok(status.success())
            })();
            let transfer_time = t0.elapsed();

            match ssh_ok {
                Ok(true) => {
                    save_to_cache(&local_hash, &local_data)?;
                    pb.finish_and_clear();

                    let speedup = file_size as f64 / patch_data.len() as f64;
                    let total_ms = (delta_time + transfer_time).as_millis();
                    eprintln!(
                        "\x1b[32m✓\x1b[0m {local_path} → {host}:{remote_path}  \
                         \x1b[1m{}\x1b[0m patch for \x1b[1m{}\x1b[0m file \
                         (\x1b[33m{:.1}×\x1b[0m smaller, {total_ms} ms)",
                        fmt_size(patch_data.len()),
                        fmt_size(file_size),
                        speedup,
                    );
                    return Ok(());
                }
                Ok(false) => {
                    pb.set_message("ssh patch failed, falling back to full upload…");
                }
                Err(e) => {
                    pb.set_message(format!("ssh error: {e}, falling back to full upload…"));
                }
            }
        }
    }

    // Full copy fallback
    let t0 = Instant::now();
    ssh_upload(&local_data, host, remote_path, local_sha1.as_slice(), &pb)?;
    let elapsed = t0.elapsed().as_millis();
    save_to_cache(&local_hash, &local_data)?;
    pb.finish_and_clear();
    eprintln!(
        "\x1b[32m✓\x1b[0m {local_path} → {host}:{remote_path}  \
         \x1b[1m{}\x1b[0m (full copy, {elapsed} ms)",
        fmt_size(file_size),
    );
    Ok(())
}

// ── arg parsing & usage ─────────────────────────────────────────────────────

fn usage(argv0: &str) -> ! {
    eprintln!("EDelta executable differ");
    eprintln!();
    eprintln!("Usage: {argv0} [-le|-be] delta BASE VERSION [PATCH]");
    eprintln!("       {argv0} [-le|-be] patch BASE OUTPUT  [PATCH]");
    eprintln!("       {argv0} [-le|-be] push  LOCAL HOST:PATH");
    eprintln!();
    eprintln!("  Endianness is auto-detected from the ELF/Mach-O/PE header.");
    eprintln!("  -le   Force little-endian     -be   Force big-endian");
    eprintln!();
    eprintln!("  If PATCH is omitted, stdin/stdout is used.");
    eprintln!();
    eprintln!("  push  Incrementally deploy LOCAL to a remote host via ssh.");
    eprintln!("        Queries the remote SHA1, looks up a cached base in");
    eprintln!("        ~/.edelta/cache/, and sends a delta. Falls back to");
    eprintln!("        zstd-compressed full upload via ssh.");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args.first().map(|s| s.as_str()).unwrap_or("edelta");

    let mut rest = &args[1..];
    let mut endian_override: Option<bool> = None;

    match rest.first().map(|s| s.as_str()) {
        Some("-le") => {
            endian_override = Some(true);
            rest = &rest[1..];
        }
        Some("-be") => {
            endian_override = Some(false);
            rest = &rest[1..];
        }
        _ => {}
    }

    if rest.len() < 2 {
        usage(argv0);
    }

    let command = rest[0].as_str();
    let compressor = ZstdCompressor::default();

    let result = match command {
        "delta" => {
            if rest.len() < 3 {
                usage(argv0);
            }
            do_diff(
                rest[1].as_str(),
                rest[2].as_str(),
                rest.get(3).map(|s| s.as_str()),
                endian_override,
                &compressor,
            )
        }
        "patch" => {
            if rest.len() < 3 {
                usage(argv0);
            }
            do_patch(
                rest[1].as_str(),
                rest[2].as_str(),
                rest.get(3).map(|s| s.as_str()),
                endian_override,
                &compressor,
            )
        }
        "push" => {
            if rest.len() < 3 {
                usage(argv0);
            }
            do_push(rest[1].as_str(), rest[2].as_str(), endian_override, &compressor)
        }
        "receive" => {
            if rest.len() < 2 {
                usage(argv0);
            }
            do_receive(rest[1].as_str(), rest.get(2).map(|s| s.as_str()))
        }
        _ => {
            eprintln!("unknown command: {command}");
            usage(argv0);
        }
    };

    if let Err(e) = result {
        eprintln!("error: {e}");
        process::exit(1);
    }
}

mod compress;
mod delta;

use compress::{Compressor, ZstdCompressor};
use indicatif::{ProgressBar, ProgressStyle};
use memmap2::MmapMut;
use sha1::{Digest, Sha1};
use std::io::{self, Read, Write};
use std::os::unix::fs::PermissionsExt;
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
    two_pass: bool,
) -> io::Result<Vec<u8>> {
    let raw_patch = delta::diff(base, version, little_endian, two_pass);

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

/// Parse patch header, decompress, verify base checksum.
/// Returns (decompressed payload — patch data starts at [8..], version hash).
fn open_patch(
    base: &[u8],
    patch_file: &[u8],
    compressor: &dyn Compressor,
) -> io::Result<(Vec<u8>, u32)> {
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

    Ok((payload, ver_hash))
}

fn decode_patch(
    base: &[u8],
    patch_file: &[u8],
    little_endian: bool,
    compressor: &dyn Compressor,
) -> io::Result<Vec<u8>> {
    let (payload, ver_hash) = open_patch(base, patch_file, compressor)?;

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
    two_pass: bool,
) -> io::Result<()> {
    let base = read_file(base_path)?;
    let version = read_file(version_path)?;

    let le = resolve_endianness(endian_override, &version);
    let out_data = encode_patch(&base, &version, le, compressor, two_pass)?;

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
    let base = mmap_file(base_path)?;

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

fn ssh_send(
    patch: &[u8],
    sha1: &[u8],
    mode: u32,
    host: &str,
    output: &str,
    base: Option<&str>,
) -> io::Result<()> {
    let mut cmd_args: Vec<&str> = vec![host, "edelta", "receive", output];
    if let Some(b) = base {
        cmd_args.push(b);
    }
    let mut child = Command::new("ssh")
        .args(&cmd_args)
        .stdin(Stdio::piped())
        .stderr(Stdio::null())
        .spawn()?;

    let mut stdin = child.stdin.take().unwrap();
    stdin.write_all(patch)?;
    stdin.write_all(sha1)?;
    stdin.write_all(&(mode as u16).to_be_bytes())?;
    drop(stdin);

    let status = child.wait()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            "remote receive failed",
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

fn mmap_file(path: &str) -> io::Result<memmap2::Mmap> {
    let file = std::fs::File::open(path)?;
    let m = unsafe { memmap2::Mmap::map(&file)? };
    m.advise(memmap2::Advice::WillNeed)?;
    Ok(m)
}

fn write_and_verify(
    tmp: &Path,
    payload: &[u8],
    expected_sha1: &[u8],
    base_path: Option<&str>,
) -> io::Result<()> {
    let base_mmap = base_path.map(mmap_file).transpose()?;
    let base: &[u8] = base_mmap.as_deref().unwrap_or(&[]);

    let le = resolve_endianness(None, base);
    let compressor = ZstdCompressor::default();
    let (decompressed, ver_hash) = open_patch(base, payload, &compressor)?;
    let patch_data = &decompressed[8..];
    let version_len = delta::patch_output_len(patch_data);

    // Create output file and mmap it
    let out_file = std::fs::OpenOptions::new()
        .read(true)
        .write(true)
        .create(true)
        .truncate(true)
        .open(tmp)?;
    out_file.set_len(version_len as u64)?;

    if version_len == 0 {
        let actual = sha1_digest(&[]);
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
        return Ok(());
    }

    let mut out = unsafe { MmapMut::map_mut(&out_file)? };
    out.advise(memmap2::Advice::Sequential)?;

    delta::patch_into(base, patch_data, le, &mut out)
        .map_err(|e| io::Error::new(io::ErrorKind::InvalidData, e))?;

    let actual_ver_hash = fnv1a(&out);
    if actual_ver_hash != ver_hash {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            format!(
                "output checksum mismatch (expected {ver_hash:#010x}, got {actual_ver_hash:#010x})"
            ),
        ));
    }

    let actual = sha1_digest(&out);
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

    if input.len() < 22 {
        return Err(io::Error::new(
            io::ErrorKind::InvalidData,
            "input too short (missing SHA1 + mode trailer)",
        ));
    }

    let (rest, mode_bytes) = input.split_at(input.len() - 2);
    let mode = u16::from_be_bytes([mode_bytes[0], mode_bytes[1]]) as u32;
    let (payload, expected_sha1) = rest.split_at(rest.len() - 20);
    let tmp = temp_path(Path::new(output_path))?;

    match write_and_verify(&tmp, payload, expected_sha1, base_path) {
        Ok(()) => {
            std::fs::set_permissions(&tmp, PermissionsExt::from_mode(mode))?;
            std::fs::rename(&tmp, output_path)
        }
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
    two_pass: bool,
) -> io::Result<()> {
    let (host, raw_remote) = parse_remote(remote_spec).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid remote spec '{remote_spec}', expected host:path"),
        )
    })?;

    let remote_buf;
    let remote_path = if raw_remote.ends_with('/') {
        let name = Path::new(local_path).file_name().unwrap_or_default().to_string_lossy();
        remote_buf = format!("{raw_remote}{name}");
        &remote_buf
    } else {
        raw_remote
    };

    let pb = ProgressBar::new_spinner();
    pb.set_style(
        ProgressStyle::default_spinner()
            .template("{spinner:.cyan} {msg}")
            .unwrap(),
    );
    pb.enable_steady_tick(std::time::Duration::from_millis(80));

    let local_mode = std::fs::metadata(local_path)?.permissions().mode();
    let local_data = read_file(local_path)?;
    let le = resolve_endianness(endian_override, &local_data);
    let file_size = local_data.len();
    let local_sha1 = sha1_digest(&local_data);
    let local_hash = sha1_hex(local_sha1.as_slice());

    pb.set_message(format!("querying {host}:{remote_path}…"));
    let remote_hash = remote_sha1(host, remote_path)?;

    if remote_hash.as_deref() == Some(local_hash.as_str()) {
        pb.finish_and_clear();
        eprintln!("\x1b[90m{local_path}: unchanged, skipping\x1b[0m");
        return Ok(());
    }

    // Try delta against cached base, fall back to diff against empty
    let (base_data, remote_base) = match remote_hash {
        Some(ref rh) => {
            let cached = cache_dir().join(rh);
            if cached.exists() {
                touch(&cached);
                (std::fs::read(&cached)?, Some(remote_path))
            } else {
                (Vec::new(), None)
            }
        }
        None => (Vec::new(), None),
    };
    let is_delta = remote_base.is_some();

    pb.set_message(format!("encoding {local_path}…"));
    let t0 = Instant::now();
    let patch_data = encode_patch(&base_data, &local_data, le, compressor, two_pass)?;
    let encode_time = t0.elapsed();

    pb.set_message(format!("sending to {host}:{remote_path}…"));
    let t0 = Instant::now();
    let send_ok = ssh_send(
        &patch_data,
        local_sha1.as_slice(),
        local_mode,
        host,
        remote_path,
        remote_base,
    );
    let send_time = t0.elapsed();

    // If delta failed on the remote, retry against empty base
    if is_delta && send_ok.is_err() {
        pb.set_message(format!("delta failed, resending {local_path}…"));
        let t0 = Instant::now();
        let patch_data = encode_patch(&[], &local_data, le, compressor, two_pass)?;
        ssh_send(&patch_data, local_sha1.as_slice(), local_mode, host, remote_path, None)?;
        let elapsed = t0.elapsed().as_millis();
        save_to_cache(&local_hash, &local_data)?;
        pb.finish_and_clear();
        eprintln!(
            "\x1b[32m✓\x1b[0m {local_path} → {host}:{remote_path}  \
             \x1b[1m{}\x1b[0m ({elapsed} ms)",
            fmt_size(file_size),
        );
        return Ok(());
    }

    send_ok?;
    save_to_cache(&local_hash, &local_data)?;
    pb.finish_and_clear();

    let total_ms = (encode_time + send_time).as_millis();
    if is_delta {
        let speedup = file_size as f64 / patch_data.len() as f64;
        eprintln!(
            "\x1b[32m✓\x1b[0m {local_path} → {host}:{remote_path}  \
             \x1b[1m{}\x1b[0m patch for \x1b[1m{}\x1b[0m file \
             (\x1b[33m{:.1}×\x1b[0m smaller, {total_ms} ms)",
            fmt_size(patch_data.len()),
            fmt_size(file_size),
            speedup,
        );
    } else {
        eprintln!(
            "\x1b[32m✓\x1b[0m {local_path} → {host}:{remote_path}  \
             \x1b[1m{}\x1b[0m ({total_ms} ms)",
            fmt_size(file_size),
        );
    }
    Ok(())
}

// ── arg parsing & usage ─────────────────────────────────────────────────────

fn usage(argv0: &str) -> ! {
    eprintln!("EDelta executable differ");
    eprintln!();
    eprintln!("Usage: {argv0} [flags] delta BASE VERSION [PATCH]");
    eprintln!("       {argv0} [flags] patch BASE OUTPUT  [PATCH]");
    eprintln!("       {argv0} [flags] push  LOCAL HOST:PATH");
    eprintln!();
    eprintln!("Flags:");
    eprintln!("  -le   Force little-endian     -be   Force big-endian");
    eprintln!("  -2    Two-pass diff (smaller patches, slower)");
    eprintln!();
    eprintln!("  Endianness is auto-detected from ELF/Mach-O/PE headers.");
    eprintln!("  If PATCH is omitted, stdin/stdout is used.");
    process::exit(1);
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let argv0 = args.first().map(|s| s.as_str()).unwrap_or("edelta");

    let mut rest = &args[1..];
    let mut endian_override: Option<bool> = None;
    let mut two_pass = false;

    while let Some(flag) = rest.first().map(|s| s.as_str()) {
        match flag {
            "-le" => endian_override = Some(true),
            "-be" => endian_override = Some(false),
            "-2" => two_pass = true,
            _ => break,
        }
        rest = &rest[1..];
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
                two_pass,
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
            do_push(rest[1].as_str(), rest[2].as_str(), endian_override, &compressor, two_pass)
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

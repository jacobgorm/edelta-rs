mod compress;
mod delta;

use compress::{Compressor, ZstdCompressor};
use indicatif::{ProgressBar, ProgressStyle};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};
use std::time::Instant;

const MAGIC: &[u8; 4] = b"EDLT";
const FORMAT_VERSION: u8 = 1;

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
    Path::new(&home).join(".edelta")
}

fn cache_path(host: &str, remote_path: &str) -> PathBuf {
    let sanitized = remote_path.replace('/', "_");
    cache_dir().join(host).join(sanitized)
}

fn parse_remote(spec: &str) -> Option<(&str, &str)> {
    let colon = spec.find(':')?;
    if colon == 0 {
        return None;
    }
    Some((&spec[..colon], &spec[colon + 1..]))
}

fn scp_full(local: &str, host: &str, remote: &str, pb: &ProgressBar) -> io::Result<()> {
    pb.set_message("uploading (scp)…");
    let status = Command::new("scp")
        .args(["-C", local, &format!("{host}:{remote}")])
        .stdout(Stdio::null())
        .stderr(Stdio::null())
        .status()?;
    if status.success() {
        Ok(())
    } else {
        Err(io::Error::new(
            io::ErrorKind::Other,
            format!("scp exited with {status}"),
        ))
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

    let cache = cache_path(host, remote_path);
    let local_data = read_file(local_path)?;
    let le = resolve_endianness(endian_override, &local_data);
    let file_size = local_data.len();

    if cache.exists() {
        let cached_data = std::fs::read(&cache)?;
        if cached_data == local_data {
            pb.finish_and_clear();
            eprintln!(
                "\x1b[90m{local_path}: unchanged, skipping\x1b[0m"
            );
            return Ok(());
        }

        pb.set_message(format!("computing delta for {local_path}…"));
        let t0 = Instant::now();
        let patch_data = encode_patch(&cached_data, &local_data, le, compressor)?;
        let delta_time = t0.elapsed();

        pb.set_message(format!("patching {host}:{remote_path}…"));
        let t0 = Instant::now();
        let ssh_ok = (|| -> io::Result<bool> {
            let mut child = Command::new("ssh")
                .args([host, "edelta", "patch", remote_path, remote_path])
                .stdin(Stdio::piped())
                .stderr(Stdio::null())
                .spawn()?;

            child.stdin.take().unwrap().write_all(&patch_data)?;

            let status = child.wait()?;
            Ok(status.success())
        })();
        let transfer_time = t0.elapsed();

        match ssh_ok {
            Ok(true) => {
                std::fs::create_dir_all(cache.parent().unwrap())?;
                std::fs::write(&cache, &local_data)?;
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
                pb.set_message("ssh patch failed, falling back to scp…");
            }
            Err(e) => {
                pb.set_message(format!("ssh error: {e}, falling back to scp…"));
            }
        }
    }

    let t0 = Instant::now();
    scp_full(local_path, host, remote_path, &pb)?;
    let elapsed = t0.elapsed().as_millis();
    std::fs::create_dir_all(cache.parent().unwrap())?;
    std::fs::write(&cache, &local_data)?;
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
    eprintln!("        Caches the last version sent in ~/.edelta/ and only");
    eprintln!("        transmits a delta when possible. Falls back to scp.");
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

mod compress;
mod delta;

use compress::{Compressor, ZstdCompressor};
use std::io::{self, Read, Write};
use std::path::{Path, PathBuf};
use std::process::{self, Command, Stdio};

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
    little_endian: bool,
    compressor: &dyn Compressor,
) -> io::Result<()> {
    let base = read_file(base_path)?;
    let version = read_file(version_path)?;

    let out_data = encode_patch(&base, &version, little_endian, compressor)?;

    match patch_out {
        Some(path) => std::fs::write(path, &out_data)?,
        None => io::stdout().write_all(&out_data)?,
    }

    eprintln!(
        "base {} bytes, version {} bytes, patch {} bytes",
        base.len(),
        version.len(),
        out_data.len(),
    );
    Ok(())
}

fn do_patch(
    base_path: &str,
    output_path: &str,
    patch_in: Option<&str>,
    little_endian: bool,
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

    let result = decode_patch(&base, &patch_file, little_endian, compressor)?;

    std::fs::write(output_path, &result)?;
    eprintln!("patched {} bytes -> {} bytes", base.len(), result.len());
    Ok(())
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

fn scp_full(local: &str, host: &str, remote: &str) -> io::Result<()> {
    let dest = format!("{host}:{remote}");
    eprintln!("scp {local} -> {dest}");
    let status = Command::new("scp")
        .args(["-C", local, &dest])
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
    little_endian: bool,
    compressor: &dyn Compressor,
) -> io::Result<()> {
    let (host, remote_path) = parse_remote(remote_spec).ok_or_else(|| {
        io::Error::new(
            io::ErrorKind::InvalidInput,
            format!("invalid remote spec '{remote_spec}', expected host:path"),
        )
    })?;

    let cache = cache_path(host, remote_path);
    let local_data = read_file(local_path)?;

    if cache.exists() {
        let cached_data = std::fs::read(&cache)?;
        if cached_data == local_data {
            eprintln!("{local_path}: unchanged, skipping");
            return Ok(());
        }

        // Try incremental patch via ssh
        eprintln!("patching {local_path} -> {host}:{remote_path}");
        let patch_data = encode_patch(&cached_data, &local_data, little_endian, compressor)?;

        let ssh_ok = (|| -> io::Result<bool> {
            // ssh $host "edelta patch $remote $remote"
            // pipe the patch to stdin
            let mut child = Command::new("ssh")
                .args([host, "edelta", "patch", remote_path, remote_path])
                .stdin(Stdio::piped())
                .spawn()?;

            child.stdin.take().unwrap().write_all(&patch_data)?;

            let status = child.wait()?;
            Ok(status.success())
        })();

        match ssh_ok {
            Ok(true) => {
                std::fs::create_dir_all(cache.parent().unwrap())?;
                std::fs::write(&cache, &local_data)?;
                eprintln!(
                    "done ({} byte patch for {} byte file)",
                    patch_data.len(),
                    local_data.len()
                );
                return Ok(());
            }
            Ok(false) => eprintln!("ssh patch failed, falling back to scp"),
            Err(e) => eprintln!("ssh patch error: {e}, falling back to scp"),
        }
    }

    // Full copy fallback (or first time)
    scp_full(local_path, host, remote_path)?;
    std::fs::create_dir_all(cache.parent().unwrap())?;
    std::fs::write(&cache, &local_data)?;
    Ok(())
}

// ── arg parsing & usage ─────────────────────────────────────────────────────

fn usage(argv0: &str) -> ! {
    eprintln!("EDelta executable differ");
    eprintln!();
    eprintln!("Usage: {argv0} [-be] delta BASE VERSION [PATCH]");
    eprintln!("       {argv0} [-be] patch BASE OUTPUT  [PATCH]");
    eprintln!("       {argv0} [-be] push  LOCAL HOST:PATH");
    eprintln!();
    eprintln!("  -be   Assume big-endian integer encoding (default: little-endian)");
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
    let mut little_endian = true; // default: little-endian

    if rest.first().is_some_and(|a| a == "-be") {
        little_endian = false;
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
                little_endian,
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
                little_endian,
                &compressor,
            )
        }
        "push" => {
            if rest.len() < 3 {
                usage(argv0);
            }
            do_push(rest[1].as_str(), rest[2].as_str(), little_endian, &compressor)
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

# EDelta

A delta compression tool optimized for executables. Produces small patches
between similar binaries by tolerating relocatable address differences within
matches, rather than breaking them into separate copy/insert hunks.

This is a ground-up Rust reimplementation of the original EDelta C tool by
Jacob Gorm Hansen (Copyright 2003-2006, GPL v2). The algorithm has been
substantially reworked: GearHash replaces the polynomial rolling hash, zstd
replaces gzip, LEB128 replaces the custom varint encoding, and the wire format
is new and incompatible with the original. A built-in `cp` command provides
incremental remote file transfer over SSH with delta compression.

Copyright 2026 Dropbox, Inc.

## Usage

```
edelta [flags] delta BASE VERSION [PATCH]   # create patch
edelta [flags] patch BASE OUTPUT  [PATCH]   # apply patch
edelta [flags] cp    SRC DST                # remote copy via ssh
ecp [flags] SRC DST                         # shorthand (symlink edelta to ecp)
```

`cp` works like `scp` but transfers only the delta when possible. Either `SRC`
or `DST` can be `host:path` for remote operation. Direction is auto-detected.

### Flags

- `-le` / `-be` — force little- or big-endian (auto-detected from ELF/Mach-O/PE headers by default)
- `-zN` — zstd compression level (default 3, max 19)
- `--2pass` — two-pass diff for smaller patches (slower)
- `-q` — quiet mode (suppress progress bars and status output)

### Examples

```
# push a binary to a remote host
edelta cp target/release/myapp server:bin/myapp

# pull a binary from a remote host
edelta cp server:bin/myapp ./myapp

# using ecp shorthand
ecp target/release/myapp server:bin/

# create and apply a patch locally
edelta delta old_binary new_binary patch.edlt
edelta patch old_binary output_binary patch.edlt
```

## Building

```
cargo build --release
ln -s target/release/edelta target/release/ecp   # optional shorthand
```

Remote hosts need `edelta` in `$PATH` for `cp` to work.

## Benchmark vs bsdiff

Test corpus of 11 binary pairs (ELF, Mach-O, PE) on Apple M2 Max.

| Test | File size | edelta -z3 | | edelta --2pass -z19 | | bsdiff | |
|---|--:|--:|--:|--:|--:|--:|--:|
| | | **ratio** | **time** | **ratio** | **time** | **ratio** | **time** |
| epiphany-ia32 | 848 KiB | 16.0% | 59ms | 12.8% | 105ms | 10.2% | 817ms |
| hello-ppc | 55 B | 164% | 45ms | 164% | 52ms | 327% | 39ms |
| runclient-ppc | 8.3 KiB | 13.9% | 50ms | 12.8% | 68ms | 6.0% | 40ms |
| user32_12 | 541 KiB | 24.2% | 51ms | 24.2% | 103ms | 15.7% | 145ms |
| user32_prebbt | 541 KiB | 5.9% | 61ms | 7.5% | 84ms | 5.0% | 107ms |
| user32 | 563 KiB | 29.0% | 59ms | 32.4% | 113ms | 11.1% | 128ms |
| vim-ppc | 1.0 MiB | 4.6% | 61ms | 5.0% | 94ms | 3.6% | 216ms |
| vlad | 100 KiB | 102.9% | 56ms | 33.6% | 85ms | 28.2% | 75ms |
| **warp-cli** | **15.0 MiB** | **0.012%** | **201ms** | **0.010%** | **309ms** | **0.001%** | **2192ms** |
| wget-ppc | 259 KiB | 24.9% | 57ms | 20.2% | 96ms | 16.9% | 88ms |
| xpdf-ppc | 848 KiB | 40.3% | 63ms | 33.2% | 196ms | 38.7% | 460ms |

Ratio = patch size as % of the new file size. Lower is better.

**Takeaways:**

- edelta -z3 is **2-10x faster** than bsdiff, with moderately larger patches.
- --2pass -z19 trades speed for ~10% better compression, but the two-pass
  heuristic occasionally backfires (user32, user32_prebbt).
- bsdiff generally compresses better on small test binaries thanks to its
  suffix-sort algorithm.
- On large near-identical binaries (warp-cli), all tools produce tiny patches
  but edelta is 10x faster (201ms vs 2192ms).

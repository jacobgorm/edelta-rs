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

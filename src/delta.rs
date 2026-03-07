use std::collections::HashMap;

const PREFIX_LEN: usize = 32;
const TOLERANCE: usize = 4;
const HASH_SIZE: usize = 0x10000;
const HASH_MASK: u32 = (HASH_SIZE - 1) as u32;
const MIN_BYTES_SAVED: i32 = 8;

// ── Gear hash (u32 → 32-byte effective window, matching PREFIX_LEN) ─────────

const fn make_gear_table() -> [u32; 256] {
    let mut t = [0u32; 256];
    let mut s: u64 = 0x9E3779B97F4A7C15;
    let mut i = 0;
    while i < 256 {
        s = s.wrapping_add(0x9E3779B97F4A7C15);
        let mut z = s;
        z = (z ^ (z >> 30)).wrapping_mul(0xBF58476D1CE4E5B9);
        z = (z ^ (z >> 27)).wrapping_mul(0x94D049BB133111EB);
        z = z ^ (z >> 31);
        t[i] = z as u32;
        i += 1;
    }
    t
}

static GEAR: [u32; 256] = make_gear_table();

fn gear_init(data: &[u8], start: usize, len: usize) -> u32 {
    let mut h: u32 = 0;
    for i in 0..len {
        let b = data.get(start + i).copied().unwrap_or(0);
        h = h.wrapping_shl(1).wrapping_add(GEAR[b as usize]);
    }
    h
}

fn gear_roll(h: u32, new_byte: u8) -> u32 {
    h.wrapping_shl(1).wrapping_add(GEAR[new_byte as usize])
}

// ── Varint codec ─────────────────────────────────────────────────────────────

/// Swap bits 0-1 with bits 7-8 for better varint compression of aligned offsets
fn swap_bits(x: u32) -> u32 {
    ((x & 3) << 7) | ((x & 0x180) >> 7) | (x & 0xFFFF_FE7C)
}

struct Writer {
    buf: Vec<u8>,
}

impl Writer {
    fn new() -> Self {
        Self { buf: Vec::new() }
    }

    fn write_i32be(&mut self, v: i32) {
        self.buf.extend_from_slice(&v.to_be_bytes());
    }

    fn write_bytes(&mut self, data: &[u8]) {
        self.buf.extend_from_slice(data);
    }

    fn write_varint(&mut self, v: u32) {
        self.write_varint_rle(v, 1);
    }

    fn write_varint_rle(&mut self, v: u32, n: u32) {
        let (width, encoded) = if v < 0x80 {
            (1u32, v)
        } else if v < 0x2000 {
            (2, v | (4 << 13))
        } else if v < 0x20_0000 {
            (3, v | (5 << 21))
        } else if v < 0x2000_0000 {
            (4, v | (6 << 29))
        } else {
            panic!("varint overflow: {v:#x}");
        };

        let mut count = n;
        if n > 1 && (n > 2 || width > 1) {
            let r: u16 = (7 << 13) | (n as u16);
            self.buf.push((r >> 8) as u8);
            self.buf.push(r as u8);
            count = 1;
        }

        for _ in 0..count {
            for j in (0..width).rev() {
                self.buf.push((encoded >> (j * 8)) as u8);
            }
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
    rle_count: u32,
    rle_val: u32,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self {
            data,
            pos: 0,
            rle_count: 0,
            rle_val: 0,
        }
    }

    fn byte(&mut self) -> u8 {
        let b = self.data[self.pos];
        self.pos += 1;
        b
    }

    fn read_i32be(&mut self) -> i32 {
        let b = [self.byte(), self.byte(), self.byte(), self.byte()];
        i32::from_be_bytes(b)
    }

    fn read_bytes(&mut self, n: usize) -> &'a [u8] {
        let s = &self.data[self.pos..self.pos + n];
        self.pos += n;
        s
    }

    fn read_varint(&mut self) -> u32 {
        if self.rle_count > 0 {
            self.rle_count -= 1;
            return self.rle_val;
        }

        let h = self.byte() as u32;
        if (h >> 5) == 7 {
            let c = self.byte() as u32;
            self.rle_count = ((h & 0x1F) << 8 | c) - 1;
            let h2 = self.byte() as u32;
            self.rle_val = self.decode_body(h2);
            return self.rle_val;
        }
        self.decode_body(h)
    }

    fn decode_body(&mut self, h: u32) -> u32 {
        if h & 0x80 == 0 {
            h & 0x7F
        } else {
            let extra = (h >> 5) as usize - 3;
            let mut v = h & 0x1F;
            for _ in 0..extra {
                v = v << 8 | self.byte() as u32;
            }
            v
        }
    }
}

// ── Helpers ──────────────────────────────────────────────────────────────────

fn get_byte(buf: &[u8], off: usize) -> u8 {
    buf.get(off).copied().unwrap_or(0)
}

fn get_delta_val(
    base: &[u8],
    bo: usize,
    ver: &[u8],
    vo: usize,
    width: usize,
    le: bool,
) -> i32 {
    let mut a: i32 = 0;
    let mut b: i32 = 0;
    for i in 0..width {
        let idx = if le { (width - 1) - i } else { i };
        a = a << 8 | get_byte(base, bo + idx) as i32;
        b = b << 8 | get_byte(ver, vo + idx) as i32;
    }
    b.wrapping_sub(a)
}

fn bufs_eq(a: &[u8], ao: usize, b: &[u8], bo: usize, len: usize) -> bool {
    ao + len <= a.len()
        && bo + len <= b.len()
        && a[ao..ao + len] == b[bo..bo + len]
}

// ── Diff (encode) ────────────────────────────────────────────────────────────

struct DeltaEntry {
    delta: i32,
    bytes_saved: i32,
    offsets: Vec<u32>,
}

struct MatchEntry {
    hash: u32,
    is_base: bool,
    offset: u32,
    next: u32, // 0 = end of chain
}

pub fn diff(base: &[u8], version: &[u8], little_endian: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_varint(version.len() as u32);

    if version.is_empty() {
        w.write_varint_rle(0, 4);
        w.write_i32be(0);
        return w.buf;
    }

    let mut dead_ends: Vec<i32> = Vec::new();
    let mut final_deltas: Vec<DeltaEntry> = Vec::new();

    for pass in 0..2u8 {
        let mut hash_run: Vec<u16> = vec![0; HASH_SIZE];
        let mut hash_first: Vec<u32> = vec![0; HASH_SIZE];
        let mut mtab: Vec<MatchEntry> = Vec::with_capacity(0x4000);
        // Index 0 is a sentinel (never used as a real entry)
        mtab.push(MatchEntry {
            hash: 0,
            is_base: false,
            offset: 0,
            next: 0,
        });

        let mut deltas: HashMap<i32, DeltaEntry> = HashMap::new();

        let mut h_b = gear_init(base, 0, PREFIX_LEN);
        let mut h_v = gear_init(version, 0, PREFIX_LEN);

        let mut v_start: usize = 0;
        let mut v_offset: usize = 0;
        let mut b_offset: usize = 0;
        let mut b_last_copy: usize = 0;
        let mut run: u16 = 1;

        // For hunk delta-encoding (pass 1 only)
        let mut prev_vs: u32 = 0;
        let mut prev_vc: u32 = 0;
        let mut prev_bc: u32 = 0;

        loop {
            let mut _found_match = false;

            for file_idx in 0..2u8 {
                let (is_base, h, offset) = if file_idx == 0 {
                    (true, h_b, b_offset)
                } else {
                    (false, h_v, v_offset)
                };

                let bucket = (h & HASH_MASK) as usize;
                let mut idx =
                    if hash_run[bucket] == run { hash_first[bucket] } else { 0 };
                let mut prev_link: u32 = 0;

                while idx != 0 && mtab[idx as usize].hash != h {
                    prev_link = idx;
                    idx = mtab[idx as usize].next;
                }

                if idx != 0 {
                    let m_is_base = mtab[idx as usize].is_base;
                    let m_offset = mtab[idx as usize].offset as usize;

                    // Only match across different files
                    if m_is_base != is_base {
                        let (cur_data, cur_off) =
                            if is_base { (base, offset) } else { (version, offset) };
                        let (m_data, m_off) = if m_is_base {
                            (base, m_offset)
                        } else {
                            (version, m_offset)
                        };

                        if bufs_eq(cur_data, cur_off, m_data, m_off, PREFIX_LEN) {
                            let (mut b_copy, mut v_copy) = if m_is_base {
                                (m_offset, offset)
                            } else {
                                (offset, m_offset)
                            };

                            // ── Backward scan ──
                            let mut ahead: usize = 0;
                            let mut faults: usize = 0;

                            while b_copy
                                .checked_sub(ahead + 1)
                                .is_some_and(|v| v >= b_last_copy)
                                && v_copy
                                    .checked_sub(ahead + 1)
                                    .is_some_and(|v| v >= v_start)
                            {
                                ahead += 1;
                                let cb = get_byte(base, b_copy - ahead);
                                let cv = get_byte(version, v_copy - ahead);

                                if cb != cv {
                                    faults += 1;
                                } else if faults > 0 {
                                    let d = get_delta_val(
                                        base,
                                        b_copy - (ahead - 1),
                                        version,
                                        v_copy - (ahead - 1),
                                        faults,
                                        little_endian,
                                    );
                                    if !dead_ends.is_empty()
                                        && dead_ends.binary_search(&d).is_ok()
                                    {
                                        ahead = 0;
                                        faults = 0;
                                        break;
                                    }
                                    faults = 0;
                                }
                                if faults > TOLERANCE {
                                    ahead -= faults;
                                    break;
                                }
                            }

                            if ahead > 0 && faults > 0 {
                                let d = get_delta_val(
                                    base,
                                    b_copy - ahead,
                                    version,
                                    v_copy - ahead,
                                    faults,
                                    little_endian,
                                );
                                if !dead_ends.is_empty()
                                    && dead_ends.binary_search(&d).is_ok()
                                {
                                    ahead -= faults;
                                }
                            }

                            faults = 0;
                            b_copy -= ahead;
                            v_copy -= ahead;

                            // ── Forward scan ──
                            let mut l: usize = 0;

                            // Track which delta entry (if any) should get
                            // bytes_saved credit on each forward step.
                            let mut active_delta: Option<i32> = None;
                            let mut scan_broke = false;

                            while v_copy + l < version.len() {
                                let cb = get_byte(base, b_copy + l);
                                let cv = get_byte(version, v_copy + l);

                                if cb != cv {
                                    faults += 1;
                                } else if faults > 0 {
                                    let d = get_delta_val(
                                        base,
                                        b_copy + l - faults,
                                        version,
                                        v_copy + l - faults,
                                        faults,
                                        little_endian,
                                    );

                                    if dead_ends.is_empty()
                                        || dead_ends.binary_search(&d).is_err()
                                    {
                                        let delta_off = if little_endian {
                                            (v_copy + l - faults) as u32
                                        } else {
                                            (v_copy + l - TOLERANCE) as u32
                                        };

                                        let entry = deltas
                                            .entry(d)
                                            .or_insert_with(|| DeltaEntry {
                                                delta: d,
                                                bytes_saved: 0,
                                                offsets: Vec::new(),
                                            });
                                        entry.offsets.push(delta_off);
                                        active_delta = Some(d);
                                        faults = 0;
                                    } else {
                                        l -= faults;
                                        scan_broke = true;
                                        break;
                                    }
                                }

                                if faults > TOLERANCE {
                                    l -= faults - 1;
                                    scan_broke = true;
                                    break;
                                }

                                if let Some(dk) = active_delta {
                                    if let Some(e) = deltas.get_mut(&dk) {
                                        e.bytes_saved += 1;
                                    }
                                }
                                l += 1;
                            }

                            // Only trim trailing faults when the loop exited
                            // normally (EOF) — the break paths already adjusted l.
                            if !scan_broke && faults > 0 {
                                l -= faults;
                            }

                            // ── Emit hunk (pass 1) ──
                            if pass == 1 {
                                let vs = v_start as u32;
                                let vc = v_copy as u32;
                                let bc = b_copy as u32;
                                w.write_varint(vs - prev_vs);
                                w.write_varint(vc - prev_vc);
                                w.write_varint(bc - prev_bc);
                                w.write_varint(l as u32);
                                w.write_bytes(&version[v_start..v_copy]);
                                prev_vs = vs;
                                prev_vc = vc;
                                prev_bc = bc;
                            }

                            b_last_copy = b_copy;
                            v_offset = v_copy + l;
                            b_offset = b_copy + l;

                            h_b = gear_init(base, b_offset, PREFIX_LEN);
                            h_v = gear_init(version, v_offset, PREFIX_LEN);

                            run = run.wrapping_add(1);
                            if run == 0 {
                                hash_run.fill(0);
                                run = 1;
                            }
                            v_start = v_offset;
                            _found_match = true;
                            break; // break file_idx loop
                        }
                    }
                }

                // No match in chain — add new entry
                if idx == 0 {
                    let new_idx = mtab.len() as u32;
                    mtab.push(MatchEntry {
                        hash: h,
                        is_base,
                        offset: offset as u32,
                        next: 0,
                    });

                    if hash_run[bucket] != run {
                        hash_run[bucket] = run;
                        hash_first[bucket] = new_idx;
                    } else if prev_link != 0 {
                        mtab[prev_link as usize].next = new_idx;
                    }
                }
            } // end file_idx

            // Check if a match (or prior state) already consumed all of version
            if v_offset >= version.len() {
                if pass == 1 && v_start < version.len() {
                    let vs = v_start as u32;
                    let vc = version.len() as u32;
                    let bc = b_offset as u32;
                    w.write_varint(vs - prev_vs);
                    w.write_varint(vc - prev_vc);
                    w.write_varint(bc - prev_bc);
                    w.write_varint(0);
                    w.write_bytes(&version[v_start..]);
                }
                break;
            }

            // Roll hashes forward and advance offsets
            h_b = gear_roll(h_b, get_byte(base, b_offset + PREFIX_LEN));
            h_v = gear_roll(h_v, get_byte(version, v_offset + PREFIX_LEN));
            v_offset += 1;
            b_offset += 1;

            if v_offset >= version.len() {
                if pass == 1 && v_start < version.len() {
                    let vs = v_start as u32;
                    let vc = version.len() as u32;
                    let bc = b_offset as u32;
                    w.write_varint(vs - prev_vs);
                    w.write_varint(vc - prev_vc);
                    w.write_varint(bc - prev_bc);
                    w.write_varint(0);
                    w.write_bytes(&version[v_start..]);
                }
                break;
            }
        } // end main loop

        if pass == 0 {
            for entry in deltas.values() {
                if entry.bytes_saved < MIN_BYTES_SAVED {
                    dead_ends.push(entry.delta);
                }
            }
            dead_ends.sort();
            dead_ends.dedup();
        } else {
            final_deltas = deltas.into_values().collect();
        }
    } // end pass

    // Hunk stream terminator: 4× varint(0)
    w.write_varint_rle(0, 4);

    // Delta table
    for entry in &final_deltas {
        w.write_i32be(entry.delta);
        w.write_varint(entry.offsets.len() as u32);

        let mut sub: u32 = 0;
        let mut i = 0;
        while i < entry.offsets.len() {
            let v = entry.offsets[i] - sub;

            let mut rept: u32 = 0;
            while i + rept as usize + 1 < entry.offsets.len()
                && entry.offsets[i + rept as usize + 1]
                    - entry.offsets[i + rept as usize]
                    == v
            {
                rept += 1;
            }

            w.write_varint_rle(swap_bits(v), rept + 1);
            i += rept as usize;
            sub = entry.offsets[i];
            i += 1;
        }
    }

    // Delta table terminator
    w.write_i32be(0);

    w.buf
}

// ── Patch (decode) ───────────────────────────────────────────────────────────

pub fn patch(base: &[u8], patch_data: &[u8], little_endian: bool) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(patch_data);

    let version_len = r.read_varint() as usize;
    let mut dest = vec![0u8; version_len];

    // Read hunks
    let mut v_start: usize = 0;
    let mut v_copy: usize = 0;
    let mut b_copy: usize = 0;

    loop {
        let vsd = r.read_varint() as usize;
        let vcd = r.read_varint() as usize;
        let bcd = r.read_varint() as usize;
        let l = r.read_varint() as usize;

        if l == 0 && vsd == 0 && vcd == 0 && bcd == 0 {
            break;
        }

        v_start += vsd;
        v_copy += vcd;
        b_copy += bcd;

        // Copy literal data from patch
        if v_copy > v_start {
            let literal = r.read_bytes(v_copy - v_start);
            dest[v_start..v_copy].copy_from_slice(literal);
        }

        // Copy from base (may extend past base; C version reads what's available)
        if l > 0 {
            let avail = base.len().saturating_sub(b_copy).min(l);
            if avail > 0 {
                dest[v_copy..v_copy + avail]
                    .copy_from_slice(&base[b_copy..b_copy + avail]);
            }
            // Bytes beyond base remain 0 — the delta table will fix them
        }
    }

    // Apply delta table
    loop {
        let delta = r.read_i32be();
        if delta == 0 {
            break;
        }

        let width = TOLERANCE;
        let num_elems = r.read_varint() as usize;
        let mut offset: u32 = 0;

        for _ in 0..num_elems {
            offset += swap_bits(r.read_varint());
            let off = offset as usize;

            if little_endian {
                let mut a: i32 = 0;
                for j in 0..width {
                    a = (a << 8) | dest.get(off + (width - 1) - j).copied().unwrap_or(0) as i32;
                }
                a = a.wrapping_add(delta);
                for j in 0..width {
                    if off + j < dest.len() {
                        dest[off + j] = a as u8;
                        a >>= 8;
                    }
                }
            } else {
                let mut a: i32 = 0;
                for j in 0..width {
                    a = (a << 8) | dest.get(off + j).copied().unwrap_or(0) as i32;
                }
                a = a.wrapping_add(delta);
                for j in (0..width).rev() {
                    if off + j < dest.len() {
                        dest[off + j] = a as u8;
                        a >>= 8;
                    }
                }
            }
        }
    }

    Ok(dest)
}

#[cfg(test)]
mod tests {
    use super::*;

    #[test]
    fn roundtrip_identical() {
        let data = b"Hello, world! This is a test of the edelta algorithm.";
        let patch_data = diff(data, data, false);
        let result = patch(data, &patch_data, false).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_small_change() {
        let base = b"AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL";
        let version = b"AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK MMMM";
        let patch_data = diff(base, version, false);
        let result = patch(base, &patch_data, false).unwrap();
        assert_eq!(result, version);
    }

    #[test]
    fn roundtrip_empty_version() {
        let base = b"some data";
        let version = b"";
        let patch_data = diff(base, version, false);
        let result = patch(base, &patch_data, false).unwrap();
        assert_eq!(result, version.as_slice());
    }

    #[test]
    fn roundtrip_larger() {
        let mut base = vec![0u8; 4096];
        let mut version = vec![0u8; 4096];
        for i in 0..4096 {
            base[i] = (i * 7 + 13) as u8;
            version[i] = (i * 7 + 13) as u8;
        }
        // Introduce some relocated references (simulate address delta)
        for off in (512..1024).step_by(64) {
            let val = u32::from_be_bytes([base[off], base[off + 1], base[off + 2], base[off + 3]]);
            let new_val = val.wrapping_add(0x20);
            let bytes = new_val.to_be_bytes();
            version[off..off + 4].copy_from_slice(&bytes);
        }
        // Add some new data
        for i in 2048..2080 {
            version[i] = 0xFF;
        }

        let patch_data = diff(&base, &version, false);
        let result = patch(&base, &patch_data, false).unwrap();
        assert_eq!(result, version);
    }

    #[test]
    fn varint_roundtrip() {
        for &v in &[0u32, 1, 0x7F, 0x80, 0x1FFF, 0x2000, 0x1F_FFFF, 0x20_0000, 0x1FFF_FFFF] {
            let mut w = Writer::new();
            w.write_varint(v);
            let mut r = Reader::new(&w.buf);
            assert_eq!(r.read_varint(), v, "failed for {v:#x}");
        }
    }

    #[test]
    fn varint_rle_roundtrip() {
        let mut w = Writer::new();
        w.write_varint_rle(42, 5);
        let mut r = Reader::new(&w.buf);
        for _ in 0..5 {
            assert_eq!(r.read_varint(), 42);
        }
    }

    #[test]
    fn swap_bits_is_involution() {
        for x in 0..1024 {
            assert_eq!(swap_bits(swap_bits(x)), x);
        }
    }
}

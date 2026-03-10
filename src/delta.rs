use std::collections::HashMap;

const PREFIX_LEN: usize = 32;
const TOLERANCE: usize = 4;
const MIN_BYTES_SAVED: i32 = 8;
const MAP_BITS: u32 = 20; // 1M slots per map, ~12 MB each

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

// ── Fixed-size hash map with O(1) clear ──────────────────────────────────────

#[derive(Clone, Copy)]
struct Slot {
    gen: u32,
    key: u32,
    val: u32,
}

struct FixedMap {
    mask: usize,
    gen: u32,
    slots: Vec<Slot>,
}

impl FixedMap {
    fn new() -> Self {
        let size = 1usize << MAP_BITS;
        Self {
            mask: size - 1,
            gen: 1,
            slots: vec![Slot { gen: 0, key: 0, val: 0 }; size],
        }
    }

    fn get(&self, key: u32) -> Option<u32> {
        let idx = key as usize & self.mask;
        let s = &self.slots[idx];
        if s.gen == self.gen && s.key == key {
            Some(s.val)
        } else {
            None
        }
    }

    /// Insert if the slot is empty (keeps first occurrence per generation).
    fn insert(&mut self, key: u32, val: u32) {
        let idx = key as usize & self.mask;
        if self.slots[idx].gen != self.gen {
            self.slots[idx] = Slot { gen: self.gen, key, val };
        }
    }

    fn clear(&mut self) {
        self.gen = self.gen.wrapping_add(1);
        if self.gen == 0 {
            for s in &mut self.slots {
                s.gen = 0;
            }
            self.gen = 1;
        }
    }
}

// ── LEB128 codec ─────────────────────────────────────────────────────────────

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

    fn write_leb128(&mut self, v: impl Into<u64>) {
        let mut v: u64 = v.into();
        loop {
            let byte = (v & 0x7F) as u8;
            v >>= 7;
            if v == 0 {
                self.buf.push(byte);
                break;
            }
            self.buf.push(byte | 0x80);
        }
    }
}

struct Reader<'a> {
    data: &'a [u8],
    pos: usize,
}

impl<'a> Reader<'a> {
    fn new(data: &'a [u8]) -> Self {
        Self { data, pos: 0 }
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

    fn read_leb128(&mut self) -> u64 {
        let mut result: u64 = 0;
        let mut shift = 0;
        loop {
            let byte = self.byte();
            result |= ((byte & 0x7F) as u64) << shift;
            if byte & 0x80 == 0 {
                break;
            }
            shift += 7;
        }
        result
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

pub fn diff(base: &[u8], version: &[u8], little_endian: bool, two_pass: bool) -> Vec<u8> {
    let mut w = Writer::new();
    w.write_leb128(version.len() as u64);

    if version.is_empty() || base.is_empty() {
        // No base or no version — emit entire version as a single literal hunk
        w.write_leb128(0u32);
        w.write_leb128(version.len() as u64);
        w.write_leb128(0u32);
        w.write_leb128(0u32);
        w.write_bytes(version);
        for _ in 0..4 { w.write_leb128(0u32); }
        w.write_i32be(0);
        return w.buf;
    }

    let mut dead_ends: Vec<i32> = Vec::new();
    let mut final_deltas: Vec<DeltaEntry> = Vec::new();
    let mut base_map = FixedMap::new();
    let mut ver_map = FixedMap::new();

    let start_pass: u8 = if two_pass { 0 } else { 1 };

    for pass in start_pass..2u8 {
        base_map.clear();
        ver_map.clear();

        let mut deltas: HashMap<i32, DeltaEntry> = HashMap::new();

        let mut h_b = gear_init(base, 0, PREFIX_LEN);
        let mut h_v = gear_init(version, 0, PREFIX_LEN);

        let mut v_start: usize = 0;
        let mut v_offset: usize = 0;
        let mut b_offset: usize = 0;
        let mut b_last_copy: usize = 0;

        // For hunk delta-encoding (pass 1 only)
        let mut prev_vs: u32 = 0;
        let mut prev_vc: u32 = 0;
        let mut prev_bc: u32 = 0;

        loop {
            // Try to find a cross-file match: base hash in version map,
            // or version hash in base map.
            let match_pair = ver_map
                .get(h_b)
                .and_then(|vp| {
                    bufs_eq(base, b_offset, version, vp as usize, PREFIX_LEN)
                        .then_some((b_offset, vp as usize))
                })
                .or_else(|| {
                    base_map.get(h_v).and_then(|bp| {
                        bufs_eq(base, bp as usize, version, v_offset, PREFIX_LEN)
                            .then_some((bp as usize, v_offset))
                    })
                });

            if let Some((mut b_copy, mut v_copy)) = match_pair {
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
                    w.write_leb128(vs - prev_vs);
                    w.write_leb128(vc - prev_vc);
                    w.write_leb128(bc - prev_bc);
                    w.write_leb128(l as u64);
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

                base_map.clear();
                ver_map.clear();
                v_start = v_offset;
            } else {
                base_map.insert(h_b, b_offset as u32);
                ver_map.insert(h_v, v_offset as u32);
            }

            // Check if a match (or prior state) already consumed all of version
            if v_offset >= version.len() {
                if pass == 1 && v_start < version.len() {
                    let vs = v_start as u32;
                    let vc = version.len() as u32;
                    let bc = b_offset as u32;
                    w.write_leb128(vs - prev_vs);
                    w.write_leb128(vc - prev_vc);
                    w.write_leb128(bc - prev_bc);
                    w.write_leb128(0u32);
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
                    w.write_leb128(vs - prev_vs);
                    w.write_leb128(vc - prev_vc);
                    w.write_leb128(bc - prev_bc);
                    w.write_leb128(0u32);
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

    // Hunk stream terminator
    for _ in 0..4 { w.write_leb128(0u32); }

    // Delta table
    for entry in &final_deltas {
        w.write_i32be(entry.delta);
        w.write_leb128(entry.offsets.len() as u64);

        let mut prev: u32 = 0;
        for &off in &entry.offsets {
            w.write_leb128(off - prev);
            prev = off;
        }
    }

    // Delta table terminator
    w.write_i32be(0);

    w.buf
}

// ── Patch (decode) ───────────────────────────────────────────────────────────

pub fn patch(base: &[u8], patch_data: &[u8], little_endian: bool) -> Result<Vec<u8>, String> {
    let mut r = Reader::new(patch_data);

    let version_len = r.read_leb128() as usize;
    let mut dest = vec![0u8; version_len];

    // Read hunks
    let mut v_start: usize = 0;
    let mut v_copy: usize = 0;
    let mut b_copy: usize = 0;

    loop {
        let vsd = r.read_leb128() as usize;
        let vcd = r.read_leb128() as usize;
        let bcd = r.read_leb128() as usize;
        let l = r.read_leb128() as usize;

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
        let num_elems = r.read_leb128() as usize;
        let mut offset: u32 = 0;

        for _ in 0..num_elems {
            offset += r.read_leb128() as u32;
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
        let patch_data = diff(data, data, false, false);
        let result = patch(data, &patch_data, false).unwrap();
        assert_eq!(result, data);
    }

    #[test]
    fn roundtrip_small_change() {
        let base = b"AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK LLLL";
        let version = b"AAAA BBBB CCCC DDDD EEEE FFFF GGGG HHHH IIII JJJJ KKKK MMMM";
        let patch_data = diff(base, version, false, false);
        let result = patch(base, &patch_data, false).unwrap();
        assert_eq!(result, version);
    }

    #[test]
    fn roundtrip_empty_version() {
        let base = b"some data";
        let version = b"";
        let patch_data = diff(base, version, false, false);
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

        let patch_data = diff(&base, &version, false, false);
        let result = patch(&base, &patch_data, false).unwrap();
        assert_eq!(result, version);
    }

    #[test]
    fn leb128_roundtrip() {
        for &v in &[0u64, 1, 0x7F, 0x80, 0x3FFF, 0x4000, 0x1F_FFFF, 0xFFFF_FFFF, 0x1_0000_0000] {
            let mut w = Writer::new();
            w.write_leb128(v);
            let mut r = Reader::new(&w.buf);
            assert_eq!(r.read_leb128(), v, "failed for {v:#x}");
        }
    }
}

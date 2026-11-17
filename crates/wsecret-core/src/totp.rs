//! TOTP: behavior port of upstream `s_totp`/`s_totp32` (`secret.c`, pinned
//! `angt/secret` commit `e98103def4e062a6f9a8fa5e7693abe15f20817a`).
//!
//! This is a faithful reimplementation of upstream's hand-rolled SHA-1/HMAC
//! and base32 decoder — including its quirks — not a new cryptographic
//! design (user decision, 2026-11-17). SHA-1 and HMAC-SHA-1 are standard
//! algorithms; the exact behavior matrix of §7.3 C8 is reproduced:
//!
//! - `s_totp`: the value (1..=64 bytes) is the HMAC-SHA-1 key over the
//!   8-byte big-endian counter (`unix_now / 30`); dynamic truncation
//!   `(load32_be(&h[h[19] & 0xF]) & !(1 << 31)) % 1_000_000`, rendered as
//!   6 decimal digits. Empty or >64-byte values are invalid.
//! - `s_totp32`: the value is base32-decoded first (RFC 4648 alphabet
//!   `A–Z2–7`; decoding stops at `NUL`, `=`, or `\n`; any other invalid
//!   character — including `\r` and lowercase — is an error; a trailing
//!   partial group is kept as an extra byte with the leftover bits shifted
//!   left, i.e. zero-padded; a further complete decoded byte beyond the
//!   63-byte guard is an error, NOT a silent truncation), then `s_totp`
//!   runs over the decoded bytes.

/// Upstream `s_totp` rejects keys longer than 64 bytes (`secret.len > 64`).
const KEY_MAX: usize = 64;

/// Upstream `s_totp32`'s decoded-buffer guard: `out[64]` with
/// `outlen == sizeof(out) - 1` rejecting a further complete byte (audit P6:
/// 102×`A` accepted, 103×`A` rejected).
const B32_OUT_GUARD: usize = 63;

/// The 6-digit decimal code (upstream `struct s_totp { char b[7]; }`, of
/// which `s_show` writes `b[0..6]`).
pub type TotpCode = [u8; 6];

/// Upstream `s_show` dispatch over `struct s_secret { name, value, len }`:
/// names containing `"totp"` are TOTP names (case-sensitive substring),
/// `"totp32"` wins over plain `"totp"`; `counter = unix_now / 30`.
/// `None` for non-TOTP names (the `dump` path never computes TOTP) and for
/// invalid secrets (upstream: all-zero struct → `Fatal: Invalid secret`).
pub fn totp_for(name: &[u8], value: &[u8], unix_now: u64) -> Option<TotpCode> {
    if !contains_sub(name, b"totp") {
        return None;
    }
    let counter = unix_now / 30;
    if contains_sub(name, b"totp32") {
        totp32(value, counter)
    } else {
        totp(value, counter)
    }
}

/// Upstream `s_totp(secret, counter)`: HMAC-SHA-1 with the value as key and
/// the counter as message, then dynamic truncation to 6 digits.
pub fn totp(value: &[u8], counter: u64) -> Option<TotpCode> {
    if value.is_empty() || value.len() > KEY_MAX {
        return None;
    }
    let mut h = hmac_sha1(value, &counter.to_be_bytes());
    let o = (h[19] & 0x0f) as usize;
    let v = (u32::from_be_bytes([h[o], h[o + 1], h[o + 2], h[o + 3]]) & !(1u32 << 31)) % 1_000_000;
    zeroize(&mut h);
    Some(digits6(v))
}

/// Upstream `s_totp32(secret, counter)`: base32-decode (upstream quirk
/// semantics) then `s_totp`. `None` on any decode error, exactly matching
/// upstream's empty-result → `Invalid secret` path. The decode buffer is
/// zeroized on every return path (upstream's `done:` label).
pub fn totp32(value: &[u8], counter: u64) -> Option<TotpCode> {
    let mut decoded = [0u8; KEY_MAX];
    let code = match b32_decode(value, &mut decoded) {
        Some(outlen) => totp(&decoded[..outlen], counter),
        None => None,
    };
    zeroize(&mut decoded);
    code
}

/// Upstream `s_b32` + `s_totp32` decode loop, verbatim semantics:
/// stops at `NUL`/`=`/`\n`; invalid char → `None`; a further complete
/// decoded byte past the 63-byte guard → `None` (NOT truncation); a
/// trailing partial group is emitted as an extra byte with the leftover
/// bits shifted left (zero-padded). Returns the decoded length.
fn b32_decode(input: &[u8], out: &mut [u8; KEY_MAX]) -> Option<usize> {
    let mut outlen: usize = 0;
    let mut buf: u32 = 0;
    let mut bits: u32 = 0;

    for &c in input {
        if c == 0 || c == b'=' || c == b'\n' {
            break;
        }
        let v = b32_value(c)?;
        buf = (buf << 5) | v;
        bits += 5;
        if bits < 8 {
            continue;
        }
        if outlen == B32_OUT_GUARD {
            return None;
        }
        bits -= 8;
        out[outlen] = ((buf >> bits) & 0xff) as u8;
        outlen += 1;
    }
    if bits > 0 {
        out[outlen] = ((buf << (8 - bits)) & 0xff) as u8;
        outlen += 1;
    }
    Some(outlen)
}

/// Upstream `s_b32`: `A–Z` → 0..25, `2–7` → 26..31, everything else (digits
/// `0`/`1`/`8`/`9`, lowercase, `\r`, symbols) invalid.
fn b32_value(c: u8) -> Option<u32> {
    match c {
        b'A'..=b'Z' => Some(u32::from(c - b'A')),
        b'2'..=b'7' => Some(u32::from(c - b'2') + 26),
        _ => None,
    }
}

/// Case-sensitive byte substring search, mirroring upstream `strstr` on the
/// name (which is raw bytes, not necessarily valid text).
fn contains_sub(hay: &[u8], needle: &[u8]) -> bool {
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len()).any(|w| w == needle)
}

/// 6-digit zero-padded decimal, matching upstream's `out.b[i] = '0' + ret % 10`
/// over `b[0..6]` (`b[6]` is the NUL, not part of the code).
fn digits6(v: u32) -> TotpCode {
    let mut out = [b'0'; 6];
    let mut v = v;
    for slot in out.iter_mut().rev() {
        *slot = b'0' + (v % 10) as u8;
        v /= 10;
    }
    out
}

// ---- SHA-1 (FIPS 180-4), a port of upstream `s_sha1`/`s_sha1_process` ----
//
// Upstream's copy only hashes the one- and two-block shapes its fixed HMAC
// buffers produce; this implementation is general (streaming) with the same
// compression function, word schedule, and constants.

struct Sha1 {
    x: [u32; 5],
    buf: [u8; 64],
    buf_len: usize,
    total: u64,
}

impl Sha1 {
    fn new() -> Self {
        Self {
            x: [0x6745_2301, 0xEFCD_AB89, 0x98BA_DCFE, 0x1032_5476, 0xC3D2_E1F0],
            buf: [0u8; 64],
            buf_len: 0,
            total: 0,
        }
    }

    fn update(&mut self, mut data: &[u8]) {
        self.total = self.total.wrapping_add(data.len() as u64);
        if self.buf_len > 0 {
            let take = (64 - self.buf_len).min(data.len());
            self.buf[self.buf_len..self.buf_len + take].copy_from_slice(&data[..take]);
            self.buf_len += take;
            data = &data[take..];
            if self.buf_len == 64 {
                let block = self.buf;
                process_block(&block, &mut self.x);
                self.buf_len = 0;
            }
        }
        while data.len() >= 64 {
            process_block(&data[..64], &mut self.x);
            data = &data[64..];
        }
        if !data.is_empty() {
            self.buf[..data.len()].copy_from_slice(data);
            self.buf_len = data.len();
        }
    }

    fn finalize(mut self) -> [u8; 20] {
        let bit_len = self.total.wrapping_mul(8);
        // Padding: 0x80, zeros, 64-bit big-endian bit length.
        let mut tail = [0u8; 128];
        tail[..self.buf_len].copy_from_slice(&self.buf[..self.buf_len]);
        tail[self.buf_len] = 0x80;
        let pad_len = if self.buf_len + 1 + 8 <= 64 { 64 } else { 128 };
        tail[pad_len - 8..pad_len].copy_from_slice(&bit_len.to_be_bytes());
        process_block(&tail[..64], &mut self.x);
        if pad_len == 128 {
            process_block(&tail[64..], &mut self.x);
        }
        let mut out = [0u8; 20];
        for (i, word) in self.x.iter().enumerate() {
            out[i * 4..i * 4 + 4].copy_from_slice(&word.to_be_bytes());
        }
        zeroize(&mut self.buf);
        zeroize(&mut tail);
        zeroize_u32(&mut self.x);
        out
    }
}

/// One SHA-1 compression step over a 64-byte block (upstream
/// `s_sha1_process`: same word schedule, round constants, rotations).
fn process_block(block: &[u8], x: &mut [u32; 5]) {
    const K: [u32; 4] = [0x5A82_7999, 0x6ED9_EBA1, 0x8F1B_BCDC, 0xCA62_C1D6];
    let mut w = [0u32; 80];
    for i in 0..16 {
        w[i] = u32::from_be_bytes([
            block[i * 4],
            block[i * 4 + 1],
            block[i * 4 + 2],
            block[i * 4 + 3],
        ]);
    }
    for i in 16..80 {
        w[i] = (w[i - 3] ^ w[i - 8] ^ w[i - 14] ^ w[i - 16]).rotate_left(1);
    }

    let [mut a, mut b, mut c, mut d, mut e] = *x;
    for (i, &wi) in w.iter().enumerate() {
        // All arithmetic wraps, exactly as the C reference does.
        let f = match i {
            0..=19 => K[0].wrapping_add((b & c) | ((!b) & d)),
            20..=39 => K[1].wrapping_add(b ^ c ^ d),
            40..=59 => K[2].wrapping_add((b & c) | (b & d) | (c & d)),
            _ => K[3].wrapping_add(b ^ c ^ d),
        };
        let t = a
            .rotate_left(5)
            .wrapping_add(e)
            .wrapping_add(wi)
            .wrapping_add(f);
        e = d;
        d = c;
        c = b.rotate_left(30);
        b = a;
        a = t;
    }
    x[0] = x[0].wrapping_add(a);
    x[1] = x[1].wrapping_add(b);
    x[2] = x[2].wrapping_add(c);
    x[3] = x[3].wrapping_add(d);
    x[4] = x[4].wrapping_add(e);

    zeroize_u32(&mut w);
}

fn sha1(msg: &[u8]) -> [u8; 20] {
    let mut h = Sha1::new();
    h.update(msg);
    h.finalize()
}

/// HMAC-SHA-1 (RFC 2104). For the TOTP call shape (key ≤ 64 bytes, 8-byte
/// message) this is bit-identical to upstream's fixed `ki[72]`/`ko[84]`
/// buffers: secret copied into both, 64 bytes XOR 0x36/0x5c, counter
/// big-endian at offset 64, inner SHA-1 then outer SHA-1.
fn hmac_sha1(key: &[u8], msg: &[u8]) -> [u8; 20] {
    // Keys longer than one block are hashed first (RFC 2104; upstream's
    // key ≤ 64 bytes never hits this path).
    let mut key_block = [0u8; 64];
    let key_hash;
    let key_slice: &[u8] = if key.len() > 64 {
        key_hash = sha1(key);
        &key_hash
    } else {
        key
    };
    key_block[..key_slice.len()].copy_from_slice(key_slice);

    let mut inner = Sha1::new();
    let mut pad = key_block;
    for b in pad.iter_mut() {
        *b ^= 0x36;
    }
    inner.update(&pad);
    inner.update(msg);
    let inner = inner.finalize();

    let mut outer = Sha1::new();
    let mut pad = key_block;
    for b in pad.iter_mut() {
        *b ^= 0x5c;
    }
    outer.update(&pad);
    outer.update(&inner);
    let out = outer.finalize();

    zeroize(&mut key_block);
    out
}

/// Upstream uses `hydro_memzero` (non-elidable) on every secret buffer; this
/// module is a pure-Rust port, so use a volatile-write barrier instead.
/// All affected buffers are transient stack values (SHA-1 state, HMAC pads).
fn zeroize(x: &mut [u8]) {
    for b in x.iter_mut() {
        // SAFETY: `b` is a valid writable reference; a volatile byte write
        // cannot be optimized away.
        unsafe { core::ptr::write_volatile(b, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

/// `zeroize` for word buffers (SHA-1 state and schedule).
fn zeroize_u32(x: &mut [u32]) {
    for w in x.iter_mut() {
        // SAFETY: same volatile-write barrier as [`zeroize`], for `u32`.
        unsafe { core::ptr::write_volatile(w, 0) };
    }
    core::sync::atomic::compiler_fence(core::sync::atomic::Ordering::SeqCst);
}

#[cfg(test)]
mod tests {
    use super::*;

    // ---- SHA-1 KATs (independent oracle: GNU coreutils `sha1sum`) ----

    #[test]
    fn sha1_known_answers() {
        assert_eq!(hex(&sha1(b"")), "da39a3ee5e6b4b0d3255bfef95601890afd80709");
        assert_eq!(hex(&sha1(b"abc")), "a9993e364706816aba3e25717850c26c9cd0d89d");
        assert_eq!(
            hex(&sha1(b"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq")),
            "84983e441c3bd26ebaae4aa1f95129e5e54670f1"
        );
        // Padding-boundary shapes: 89 (two blocks), 112 (pad spills into a
        // second block), 56 (fits one block with the length field), 64
        // (exactly one block).
        assert_eq!(hex(&sha1(&[b'a'; 89])), "9e8212145ce950d3148e92a0736639d78ffae165");
        assert_eq!(hex(&sha1(&[b'b'; 112])), "7613e3edd19e38b9f5b8df789c0a948eec6a0f04");
        assert_eq!(hex(&sha1(&[b'c'; 56])), "ee59278c72f2b1f1c6be889b06f4c47d7a220b3d");
        assert_eq!(hex(&sha1(&[b'd'; 64])), "7d4f9b6d084894fb8640dc55aab16ad0e021e4c8");
    }

    // ---- RFC 2202 HMAC-SHA-1 KATs (independent oracle: OpenSSL) ----

    #[test]
    fn hmac_sha1_rfc2202_cases_1_to_4() {
        assert_eq!(
            hex(&hmac_sha1(&[0x0b; 20], b"Hi There")),
            "b617318655057264e28bc0b6fb378c8ef146be00"
        );
        assert_eq!(
            hex(&hmac_sha1(b"Jefe", b"what do ya want for nothing?")),
            "effcdf6ae5eb2fa2d27416d5f184df9c259a7c79"
        );
        assert_eq!(
            hex(&hmac_sha1(&[0xaa; 20], &[0xdd; 50])),
            "125d7342b9ac11cd91a39af48aa17b4f63f175d3"
        );
        let key: Vec<u8> = (0x01..=0x19).collect();
        assert_eq!(
            hex(&hmac_sha1(&key, &[0xcd; 50])),
            "4c9007f4026250c6bc8414f9bf50c86c2d7235da"
        );
    }

    #[test]
    fn hmac_sha1_rfc2202_cases_5_to_7() {
        assert_eq!(
            hex(&hmac_sha1(&[0x0c; 20], b"Test With Truncation")),
            "4c1a03424b55e07fe7f27be1d58bb9324a9a5a04"
        );
        // Cases 6 and 7 use an 80-byte key (hashed first, RFC 2104).
        assert_eq!(
            hex(&hmac_sha1(&[0xaa; 80], b"Test Using Larger Than Block-Size Key - Hash Key First")),
            "aa4ae5e15272d00e95705637ce8a3b55ed402112"
        );
        assert_eq!(
            hex(&hmac_sha1(
                &[0xaa; 80],
                b"Test Using Larger Than Block-Size Key and Larger Than One Block-Size Data"
            )),
            "e8e99d0f45237d786d6bbaa7965c7808bbff1a91"
        );
    }

    // ---- RFC 4226 HOTP vectors (key = "12345678901234567890") ----

    #[test]
    fn rfc4226_vectors() {
        let key = b"12345678901234567890";
        let expect = [
            "755224", "287082", "359152", "969429", "338314", //
            "254676", "287922", "162583", "399871", "520489",
        ];
        for (c, want) in expect.iter().enumerate() {
            let code = totp(key, c as u64).unwrap();
            assert_eq!(std::str::from_utf8(&code).unwrap(), *want, "counter {c}");
        }
    }

    #[test]
    fn totp_rejects_empty_and_oversized() {
        assert_eq!(totp(b"", 0), None);
        assert_eq!(totp(&[0u8; 65], 0), None);
        assert!(totp(&[0u8; 64], 0).is_some());
    }

    // ---- Dispatch and counter ----

    #[test]
    fn totp_for_dispatch() {
        let key = b"12345678901234567890";
        // counter = unix_now / 30: 29 → 0, 30 → 1, 59 → 1, 60 → 2.
        assert_eq!(totp_for(b"test/totp", key, 29), totp(key, 0));
        assert_eq!(totp_for(b"test/totp", key, 30), totp(key, 1));
        assert_eq!(totp_for(b"test/totp", key, 59), totp(key, 1));
        assert_eq!(totp_for(b"test/totp", key, 60), totp(key, 2));
        // Names without the substring never dispatch to TOTP (dump path).
        assert_eq!(totp_for(b"test/tot", key, 0), None);
        assert_eq!(totp_for(b"tot", key, 0), None);
        // Case-sensitive: "TOTP" does not match.
        assert_eq!(totp_for(b"test/TOTP", key, 0), None);
        // "totp32" wins even though it also contains "totp".
        let v32 = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp_for(b"a-totp32-b", v32, 0), totp32(v32, 0));
        assert_ne!(totp_for(b"a-totp32-b", v32, 0), totp(v32, 0));
    }

    #[test]
    fn totp32_fixture_vector() {
        // Plan §6 fixture: test/totp32 = base32("12345678901234567890").
        let v32 = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(totp32(v32, 0), totp(b"12345678901234567890", 0));
        assert_eq!(std::str::from_utf8(&totp32(v32, 0).unwrap()).unwrap(), "755224");
    }

    // ---- Differential test against the verbatim pinned C (`secret.c`,
    // `s_totp`/`s_totp32`, compiled with `-DNOMAIN` on MSVC /std:c11). Every
    // value below is the observed C output for the same input. ----

    #[test]
    fn matches_upstream_c_oracle() {
        // s_totp32 quirk matrix (counter 0).
        let cases: &[(&[u8], &str)] = &[
            (b"MY", "531249"),
            (b"MY=", "531249"),
            (b"M=Y", "005842"),
            (b"MZ", "714153"),
            (b"MZXW6YTBOI", "734211"),
            (b"MZXW6YTBOJ", "754920"),
            (b"MY\nZZZ", "531249"),
            (b"MY\0ZZZ", "531249"),
            (&[b'A'; 102], "328482"),
        ];
        for (input, want) in cases {
            let got = totp32(input, 0).expect("C oracle accepted");
            assert_eq!(std::str::from_utf8(&got).unwrap(), *want, "input {input:?}");
        }
        // C rejections.
        for input in [
            b"MY\r\n".as_slice(),
            b"My",
            b"MY1",
            b"MY8",
            b"MY0",
            b"=",
            b"\nAB",
            &[b'A'; 103][..],
        ] {
            assert_eq!(totp32(input, 0), None, "input {input:?}");
        }
        assert_eq!(totp32(b"", 0), None);
        // s_totp boundary and fixture values.
        assert_eq!(totp(&[0x0b; 64], 0), Some(*b"356016"));
        assert_eq!(totp(&[0x0b; 65], 0), None);
        let v32 = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
        assert_eq!(std::str::from_utf8(&totp32(v32, 5).unwrap()).unwrap(), "254676");
    }

    // ---- Base32 quirk matrix (§7.3 C8) ----

    #[test]
    fn b32_trailing_partial_group_zero_padded() {
        // "MY" = 2 chars = 10 bits → 1 full byte + 2 leftover bits, emitted
        // as an extra byte shifted left (zero-padded): 66 00.
        let mut out = [0u8; 64];
        let n = b32_decode(b"MY", &mut out).unwrap();
        assert_eq!(&out[..n], &[0x66, 0x00]);
    }

    #[test]
    fn b32_terminators() {
        // '=' terminates anywhere.
        let mut out = [0u8; 64];
        let n = b32_decode(b"M=Y", &mut out).unwrap();
        assert_eq!(&out[..n], &[0x60]);
        assert_eq!(b32_decode(b"MY=", &mut out), Some(2));
        // '\n' terminates (later characters ignored).
        assert_eq!(b32_decode(b"MY\nZZZ", &mut out), Some(2));
        // NUL terminates.
        assert_eq!(b32_decode(b"MY\0ZZZ", &mut out), Some(2));
    }

    #[test]
    fn b32_invalid_characters_rejected() {
        for bad in [
            b"MY\r\n".as_slice(),
            b"My",
            b"MY1",
            b"MY8",
            b"MY9",
            b"MY0",
            b"mz",
            b"MY+",
        ] {
            assert_eq!(b32_decode(bad, &mut [0u8; 64]), None, "input {bad:?}");
        }
    }

    #[test]
    fn b32_non_canonical_trailing_bits_accepted() {
        let mut out = [0u8; 64];
        // "MZ" = 'M'(01100) 'Z'(11001): same leading byte as "MY" but the
        // leftover 2 bits are non-canonical (01). Upstream accepts it and
        // emits the leftover bits shifted left — it does NOT reject.
        let n = b32_decode(b"MZ", &mut out).unwrap();
        assert_eq!(&out[..n], &[0x66, 0x40]);
        // Likewise "MZXW6YTBOJ" decodes "foobar" + a non-canonical trailing
        // partial byte (J = 01001 → leftover 01 → 0x40); the canonical
        // "MZXW6YTBOI" gives 0x00.
        let n = b32_decode(b"MZXW6YTBOI", &mut out).unwrap();
        assert_eq!(&out[..n], b"foobar\0");
        let n = b32_decode(b"MZXW6YTBOJ", &mut out).unwrap();
        assert_eq!(&out[..n], b"foobar\x40");
    }

    #[test]
    fn b32_capacity_boundary() {
        // Audit P6: 102×'A' accepted (63 full bytes + 1 zero-padded partial),
        // 103×'A' rejected — NOT silently truncated.
        let mut out = [0u8; 64];
        assert_eq!(b32_decode(&[b'A'; 102], &mut out), Some(64));
        assert_eq!(b32_decode(&[b'A'; 103], &mut out), None);
    }

    #[test]
    fn totp32_invalid_input() {
        assert_eq!(totp32(b"", 0), None);
        assert_eq!(totp32(b"My", 0), None);
        assert_eq!(totp32(b"MY\r\n", 0), None);
        assert_eq!(totp32(&[b'A'; 103], 0), None);
        // Valid base32 that decodes to an empty value → s_totp rejects.
        assert_eq!(totp32(b"=", 0), None);
        assert_eq!(totp32(b"\nAB", 0), None);
    }

    // ---- §7.3 C8 base32 quirk matrix, assignment rows. Codes below are
    // exact KATs cross-checked against an independent HMAC-SHA-1 oracle
    // (Node `crypto`); inputs shared with `matches_upstream_c_oracle` agree
    // with the compiled pinned-C values recorded there. ----

    #[test]
    fn c8_canonical_secret_decodes_to_ten_bytes_with_upstream_code() {
        let mut out = [0u8; 64];
        let n = b32_decode(b"JBSWY3DPEHPK3PXP", &mut out).unwrap();
        assert_eq!(&out[..n], b"Hello!\xde\xad\xbe\xef", "10 decoded bytes");
        assert_eq!(
            std::str::from_utf8(&totp32(b"JBSWY3DPEHPK3PXP", 0).unwrap()).unwrap(),
            "282760"
        );
    }

    #[test]
    fn c8_padding_terminates_and_matches_unpadded() {
        // '=' terminates anywhere: the padded secret is byte-identical to
        // the unpadded one, hence the same code.
        assert_eq!(
            totp32(b"JBSWY3DPEHPK3PXP=", 0),
            totp32(b"JBSWY3DPEHPK3PXP", 0)
        );
    }

    #[test]
    fn c8_ab_cd_decodes_as_ab_only() {
        let mut out = [0u8; 64];
        let n = b32_decode(b"AB=CD", &mut out).unwrap();
        let mut plain = [0u8; 64];
        let m = b32_decode(b"AB", &mut plain).unwrap();
        // Everything after the first '=' is ignored: "AB=CD" decodes as
        // "AB" only (2 chars = 10 bits → 1 byte + zero-padded partial).
        assert_eq!(&out[..n], &plain[..m]);
        assert_eq!(&out[..n], &[0x00, 0x40]);
        assert_eq!(totp32(b"AB=CD", 0), totp32(b"AB", 0));
        assert_eq!(
            std::str::from_utf8(&totp32(b"AB=CD", 0).unwrap()).unwrap(),
            "675116"
        );
    }

    #[test]
    fn c8_fifteen_char_non_canonical_secret_accepted() {
        // 15 chars = 75 bits → 9 full bytes + 3 leftover bits, kept as a
        // 10th byte zero-padded on the right: ACCEPTED (non-canonical).
        let mut out = [0u8; 64];
        let n = b32_decode(b"JBSWY3DPEHPK3PX", &mut out).unwrap();
        assert_eq!(
            &out[..n],
            &[0x48, 0x65, 0x6c, 0x6c, 0x6f, 0x21, 0xde, 0xad, 0xbe, 0xe0]
        );
        // Same TOTP as upstream for this non-canonical seed.
        assert_eq!(
            std::str::from_utf8(&totp32(b"JBSWY3DPEHPK3PX", 0).unwrap()).unwrap(),
            "757479"
        );
        // The seeds differ from the canonical 16-char form (final byte
        // 0xe0 vs 0xef), so the codes differ at the same counter.
        assert_ne!(
            totp32(b"JBSWY3DPEHPK3PX", 0),
            totp32(b"JBSWY3DPEHPK3PXP", 0)
        );
    }

    #[test]
    fn c8_lowercase_cr_and_digits_0189_rejected() {
        let bads: &[&[u8]] = &[
            b"jbswy3dpehpk3pxp",
            b"my",
            b"MY\r\n",
            b"JBSWY3DPEHPK3PX0",
        ];
        for bad in bads {
            assert_eq!(totp32(bad, 0), None, "input {bad:?}");
        }
        // Digits 0/1/8/9 are outside the RFC 4648 alphabet (2–7) — a '0'
        // anywhere is invalid, not just in the canonical fixture.
        for d in [b'0', b'1', b'8', b'9'] {
            let mut input = b"MY".to_vec();
            input.push(d);
            assert_eq!(totp32(&input, 0), None, "input {input:?}");
        }
    }

    #[test]
    fn c8_my_zero_padded_partial_group_code() {
        // "MY" → 66 00 (covered byte-wise above); its upstream code at
        // counter 0, pinned so the zero-padding is observable end to end.
        assert_eq!(
            std::str::from_utf8(&totp32(b"MY", 0).unwrap()).unwrap(),
            "531249"
        );
    }

    #[test]
    fn c8_capacity_boundary_accepts_102_rejects_103() {
        // Audit P6: NOT silently truncated — 103×'A' is an error.
        assert_eq!(
            std::str::from_utf8(&totp32(&[b'A'; 102], 0).unwrap()).unwrap(),
            "328482"
        );
        assert_eq!(totp32(&[b'A'; 103], 0), None);
    }

    #[test]
    fn c8_raw_seed_length_boundaries() {
        // Raw `s_totp`: any 1..=64-byte seed is accepted (both extremes
        // pinned to independent-oracle codes).
        assert_eq!(
            std::str::from_utf8(&totp(&[0x0b], 0).unwrap()).unwrap(),
            "771929"
        );
        assert_eq!(
            std::str::from_utf8(&totp(&[0x0b; 64], 0).unwrap()).unwrap(),
            "356016"
        );
        for len in [1usize, 2, 20, 63, 64] {
            assert!(totp(&vec![0x5a; len], 0).is_some(), "len {len}");
        }
        // Empty and >64 bytes → invalid (upstream's empty `s_totp` struct).
        assert_eq!(totp(b"", 0), None);
        assert_eq!(totp(&[0x0b; 65], 0), None);
    }

    // ---- helper ----

    fn hex(bytes: &[u8]) -> String {
        bytes.iter().map(|b| format!("{b:02x}")).collect()
    }
}

//! Explicit byte codecs for the portable store format (plan §1.1–§1.3).
//!
//! Every field is read and written through `u16`/`u64` little-endian helpers
//! on byte slices — NEVER `#[repr(C)]` struct memcpy (padding/endianness
//! hazards). Layouts encoded here:
//!
//! - Header block (plan §1.2): `version[1] master[32] ops_limit_le64[8]`
//!   at offsets 0/1/33, total 41 bytes; bytes 41..512 are zero-filled at
//!   `init`, never validated by readers (upstream-exact), and preserved by
//!   mutations.
//! - Entry plaintext (plan §1.3): `slen_le16[2] data[474]`, where `data` is
//!   `name[len] 0x00 value[slen] random padding`. The padding is filled with
//!   `libhydrogen_sys::random_buf` on encode.

use crate::error::{FormatError, NameError};

/// One store block / one entry ciphertext: `S_ENTRYSIZE`.
pub const BLOCK: usize = 512;
/// Parsed header size: `version + master + ops_limit`.
pub const HEADER_LEN: usize = 41;
/// Entry plaintext size: `slen[2] + data[474]`.
pub const ENTRY_PLAIN_LEN: usize = 476;
/// Entry data area size (`S_ENTRYSIZE - secretbox_header - 2`).
pub const ENTRY_DATA_LEN: usize = ENTRY_PLAIN_LEN - 2;
/// Maximum value length (empty name; decreases as the name grows).
pub const VALUE_MAX: usize = 473;
/// Maximum name length: `S_KEYLENMAX`.
pub const NAME_MAX: usize = 255;
/// Store-format floor for `ops_limit`: `S_OPS_LIMIT`.
pub const OPS_LIMIT_MIN: u64 = 10_000;
/// Default `ops_limit` at `init`: `S_OPS_LIMIT * 10`.
pub const OPS_LIMIT_DEFAULT: u64 = 100_000;
/// `(S_VER_MAJOR, S_VER_MINOR)`. Only the major (`.0`) is stored in the file;
/// the minor is compile-time only (upstream-exact).
pub const VERSION: (u8, u8) = (0, 21);

/// The parsed in-memory form of the store header (plan §1.2/§3.4).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct Header {
    /// Format version; must equal [`VERSION`].0.
    pub version: u8,
    /// Random 32-byte master key (KDF input, never a secretbox key).
    pub master: [u8; 32],
    /// KDF operation count, little-endian on disk; floor [`OPS_LIMIT_MIN`].
    pub ops_limit: u64,
}

impl Header {
    /// Parses the 41-byte header out of a full 512-byte block with upstream
    /// `s_header` semantics: `version != 0` → [`FormatError::UnsupportedVersion`],
    /// then `ops_limit < 10_000` → [`FormatError::OpsLimitTooLow`].
    ///
    /// The block's trailing padding (bytes 41..512) is never validated:
    /// upstream readers do not check it (plan §1.2).
    pub fn parse(block: &[u8; BLOCK]) -> Result<Self, FormatError> {
        let version = block[0];
        if version != VERSION.0 {
            return Err(FormatError::UnsupportedVersion(version));
        }
        let mut master = [0u8; 32];
        master.copy_from_slice(&block[1..33]);
        let ops_limit = u64::from_le_bytes(
            block[33..41]
                .try_into()
                .expect("ops_limit field is exactly 8 bytes"),
        );
        if ops_limit < OPS_LIMIT_MIN {
            return Err(FormatError::OpsLimitTooLow(ops_limit));
        }
        Ok(Header {
            version,
            master,
            ops_limit,
        })
    }

    /// Encodes a fresh 512-byte initialization block: the 41 header bytes
    /// followed by zero padding (upstream `s_init` memsets the block, plan
    /// §1.1). `ops_limit` is encoded as given; the [`OPS_LIMIT_MIN`] floor is
    /// enforced by the callers that accept user input, not by the codec.
    pub fn encode_init(master: [u8; 32], ops_limit: u64) -> [u8; BLOCK] {
        let mut block = [0u8; BLOCK];
        block[0] = VERSION.0;
        block[1..33].copy_from_slice(&master);
        block[33..41].copy_from_slice(&ops_limit.to_le_bytes());
        block
    }
}

/// A name/value pair borrowed from one decoded entry plaintext (plan §1.3).
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct Entry<'a> {
    /// Record name, without the terminating NUL: 1..=255 bytes, no byte
    /// `<= 0x20` (upstream `s_keylen`).
    pub name: &'a [u8],
    /// Record value: exactly `slen` bytes, opaque binary.
    pub value: &'a [u8],
}

/// Validates a name with upstream `s_keylen` semantics (plan §1.3): non-empty,
/// at most [`NAME_MAX`] bytes, no byte `<= 0x20` (bytes `> 0x7f` are allowed).
pub fn check_name(name: &[u8]) -> Result<(), NameError> {
    if name.is_empty() {
        return Err(NameError::Empty);
    }
    if name.len() > NAME_MAX {
        return Err(NameError::TooLong);
    }
    if name.iter().any(|&b| b <= 0x20) {
        return Err(NameError::SpecialChar);
    }
    Ok(())
}

impl<'a> Entry<'a> {
    /// Decodes one authenticated entry plaintext (`slen_le16[2] data[474]`).
    ///
    /// Structural validation, rejecting malformed records without exposing
    /// any partial name or value bytes in the error:
    ///
    /// - the name is the bytes before the first NUL inside the 474-byte data
    ///   area; no NUL at all → [`FormatError::MalformedRecord`] ("no bounded
    ///   NUL") — upstream `s_keylen` would abort on such a record;
    /// - the name must satisfy [`check_name`] (upstream `s_keylen` runs on
    ///   every decrypted record);
    /// - `slen` must fit the value's data bounds:
    ///   `slen <= 474 - name.len() - 1`, otherwise
    ///   [`FormatError::MalformedRecord`] (upstream: "Invalid secret").
    ///
    /// A record rejected here is one upstream itself would fatal on; the
    /// scanning layer decides whether to skip it (read path) or fail
    /// (mutation path) — see plan §1.1/§3.5.
    pub fn decode(plain: &'a [u8; ENTRY_PLAIN_LEN]) -> Result<Entry<'a>, FormatError> {
        let slen = u16::from_le_bytes([plain[0], plain[1]]) as usize;
        let data: &'a [u8] = &plain[2..2 + ENTRY_DATA_LEN];

        let name_len = data
            .iter()
            .position(|&b| b == 0)
            .ok_or(FormatError::MalformedRecord)?;
        let name = &data[..name_len];
        check_name(name).map_err(FormatError::Name)?;

        let value_start = name_len + 1;
        let value_end = value_start + slen;
        if value_end > data.len() {
            return Err(FormatError::MalformedRecord);
        }

        Ok(Entry {
            name,
            value: &data[value_start..value_end],
        })
    }

    /// Encodes one entry plaintext: `slen_le16[2]`, then
    /// `name NUL value` in the data area, then `libhydrogen_sys::random_buf`
    /// random padding to the end of the 474-byte area (upstream
    /// `s_set_secret`).
    ///
    /// Errors: name-rule failures as [`FormatError::Name`];
    /// `name.len() + value.len() + 1 > 474` as [`FormatError::EntryTooBig`]
    /// (upstream: "Entry too big!").
    pub fn encode(
        name: &[u8],
        value: &[u8],
        out: &mut [u8; ENTRY_PLAIN_LEN],
    ) -> Result<(), FormatError> {
        check_name(name).map_err(FormatError::Name)?;
        if name.len() + value.len() + 1 > ENTRY_DATA_LEN {
            return Err(FormatError::EntryTooBig);
        }

        let slen = value.len() as u16;
        out[0..2].copy_from_slice(&slen.to_le_bytes());

        let data = &mut out[2..2 + ENTRY_DATA_LEN];
        let mut t = 0;
        data[t..t + name.len()].copy_from_slice(name);
        t += name.len();
        data[t] = 0;
        t += 1;
        data[t..t + value.len()].copy_from_slice(value);
        t += value.len();
        libhydrogen_sys::random_buf(&mut data[t..]);
        Ok(())
    }
}

/// Builds one entry plaintext in a fresh buffer ([`Entry::encode`] with an
/// owned output). Padding is `libhydrogen_sys::random_buf`, as upstream.
pub fn build_entry_payload(name: &[u8], value: &[u8]) -> Result<[u8; ENTRY_PLAIN_LEN], FormatError> {
    let mut out = [0u8; ENTRY_PLAIN_LEN];
    Entry::encode(name, value, &mut out)?;
    Ok(out)
}

#[cfg(test)]
mod tests {
    use super::*;

    const MASTER: [u8; 32] = {
        let mut m = [0u8; 32];
        let mut i = 0;
        while i < 32 {
            m[i] = i as u8;
            i += 1;
        }
        m
    };

    #[test]
    fn header_encode_parse_round_trip() {
        let block = Header::encode_init(MASTER, OPS_LIMIT_DEFAULT);
        assert!(block[HEADER_LEN..].iter().all(|&b| b == 0)); // zero padding

        let header = Header::parse(&block).expect("round-trip header parses");
        assert_eq!(header.version, VERSION.0);
        assert_eq!(header.master, MASTER);
        assert_eq!(header.ops_limit, OPS_LIMIT_DEFAULT);
    }

    #[test]
    fn header_parse_tolerates_nonzero_padding() {
        // Upstream readers never check bytes 41..512 (plan §1.2).
        let mut block = Header::encode_init(MASTER, OPS_LIMIT_MIN);
        block[HEADER_LEN] = 0xa5;
        assert_eq!(block[BLOCK - 1], 0);
        block[BLOCK - 1] = 0x5a;
        let header = Header::parse(&block).expect("padding must not be validated");
        assert_eq!(header.master, MASTER);
        assert_eq!(header.ops_limit, OPS_LIMIT_MIN);
    }

    #[test]
    fn header_rejects_unsupported_version() {
        let mut block = Header::encode_init(MASTER, OPS_LIMIT_DEFAULT);
        block[0] = 1;
        assert_eq!(
            Header::parse(&block),
            Err(FormatError::UnsupportedVersion(1))
        );
    }

    #[test]
    fn header_rejects_ops_limit_below_floor() {
        let mut block = Header::encode_init(MASTER, OPS_LIMIT_DEFAULT);
        block[33..41].copy_from_slice(&(OPS_LIMIT_MIN - 1).to_le_bytes());
        assert_eq!(
            Header::parse(&block),
            Err(FormatError::OpsLimitTooLow(OPS_LIMIT_MIN - 1))
        );
        // Exactly at the floor parses (upstream `s_header` case 2).
        block[33..41].copy_from_slice(&OPS_LIMIT_MIN.to_le_bytes());
        assert!(Header::parse(&block).is_ok());
    }

    #[test]
    fn header_ops_limit_is_little_endian_on_disk() {
        let block = Header::encode_init(MASTER, 0x0102_0304_0506_0708);
        assert_eq!(
            &block[33..41],
            &[0x08, 0x07, 0x06, 0x05, 0x04, 0x03, 0x02, 0x01]
        );
    }

    #[test]
    fn entry_encode_decode_round_trip() {
        let name = b"test";
        let value = b"hello\n";
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        Entry::encode(name, value, &mut plain).expect("encodes");

        assert_eq!(&plain[0..2], &(value.len() as u16).to_le_bytes());

        let entry = Entry::decode(&plain).expect("decodes");
        assert_eq!(entry.name, name);
        assert_eq!(entry.value, value);
    }

    #[test]
    fn entry_round_trip_empty_and_binary_values() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        Entry::encode(b"k", b"", &mut plain).expect("empty value encodes");
        let entry = Entry::decode(&plain).expect("decodes");
        assert_eq!(entry.value, b"");

        let binary: [u8; 32] = core::array::from_fn(|i| i as u8);
        Entry::encode(b"mykey", &binary, &mut plain).expect("binary value encodes");
        let entry = Entry::decode(&plain).expect("decodes");
        assert_eq!(entry.name, b"mykey");
        assert_eq!(entry.value, &binary[..]);
    }

    #[test]
    fn entry_round_trip_max_sizes() {
        // 255-byte name: value bound is 474 - 255 - 1 = 218.
        let name = [b'x'; NAME_MAX];
        let value = [b'y'; ENTRY_DATA_LEN - NAME_MAX - 1];
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        Entry::encode(&name, &value, &mut plain).expect("max record encodes");
        let entry = Entry::decode(&plain).expect("decodes");
        assert_eq!(entry.name, &name[..]);
        assert_eq!(entry.value, &value[..]);

        // 1-byte name: value bound is 474 - 1 - 1 = 472 = VALUE_MAX - 1.
        let value = [b'z'; VALUE_MAX - 1];
        Entry::encode(b"k", &value, &mut plain).expect("max short-name record encodes");
        let entry = Entry::decode(&plain).expect("decodes");
        assert_eq!(entry.value, &value[..]);
    }

    #[test]
    fn encode_rejects_name_too_long() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        let name = [b'x'; NAME_MAX + 1];
        assert_eq!(
            Entry::encode(&name, b"v", &mut plain),
            Err(FormatError::Name(NameError::TooLong))
        );
    }

    #[test]
    fn encode_rejects_bad_names() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        assert_eq!(
            Entry::encode(b"", b"v", &mut plain),
            Err(FormatError::Name(NameError::Empty))
        );
        assert_eq!(
            Entry::encode(b"has space", b"v", &mut plain),
            Err(FormatError::Name(NameError::SpecialChar))
        );
        assert_eq!(
            Entry::encode(b"tab\tname", b"v", &mut plain),
            Err(FormatError::Name(NameError::SpecialChar))
        );
    }

    #[test]
    fn encode_rejects_value_too_big() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        // 1-byte name: max value is 472; 473 is one over ("Entry too big!").
        let value = [b'v'; VALUE_MAX];
        assert_eq!(
            Entry::encode(b"k", &value, &mut plain),
            Err(FormatError::EntryTooBig)
        );
    }

    #[test]
    fn decode_rejects_name_too_long() {
        // NUL at index 256 in the data area: name would be 256 bytes.
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        plain[0..2].copy_from_slice(&0u16.to_le_bytes());
        plain[2..2 + NAME_MAX + 1].fill(b'x');
        plain[2 + NAME_MAX + 1] = 0;
        assert_eq!(
            Entry::decode(&plain),
            Err(FormatError::Name(NameError::TooLong))
        );
    }

    #[test]
    fn decode_rejects_record_without_bounded_nul() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        plain[0..2].copy_from_slice(&0u16.to_le_bytes());
        plain[2..].fill(b'x'); // no NUL anywhere in the 474-byte data area
        assert_eq!(Entry::decode(&plain), Err(FormatError::MalformedRecord));
    }

    #[test]
    fn decode_rejects_oversized_slen() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        // Name "k" (NUL at 1): value bound is 472; slen 500 overruns the data.
        plain[0..2].copy_from_slice(&500u16.to_le_bytes());
        plain[2] = b'k';
        plain[3] = 0;
        assert_eq!(Entry::decode(&plain), Err(FormatError::MalformedRecord));

        // slen exactly at the bound decodes.
        plain[0..2].copy_from_slice(&472u16.to_le_bytes());
        assert_eq!(Entry::decode(&plain).map(|e| e.value.len()), Ok(472));
    }

    #[test]
    fn decode_rejects_bad_record_names() {
        let mut plain = [0u8; ENTRY_PLAIN_LEN];
        plain[0..2].copy_from_slice(&0u16.to_le_bytes());
        // Empty name: NUL at data[0].
        assert_eq!(
            Entry::decode(&plain),
            Err(FormatError::Name(NameError::Empty))
        );
        // Name with a special character.
        plain[2] = b'a';
        plain[3] = b' ';
        plain[4] = 0;
        assert_eq!(
            Entry::decode(&plain),
            Err(FormatError::Name(NameError::SpecialChar))
        );
    }

    #[test]
    fn format_errors_map_to_stable_statuses() {
        use crate::error::Status;
        assert_eq!(
            FormatError::UnsupportedVersion(2).status(),
            Status::UnsupportedVersion
        );
        assert_eq!(
            FormatError::OpsLimitTooLow(0).status(),
            Status::MalformedStore
        );
        assert_eq!(FormatError::EntryTooBig.status(), Status::EntryTooBig);
        assert_eq!(FormatError::MalformedRecord.status(), Status::MalformedStore);
        assert_eq!(FormatError::StoreLayout.status(), Status::MalformedStore);
    }
}

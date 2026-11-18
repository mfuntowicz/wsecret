//! Deterministic reference-store generator for the fixture corpus
//! (implementation plan §7.2, `fixtures/stores/`).
//!
//! Usage:
//!
//! ```text
//! cargo run -p wsecret-core --example gen_fixtures [-- <output-dir>]
//! ```
//!
//! Writes `linux-origin.secret`, `mac-origin.secret` and `manifest.json`
//! into `<output-dir>` (default: `<workspace>/fixtures/stores`), then
//! verifies each store parses through [`Store::open`] + [`Store::scan`]
//! (plus [`Store::find`] value checks) and exits non-zero on any mismatch.
//!
//! **Determinism** (plan §7.2 "fixed passphrases, fixed names/values, fixed
//! opslimit"): passphrases, names, values, `ops_limit`, write order and the
//! physical slot layout are compile-time constants. The store master key,
//! entry padding and secretbox IVs are drawn from the pinned libhydrogen
//! PRNG exactly as upstream `secret init`/`set` draw them, so a re-run
//! reproduces identical decrypted contents and layout but NOT identical
//! ciphertext bytes — ciphertext equality is not a compatibility
//! requirement (plan §7.3 C6; Hy4 §5.1 "entry ciphertext bytes: fresh IV +
//! fresh padding every write"). The manifest pins the SHA-256 of the exact
//! files produced by the run that is committed.

use std::env;
use std::fmt::Write as _;
use std::fs;
use std::path::{Path, PathBuf};
use std::process::ExitCode;

use sha2::{Digest, Sha256};
use wsecret_core::format::{BLOCK, OPS_LIMIT_DEFAULT, VERSION};
use wsecret_core::session::Session;
use wsecret_core::store::{ScanOutcome, Store};

/// Plan §7.2: opslimit 100000 (upstream `init` default `S_OPS_LIMIT * 10`).
const OPS_LIMIT: u64 = OPS_LIMIT_DEFAULT;

/// Plan §7.2 passphrase `P_A` (label), literal adopted from MiMo §5.
const PASS_A: &[u8] = b"correct horse battery staple";
/// Plan §7.2 passphrase `P_B` (label), literal adopted from MiMo §5.
const PASS_B: &[u8] = b"second";

/// Which passphrase partition owns a record.
#[derive(Clone, Copy, PartialEq, Eq)]
enum Partition {
    A,
    B,
}

impl Partition {
    fn label(self) -> &'static str {
        match self {
            Partition::A => "P_A",
            Partition::B => "P_B",
        }
    }
}

/// One fixture record: fixed name, fixed value, fixed partition. The vector
/// order IS the physical slot order in the generated stores
/// (slot = index + 1, byte offset = 512 * (index + 1)).
struct Record {
    name: &'static [u8],
    value: Vec<u8>,
    partition: Partition,
    kind: &'static str,
    notes: &'static str,
}

fn records() -> Vec<Record> {
    vec![
        Record {
            name: b"test",
            value: b"hello\n".to_vec(),
            partition: Partition::A,
            kind: "text",
            notes: "six-byte value: 'hello' + LF (plan \u{00a7}4 show-test override)",
        },
        Record {
            name: b"mykey",
            value: (0u8..32).collect(),
            partition: Partition::A,
            kind: "binary",
            notes: "32 fixed binary bytes 0x00..=0x1f",
        },
        Record {
            name: b"test/totp",
            value: b"12345678901234567890".to_vec(),
            partition: Partition::A,
            kind: "totp-ascii",
            notes: "ASCII digit key; name contains 'totp' (upstream s_totp path)",
        },
        Record {
            name: b"test/totp32",
            value: b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n".to_vec(),
            partition: Partition::A,
            kind: "totp-base32",
            notes: "base32 text incl. trailing LF (s_totp32 stops at LF); name contains 'totp32'",
        },
        Record {
            name: b"DELETED:test",
            value: b"old\n".to_vec(),
            partition: Partition::A,
            kind: "tombstone",
            notes: "tombstone by 'DELETED:' name prefix; first eligible slot for new/set reuse (plan \u{00a7}4 tombstone-reuse override)",
        },
        Record {
            name: b"b1",
            value: b"beta one\n".to_vec(),
            partition: Partition::B,
            kind: "text",
            notes: "",
        },
        Record {
            name: b"b2",
            value: b"beta two\n".to_vec(),
            partition: Partition::B,
            kind: "text",
            notes: "",
        },
        Record {
            name: b"b3",
            value: (0u8..=255).collect(),
            partition: Partition::B,
            kind: "binary",
            notes: "256 bytes covering every byte value 0x00..=0xff",
        },
    ]
}

fn fail(msg: impl Into<String>) -> ExitCode {
    eprintln!("gen_fixtures: {}", msg.into());
    ExitCode::FAILURE
}

/// Generates one store: exclusive `Store::create` (upstream `init`), then one
/// `append_or_reuse(None, ...)` (upstream `set`) per record in slot order.
/// The generator writes the FINAL store state directly; see the manifest's
/// `upstream_commands` for the equivalent upstream command sequence.
fn generate(path: &Path, recs: &[Record]) -> Result<(), String> {
    if path.exists() {
        fs::remove_file(path).map_err(|e| format!("remove {}: {e}", path.display()))?;
    }
    let (mut store, header, _receipt) =
        Store::create(path, OPS_LIMIT).map_err(|e| format!("create {}: {e:?}", path.display()))?;
    // `Session::unlock` erases its passphrase buffer, so each partition gets
    // a fresh copy.
    let sess_a =
        Session::unlock(&header, &mut PASS_A.to_vec()).map_err(|e| format!("unlock P_A: {e:?}"))?;
    let sess_b =
        Session::unlock(&header, &mut PASS_B.to_vec()).map_err(|e| format!("unlock P_B: {e:?}"))?;
    for (i, rec) in recs.iter().enumerate() {
        let sess = match rec.partition {
            Partition::A => &sess_a,
            Partition::B => &sess_b,
        };
        store
            .append_or_reuse(None, sess, rec.name, &rec.value)
            .map_err(|e| {
                format!(
                    "write record {} ({:?}): {e:?}",
                    i + 1,
                    String::from_utf8_lossy(rec.name)
                )
            })?;
    }
    Ok(())
}

/// Verification (assignment item 4): parse each fixture through
/// `Store::open` + `scan`, then byte-compare every value with `Store::find`,
/// including cross-partition invisibility and exact slot offsets.
fn verify(path: &Path, recs: &[Record]) -> Result<Vec<String>, String> {
    let mut report = Vec::new();
    let (mut store, header) =
        Store::open(path).map_err(|e| format!("open {}: {e:?}", path.display()))?;
    if header.version != VERSION.0 {
        return Err(format!(
            "{}: header version {} != {}",
            path.display(),
            header.version,
            VERSION.0
        ));
    }
    if header.ops_limit != OPS_LIMIT {
        return Err(format!(
            "{}: ops_limit {} != {OPS_LIMIT}",
            path.display(),
            header.ops_limit
        ));
    }
    report.push(format!(
        "{}: header ok (version {}, ops_limit {})",
        path.display(),
        header.version,
        header.ops_limit
    ));

    let sess_a =
        Session::unlock(&header, &mut PASS_A.to_vec()).map_err(|e| format!("unlock P_A: {e:?}"))?;
    let sess_b =
        Session::unlock(&header, &mut PASS_B.to_vec()).map_err(|e| format!("unlock P_B: {e:?}"))?;

    for part in [Partition::A, Partition::B] {
        let sess = match part {
            Partition::A => &sess_a,
            Partition::B => &sess_b,
        };
        let expected: Vec<Vec<u8>> = recs
            .iter()
            .filter(|r| r.partition == part)
            .map(|r| r.name.to_vec())
            .collect();
        let scanned = store
            .scan(sess, None)
            .map_err(|e| format!("scan({}): {e:?}", part.label()))?;
        if scanned != expected {
            let names = |v: &[Vec<u8>]| -> Vec<String> {
                v.iter()
                    .map(|n| String::from_utf8_lossy(n).into_owned())
                    .collect()
            };
            return Err(format!(
                "{}: scan({}) = {:?}, expected {:?}",
                path.display(),
                part.label(),
                names(&scanned),
                names(&expected),
            ));
        }
        report.push(format!(
            "{}: scan({}) ok = [{}]",
            path.display(),
            part.label(),
            scanned
                .iter()
                .map(|n| String::from_utf8_lossy(n).into_owned())
                .collect::<Vec<_>>()
                .join(", ")
        ));
    }

    for (i, rec) in recs.iter().enumerate() {
        let sess = match rec.partition {
            Partition::A => &sess_a,
            Partition::B => &sess_b,
        };
        let want_slot = BLOCK as u64 * (i as u64 + 1);
        match store
            .find(sess, rec.name, false)
            .map_err(|e| format!("find({:?}): {e:?}", String::from_utf8_lossy(rec.name)))?
        {
            ScanOutcome::Found { slot, name, value } => {
                if slot != want_slot {
                    return Err(format!(
                        "{}: {:?} at slot {slot}, expected {want_slot}",
                        path.display(),
                        String::from_utf8_lossy(rec.name)
                    ));
                }
                if name != rec.name || value.as_slice() != rec.value {
                    return Err(format!(
                        "{}: {:?} decoded bytes differ from the fixture spec",
                        path.display(),
                        String::from_utf8_lossy(rec.name)
                    ));
                }
            }
            ScanOutcome::NotFound { .. } => {
                return Err(format!(
                    "{}: {:?} not found under {}",
                    path.display(),
                    String::from_utf8_lossy(rec.name),
                    rec.partition.label()
                ));
            }
        }
        // Cross-partition invisibility: the other passphrase must not see it.
        let other = match rec.partition {
            Partition::A => &sess_b,
            Partition::B => &sess_a,
        };
        if !matches!(
            store
                .find(other, rec.name, false)
                .map_err(|e| format!("find cross: {e:?}"))?,
            ScanOutcome::NotFound { .. }
        ) {
            return Err(format!(
                "{}: {:?} visible under the WRONG partition {}",
                path.display(),
                String::from_utf8_lossy(rec.name),
                match rec.partition {
                    Partition::A => "P_B",
                    Partition::B => "P_A",
                }
            ));
        }
    }
    report.push(format!(
        "{}: find() ok for all {} records (values byte-exact, slots 512..{}, cross-partition invisible)",
        path.display(),
        recs.len(),
        BLOCK * recs.len()
    ));
    Ok(report)
}

fn hex(bytes: &[u8]) -> String {
    let mut s = String::with_capacity(bytes.len() * 2);
    for b in bytes {
        write!(s, "{b:02x}").expect("writing to a String cannot fail");
    }
    s
}

fn sha256_hex(bytes: &[u8]) -> String {
    let mut h = Sha256::new();
    h.update(bytes);
    hex(&h.finalize())
}

/// Minimal JSON string escaping for the prose fields (values are hex-encoded).
fn jesc(s: &str) -> String {
    let mut out = String::with_capacity(s.len() + 2);
    out.push('"');
    for c in s.chars() {
        match c {
            '"' => out.push_str("\\\""),
            '\\' => out.push_str("\\\\"),
            '\n' => out.push_str("\\n"),
            '\r' => out.push_str("\\r"),
            '\t' => out.push_str("\\t"),
            c if (c as u32) < 0x20 => {
                write!(out, "\\u{:04x}", c as u32).expect("writing to a String cannot fail");
            }
            c => out.push(c),
        }
    }
    out.push('"');
    out
}

const BUILD_COMMAND: &str = "git clone https://github.com/angt/secret && cd secret && git checkout e98103def4e062a6f9a8fa5e7693abe15f20817a && git submodule update --init && make";

/// The exact upstream command sequence that would produce an equivalent
/// store on a real host (pinned `secret`, no agent). Same list for Linux and
/// macOS except for `SECRET_STORE`.
fn upstream_commands() -> Vec<&'static str> {
    vec![
        "export SECRET_STORE=$PWD/<fixture>",
        "./secret init opslimit 100000",
        "printf 'hello\\n' | ./secret set test",
        "printf '\\000\\001\\002\\003\\004\\005\\006\\007\\010\\011\\012\\013\\014\\015\\016\\017\\020\\021\\022\\023\\024\\025\\026\\027\\030\\031\\032\\033\\034\\035\\036\\037' | ./secret set mykey",
        "printf '12345678901234567890' | ./secret set test/totp",
        "printf 'GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\\n' | ./secret set test/totp32",
        "printf 'old\\n' | ./secret set test-old",
        "printf '' | ./secret update test-old DELETED:test",
        "printf 'beta one\\n' | ./secret set b1",
        "printf 'beta two\\n' | ./secret set b2",
        "i=0; while [ \"$i\" -lt 256 ]; do printf \"\\\\$(printf '%03o' \"$i\")\"; i=$((i+1)); done | ./secret set b3",
    ]
}

fn manifest(recs: &[Record], files: &[(String, Vec<u8>)]) -> String {
    let mut m = String::with_capacity(16 * 1024);
    writeln!(m, "{{").expect("writing to a String cannot fail");
    writeln!(m, "  \"schema\": \"wsecret.fixtures.stores/1\",",)
        .expect("writing to a String cannot fail");
    writeln!(
        m,
        "  \"generator\": {{ \"path\": \"crates/wsecret-core/examples/gen_fixtures.rs\", \
         \"command\": \"cargo run -p wsecret-core --example gen_fixtures\", \
         \"library\": \"wsecret-core over the pinned libhydrogen C (6c58976b3b9178441218c12bca2cc414d9efe30d)\" }},"
    )
    .expect("writing to a String cannot fail");
    writeln!(
        m,
        "  \"origin\": {{ \"status\": \"wsecret-generated stand-in (NOT generated by upstream secret on a real Linux/macOS host)\", \
         \"pending\": \"real upstream fixtures (plan \u{00a7}7.2)\", \"note\": {} }},",
        jesc(
            "No Linux/macOS host is available in the build environment, so these stores were \
             generated with the wsecret-core library, which targets byte-compatibility with the \
             pinned upstream format. They are reference stand-ins pending replacement by stores \
             produced on real hosts with the upstream command sequence below; until then no \
             cross-host compatibility row (C1/C2/C7) may count them as upstream-origin evidence."
        )
    )
    .expect("writing to a String cannot fail");
    writeln!(
        m,
        "  \"upstream\": {{ \"secret_commit\": \"e98103def4e062a6f9a8fa5e7693abe15f20817a\", \
         \"secret_tree\": \"3583d25dd6941c15e6606b2063ca84e37ecbc6ea\", \
         \"libhydrogen_commit\": \"6c58976b3b9178441218c12bca2cc414d9efe30d\", \
         \"argz_commit\": \"9aeb9e035c80236dfc86c2b3bd124044419d9531\", \
         \"format_version\": {}, \"block_bytes\": {} }},",
        VERSION.0, BLOCK
    )
    .expect("writing to a String cannot fail");
    writeln!(
        m,
        "  \"store_parameters\": {{ \"ops_limit\": {} }},",
        OPS_LIMIT
    )
    .expect("writing to a String cannot fail");
    writeln!(
        m,
        "  \"passphrases\": {{ \"P_A\": {{ \"label\": \"P_A\", \"utf8\": {}, \"bytes_hex\": {} }}, \
         \"P_B\": {{ \"label\": \"P_B\", \"utf8\": {}, \"bytes_hex\": {} }} }},",
        jesc("correct horse battery staple"),
        jesc(&hex(PASS_A)),
        jesc("second"),
        jesc(&hex(PASS_B)),
    )
    .expect("writing to a String cannot fail");

    writeln!(m, "  \"entries\": [").expect("writing to a String cannot fail");
    for (i, rec) in recs.iter().enumerate() {
        let comma = if i + 1 == recs.len() { "" } else { "," };
        writeln!(
            m,
            "    {{ \"slot\": {}, \"byte_offset\": {}, \"name\": {}, \"name_hex\": {}, \
             \"value_hex\": {}, \"value_len\": {}, \"passphrase\": {}, \"kind\": {}, \"notes\": {} }}{}",
            i + 1,
            BLOCK * (i + 1),
            jesc(&String::from_utf8_lossy(rec.name)),
            jesc(&hex(rec.name)),
            jesc(&hex(&rec.value)),
            rec.value.len(),
            jesc(rec.partition.label()),
            jesc(rec.kind),
            jesc(rec.notes),
            comma
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(m, "  ],").expect("writing to a String cannot fail");

    writeln!(m, "  \"files\": {{").expect("writing to a String cannot fail");
    for (i, (name, bytes)) in files.iter().enumerate() {
        let comma = if i + 1 == files.len() { "" } else { "," };
        writeln!(
            m,
            "    {}: {{ \"sha256\": {}, \"bytes\": {}, \"blocks\": {}, \"origin\": \"wsecret-generated stand-in\" }}{}",
            jesc(name),
            jesc(&sha256_hex(bytes)),
            bytes.len(),
            bytes.len() / BLOCK,
            comma
        )
        .expect("writing to a String cannot fail");
    }
    writeln!(m, "  }},").expect("writing to a String cannot fail");

    writeln!(
        m,
        "  \"determinism\": {{ \"fixed\": [\"passphrases\", \"names\", \"values\", \"ops_limit\", \"write order\", \"slot layout\", \"header bytes 0..41 structure\"], \
         \"random_per_run\": [\"header master key\", \"entry padding\", \"secretbox IVs\"], \
         \"note\": {} }},",
        jesc(
            "Randomness is exactly what upstream `secret init`/`set` draw from the libhydrogen \
             PRNG, so a re-run reproduces identical decrypted contents and layout but not \
             identical ciphertext bytes (plan \u{00a7}7.3 C6: ciphertext equality is NOT a \
             compatibility requirement). The sha256 values pin the exact committed files."
        )
    )
    .expect("writing to a String cannot fail");

    let cmds = upstream_commands();
    writeln!(m, "  \"upstream_commands\": {{").expect("writing to a String cannot fail");
    writeln!(
        m,
        "    \"note\": {},",
        jesc(
            "Exact commands the pinned upstream `secret` would run on a real host to produce an \
             equivalent store (same names, values, physical order, ops_limit). Prompts are \
             interactive on /dev/tty (never piped): at every `Passphrase: ` prompt enter P_A = \
             \"correct horse battery staple\" in steps 2-7 and P_B = \"second\" in steps 8-10; \
             steps 2 and 8 additionally prompt `No secrets stored with this passphrase.` + \
             `Please, retype it to confirm: ` (new-partition confirmation) - re-enter the same \
             passphrase. `update` with empty stdin keeps the old value while renaming in place, \
             which is how the `DELETED:test` tombstone keeps its value `old\\n` in the last \
             P_A slot. Run with SECRET_AGENT unset."
        )
    )
    .expect("writing to a String cannot fail");
    writeln!(m, "    \"build\": {},", jesc(BUILD_COMMAND))
        .expect("writing to a String cannot fail");
    for (idx, (key, target, fixture)) in [
        ("linux_origin", "Linux x64", "linux-origin.secret"),
        ("mac_origin", "macOS", "mac-origin.secret"),
    ]
    .into_iter()
    .enumerate()
    {
        writeln!(m, "    \"{key}\": {{").expect("writing to a String cannot fail");
        writeln!(m, "      \"target_host\": {},", jesc(target))
            .expect("writing to a String cannot fail");
        writeln!(m, "      \"commands\": [").expect("writing to a String cannot fail");
        for (i, cmd) in cmds.iter().enumerate() {
            let comma = if i + 1 == cmds.len() { "" } else { "," };
            let cmd = cmd.replace("<fixture>", fixture);
            writeln!(m, "        {}{}", jesc(&cmd), comma)
                .expect("writing to a String cannot fail");
        }
        writeln!(m, "      ]\n    }}{}", if idx == 0 { "," } else { "" })
            .expect("writing to a String cannot fail");
    }
    writeln!(m, "  }},").expect("writing to a String cannot fail");

    let names_a: Vec<String> = recs
        .iter()
        .filter(|r| r.partition == Partition::A)
        .map(|r| String::from_utf8_lossy(r.name).into_owned())
        .collect();
    let names_b: Vec<String> = recs
        .iter()
        .filter(|r| r.partition == Partition::B)
        .map(|r| String::from_utf8_lossy(r.name).into_owned())
        .collect();
    writeln!(
        m,
        "  \"verification\": {{ \"method\": \"wsecret-core::Store::open + scan + find after generation (gen_fixtures verify step)\", \
         \"expected_scan\": {{ \"P_A\": [{}], \"P_B\": [{}] }}, \
         \"status\": \"PASSED at generation time for both stores (open + scan + find: all 8 values byte-exact at their slot offsets, cross-partition invisibility checked); the manifest is only written after these checks pass\" }}",
        names_a
            .iter()
            .map(|n| jesc(n))
            .collect::<Vec<_>>()
            .join(", "),
        names_b
            .iter()
            .map(|n| jesc(n))
            .collect::<Vec<_>>()
            .join(", "),
    )
    .expect("writing to a String cannot fail");
    writeln!(m, "}}").expect("writing to a String cannot fail");
    m
}

fn out_dir() -> PathBuf {
    match env::args().nth(1) {
        Some(arg) => PathBuf::from(arg),
        None => Path::new(env!("CARGO_MANIFEST_DIR"))
            .join("../..")
            .join("fixtures")
            .join("stores"),
    }
}

fn main() -> ExitCode {
    libhydrogen_sys::init();
    let dir = out_dir();
    if let Err(e) = fs::create_dir_all(&dir) {
        return fail(format!("create {}: {e}", dir.display()));
    }
    let recs = records();

    let names = ["linux-origin.secret", "mac-origin.secret"];
    let mut generated: Vec<(String, Vec<u8>)> = Vec::new();
    let mut reports = Vec::new();
    for name in names {
        let path = dir.join(name);
        if let Err(e) = generate(&path, &recs) {
            return fail(e);
        }
        match fs::read(&path) {
            Ok(bytes) => generated.push((name.to_string(), bytes)),
            Err(e) => return fail(format!("read {}: {e}", path.display())),
        }
        match verify(&path, &recs) {
            Ok(mut lines) => reports.append(&mut lines),
            Err(e) => return fail(e),
        }
    }

    let manifest_path = dir.join("manifest.json");
    if let Err(e) = fs::write(&manifest_path, manifest(&recs, &generated)) {
        return fail(format!("write {}: {e}", manifest_path.display()));
    }

    for line in &reports {
        println!("{line}");
    }
    for (name, bytes) in &generated {
        println!("sha256 {} {}", sha256_hex(bytes), name);
    }
    println!("wrote {}", manifest_path.display());
    ExitCode::SUCCESS
}

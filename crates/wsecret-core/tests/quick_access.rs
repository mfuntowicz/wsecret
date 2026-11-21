//! Behavior tests for the Quick Access metadata projection: the exact-byte
//! default mapping (virtual Default, arbitrary depth, item+container,
//! literal/synthetic Default, empty/deceptive segments), Codes discovery and
//! computation (exact `totp`/`totp32` components, the `topt` alias, no
//! `totp-notes` discovery, no first-descendant copy), bounded index/search,
//! the checked compare-and-set writes (other partitions byte-preserved),
//! the finite store-size limit with its per-open override, and the writer
//! mutex ACL fail-closed rule.
//!
//! Every case here is a consumer-visible behavior of the documented Quick
//! Access contract; no internal-detail assertions.
//!
//! Custom harness (like `wsecret-cli/tests/p4.rs` and `residency_r2a.rs`):
//! the §5.8 boundary is process-wide — `init_process_protection` hardens the
//! process, every thread alive with secret use must have been registered
//! through a hardened path, and the watchdog's poison is sticky — so the
//! libtest harness's own threads can never share a protected process with a
//! case. Each case therefore runs in a ROLE subprocess of this same binary:
//! the parent spawns `--quick-role <case>` per case and asserts the role's
//! exit status. Production admission is untouched; each role opts into the
//! boundary exactly as a library host must.
//!
//! One more §5.8 fixture rule follows from that boundary: the residency
//! watchdog stops as soon as the process holds no live session and no
//! in-flight acquisition, and its stop→restart spans the residual-thread
//! detection window (the watchdog's own hardened threads unregister on exit
//! while still alive, and the watchdog's poison is sticky). A role therefore
//! runs ONE unlock epoch: the session returned by `build` stays alive for the
//! whole case, and the multi-partition / external-writer cases lock and drop
//! each surplus session inside its own scope before any later unlock, with at
//! least the fixture session still resident. Unlock-after-drain across the
//! watchdog restart is the R2-A suite's territory, not this projection
//! suite's.

use std::path::{Path, PathBuf};
use std::sync::atomic::{AtomicU32, Ordering};

use wsecret_core::error::{Error, LimitKind, LimitRemedy, NameError, Status};
use wsecret_core::format::{Header, OPS_LIMIT_MIN};
use wsecret_core::quick::{
    self, CodeKind, CodeState, CodeTarget, CodeVia, ImportCode, LinkOutcome, NavOptions, NavRef,
    Resolution, SearchQuery, Target, WriteError, WriteExpect, display_name, display_segment,
    discover_code_with, EMPTY_SEGMENT_DISPLAY, NAMED_DEFAULT_LABEL, VIRTUAL_ROOT_LABEL,
};
use wsecret_core::session::Session;
use wsecret_core::store::{CommitState, Limits, ScanOutcome, Store, STORE_BYTES_MAX};
use wsecret_core::totp::{totp, totp32, totp_for};

const PASS: &[u8] = b"correct horse battery staple";
const PASS_B: &[u8] = b"second";
const BLOCK: u64 = 512;

static COUNTER: AtomicU32 = AtomicU32::new(0);

fn init() {
    static INIT: std::sync::Once = std::sync::Once::new();
    INIT.call_once(|| {
        libhydrogen_sys::init();
        wsecret_core::windows::security::init_process_protection().expect("process protection");
    });
}

fn temp_store(tag: &str) -> PathBuf {
    std::env::temp_dir().join(format!(
        "wsecret-quick-{}-{}-{tag}.secret",
        std::process::id(),
        COUNTER.fetch_add(1, Ordering::Relaxed),
    ))
}

/// Builds a store whose partition `PASS` holds `records` (physical order) and
/// returns the fixture session KEPT ALIVE: the role's single unlock epoch
/// (module docs). Surplus sessions of the multi-partition cases are locked
/// and dropped inside their own scopes before any later unlock.
fn build(tag: &str, records: &[(&[u8], &[u8])]) -> (PathBuf, Session) {
    init();
    let path = temp_store(tag);
    let (mut store, header, _) = Store::create(&path, OPS_LIMIT_MIN).expect("create store");
    let mut pass = PASS.to_vec();
    let s = Session::unlock(&header, &mut pass).expect("unlock A");
    for (name, value) in records {
        store
            .append_or_reuse(None, &s, name, value)
            .expect("write record");
    }
    (path, s)
}

/// Reopens the store from disk under the caller's already-live session —
/// never a second unlock.
fn reopen(path: &Path) -> Store {
    Store::open(path).expect("open store").0
}

fn value_at(store: &mut Store, s: &Session, name: &[u8]) -> Option<Vec<u8>> {
    match store.find(s, name, false).expect("find") {
        ScanOutcome::Found { value, .. } => Some(value.as_slice().to_vec()),
        ScanOutcome::NotFound { .. } => None,
    }
}

fn file_bytes(path: &Path) -> Vec<u8> {
    std::fs::read(path).expect("read store")
}

// ---------------------------------------------------------------------------
// Default projection (the mapping table)
// ---------------------------------------------------------------------------

fn default_projection_maps_virtual_root_and_named_vault() {
    let (path, s) = build(
        "projection",
        &[
            (b"token", b"v1"),
            (b"GitHub/password", b"v2"),
            (b"Work/GitHub/password", b"v3"),
            (
                b"Work/Engineering/Platform/GitHub/deploy/prod/token",
                b"v4",
            ),
        ],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let tree = index.tree();

    // `token` → Virtual Default → item token directly at the root.
    let root = tree.virtual_root().expect("virtual root");
    assert_eq!(root.label, VIRTUAL_ROOT_LABEL);
    let token = root.child(b"token").expect("token node");
    assert_eq!(token.item.as_ref().map(|r| r.name.as_slice()), Some(&b"token"[..]));
    assert!(token.children.is_empty());

    // `GitHub/password` → Virtual Default → GitHub → password (no vault!).
    let gh = root.child(b"GitHub").expect("GitHub container");
    assert!(gh.item.is_none(), "pure container has no own value");
    let pw = gh.child(b"password").expect("password item");
    assert_eq!(
        pw.item.as_ref().map(|r| r.name.as_slice()),
        Some(&b"GitHub/password"[..])
    );

    // `Work/GitHub/password` → Work (literal vault) → GitHub → password.
    let work = tree.vault(b"Work").expect("Work vault");
    let pw2 = work
        .child(b"GitHub")
        .expect("GitHub in vault")
        .child(b"password")
        .expect("password in vault");
    assert_eq!(
        pw2.item.as_ref().map(|r| r.name.as_slice()),
        Some(&b"Work/GitHub/password"[..])
    );

    // Arbitrary depth: every component preserved in order.
    let deep_name = b"Work/Engineering/Platform/GitHub/deploy/prod/token";
    let mut node = work;
    for seg in [
        &b"Engineering"[..],
        &b"Platform"[..],
        &b"GitHub"[..],
        &b"deploy"[..],
        &b"prod"[..],
    ] {
        node = node.child(seg).expect("deep container");
        assert!(node.item.is_none());
    }
    let leaf = node.child(b"token").expect("deep leaf");
    assert_eq!(
        leaf.item.as_ref().map(|r| r.name.as_slice()),
        Some(&deep_name[..])
    );

    // The per-record rule: the Work vault never leaks into the virtual root.
    assert!(root.child(b"Work").is_none());

    std::fs::remove_file(&path).unwrap();
}

fn arbitrary_depth_is_supported_iteratively() {
    // 64 components: no three-level model, no recursion on untrusted depth.
    // Segment labels stay deliberately short: the full name must respect the
    // store's 255-byte name limit (`NAME_MAX`; longer names are rejected
    // `NameError::TooLong`), and DEPTH — not name length — is what this case
    // exercises. `s0`..`s62` + `leaf` is 246 bytes.
    let mut name: Vec<u8> = Vec::new();
    for i in 0..63u8 {
        name.extend_from_slice(format!("s{i}").as_bytes());
        name.push(b'/');
    }
    name.extend_from_slice(b"leaf");
    let (path, s) = build("depth", &[(&name, b"deep-value")]);
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let tree = index.tree();
    let mut node = tree.vault(b"s0").expect("vault s0");
    for i in 1..63u8 {
        node = node
            .child(format!("s{i}").as_bytes())
            .unwrap_or_else(|| panic!("container s{i}"));
        assert!(node.item.is_none());
    }
    let leaf = node.child(b"leaf").expect("leaf at depth 64");
    assert_eq!(
        leaf.item.as_ref().map(|r| r.name.as_slice()),
        Some(name.as_slice())
    );
    // Identity is exact bytes: the record resolves by its full name.
    assert!(matches!(
        index.resolve_exact(&name),
        Resolution::Unique(_)
    ));
    std::fs::remove_file(&path).unwrap();
}

fn item_and_container_are_distinct_nodes_with_distinct_actions() {
    let (path, s) = build(
        "item-container",
        &[(b"Work/GitHub/key", b"own"), (b"Work/GitHub/key/public", b"pub")],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let tree = index.tree();
    let key = tree
        .vault(b"Work")
        .expect("Work")
        .child(b"GitHub")
        .expect("GitHub")
        .child(b"key")
        .expect("key node");

    // `key` is BOTH an item (own value) and a container (children):
    // the UI offers distinct actions; there is no "value of the container"
    // and no first-descendant resolution.
    assert_eq!(
        key.item.as_ref().map(|r| r.name.as_slice()),
        Some(&b"Work/GitHub/key"[..])
    );
    let public = key.child(b"public").expect("public child");
    assert_eq!(
        public.item.as_ref().map(|r| r.name.as_slice()),
        Some(&b"Work/GitHub/key/public"[..])
    );
    std::fs::remove_file(&path).unwrap();
}

fn literal_and_synthetic_default_roots_stay_distinct_and_addressable() {
    let (path, s) = build(
        "two-defaults",
        &[(b"Default/GitHub/password", b"named"), (b"GitHub/password", b"ungrouped")],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let tree = index.tree();

    // Distinct internal roots, visibly disambiguated.
    assert_eq!(tree.roots.len(), 2);
    let virtual_root = tree.virtual_root().expect("virtual root");
    assert_eq!(virtual_root.label, VIRTUAL_ROOT_LABEL);
    let named = tree.vault(b"Default").expect("literal Default vault");
    assert_eq!(named.label, NAMED_DEFAULT_LABEL);
    assert_ne!(virtual_root.key, named.key);

    // Both records stay addressable by exact name bytes.
    match index.resolve_exact(b"Default/GitHub/password") {
        Resolution::Unique(row) => {
            assert_eq!(row.r.name.as_slice(), &b"Default/GitHub/password"[..])
        }
        other => panic!("expected unique, got {other:?}"),
    }
    match index.resolve_exact(b"GitHub/password") {
        Resolution::Unique(row) => {
            assert_eq!(row.r.name.as_slice(), &b"GitHub/password"[..])
        }
        other => panic!("expected unique, got {other:?}"),
    }

    // Each record maps under ITS OWN root (the per-record rule).
    assert_eq!(
        named
            .child(b"GitHub")
            .expect("GitHub in named Default")
            .child(b"password")
            .expect("password")
            .item
            .as_ref()
            .map(|r| r.name.as_slice()),
        Some(&b"Default/GitHub/password"[..])
    );
    assert_eq!(
        virtual_root
            .child(b"GitHub")
            .expect("GitHub in virtual Default")
            .child(b"password")
            .expect("password")
            .item
            .as_ref()
            .map(|r| r.name.as_slice()),
        Some(&b"GitHub/password"[..])
    );
    std::fs::remove_file(&path).unwrap();
}

fn empty_and_deceptive_segments_are_data_with_distinct_displays() {
    let (path, s) = build(
        "segments",
        &[
            (b"Work//GitHub/token", b"v"),
            (b"a/", b"v"),
            (b"/b", b"v"),
            (b"x/./y", b"v"),
            (b"z/..", b"v"),
            (b"q/\\", b"v"),
            (b"k\xff", b"v"),
            (b"caf\xc3\xa9", b"v"),
        ],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let tree = index.tree();

    // Split ONLY on ASCII slash; empty segments survive with an explicit
    // marker: `Work//GitHub/token` → Work → \empty → GitHub → token.
    let work = tree.vault(b"Work").expect("Work");
    let empty = work.child(b"").expect("empty segment preserved");
    assert_eq!(empty.label, EMPTY_SEGMENT_DISPLAY);
    assert_eq!(
        empty
            .child(b"GitHub")
            .expect("GitHub")
            .child(b"token")
            .expect("token")
            .item
            .as_ref()
            .map(|r| r.name.as_slice()),
        Some(&b"Work//GitHub/token"[..])
    );

    // Leading/trailing slashes produce empty segments too.
    assert!(tree
        .virtual_root()
        .expect("virtual")
        .child(b"a")
        .expect("a")
        .child(b"")
        .is_some());
    assert_eq!(
        display_name(b"a/"),
        format!("a/{}", EMPTY_SEGMENT_DISPLAY)
    );

    // Dots and backslashes are data — no filesystem normalization. `x/./y`
    // has three segments, so the documented root rule (≥3 segments) makes
    // `x` the displayed VAULT; the dot stays an ordinary segment below it.
    let x = tree.vault(b"x").expect("x vault");
    let dot = x.child(b".").expect("dot segment is data");
    assert_eq!(dot.label, ".");
    assert!(dot.child(b"y").expect("y").item.is_some());
    let z = tree.virtual_root().unwrap().child(b"z").expect("z");
    let dotdot = z.child(b"..").expect("dot-dot segment is data");
    assert_eq!(dotdot.label, "..");
    let q = tree.virtual_root().unwrap().child(b"q").expect("q");
    let backslash = q.child(b"\\").expect("backslash segment is data");
    assert_eq!(backslash.label, "\\\\");

    // Escape rendering is injective and distinguishes literal marker text.
    assert_eq!(display_segment(b""), EMPTY_SEGMENT_DISPLAY);
    assert_eq!(display_segment(b"\\empty"), "\\\\empty");
    assert_ne!(display_segment(b""), display_segment(b"\\empty"));
    assert_eq!(display_name(b"k\xff"), "k\\xFF");
    assert_eq!(display_name(b"caf\xc3\xa9"), "caf\\xC3\\xA9");
    let mut rendered: Vec<String> = Vec::new();
    for row in index.rows() {
        let d = display_name(&row.r.name);
        assert!(!rendered.contains(&d), "display collision for {:?}", row.r.name);
        rendered.push(d);
    }

    // Non-UTF-8 names are addressable by exact bytes.
    match index.resolve_exact(b"k\xff") {
        Resolution::Unique(row) => assert_eq!(row.r.name.as_slice(), &b"k\xff"[..]),
        other => panic!("expected unique, got {other:?}"),
    }
    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// Codes: discovery (exact components) and computation
// ---------------------------------------------------------------------------

fn codes_discovery_is_exact_components_not_substrings() {
    let (path, s) = build(
        "codes-discovery",
        &[
            (b"x/totp", b"seed"),
            (b"totp32/GitHub", b"seed"),
            (b"GitHub/totp32", b"seed"),
            (b"Work/totp32/GitHub/alex", b"seed"),
            (b"Work/topt/GitHub/alex", b"seed"),
            (b"x/TOTPkey", b"seed"),
            (b"mytotp32", b"seed"),
            (b"totp-notes", b"seed"),
            (b"notes/totp-notes", b"seed"),
        ],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");

    let code_of = |name: &[u8]| {
        index
            .rows()
            .iter()
            .find(|row| row.r.name == name)
            .unwrap_or_else(|| panic!("row {name:?}"))
            .code
    };

    // The four documented shapes, plus a legacy top-level `totp`.
    assert_eq!(
        code_of(b"x/totp"),
        Some(CodeTarget::Supported {
            kind: CodeKind::Raw,
            via: CodeVia::Totp
        })
    );
    for name in [
        &b"totp32/GitHub"[..],
        &b"GitHub/totp32"[..],
        &b"Work/totp32/GitHub/alex"[..],
    ] {
        assert_eq!(
            code_of(name),
            Some(CodeTarget::Supported {
                kind: CodeKind::Base32,
                via: CodeVia::Totp32
            }),
            "{name:?}"
        );
    }
    assert_eq!(
        code_of(b"Work/topt/GitHub/alex"),
        Some(CodeTarget::Supported {
            kind: CodeKind::Raw,
            via: CodeVia::ToptAlias
        })
    );

    // No discovery from labels or substrings; matching is case-sensitive.
    for name in [
        &b"x/TOTPkey"[..],
        &b"mytotp32"[..],
        &b"totp-notes"[..],
        &b"notes/totp-notes"[..],
    ] {
        assert_eq!(code_of(name), None, "{name:?} must not be discovered");
    }

    // The single adapter also honors explicit import metadata.
    assert_eq!(
        discover_code_with(b"Work/topt/GitHub/alex", Some(ImportCode::Kind(CodeKind::Base32))),
        Some(CodeTarget::Supported {
            kind: CodeKind::Base32,
            via: CodeVia::ToptAlias
        })
    );
    assert_eq!(
        discover_code_with(b"plain", Some(ImportCode::Kind(CodeKind::Raw))),
        Some(CodeTarget::Supported {
            kind: CodeKind::Raw,
            via: CodeVia::Import
        })
    );
    assert_eq!(
        discover_code_with(b"plain", Some(ImportCode::Unsupported)),
        Some(CodeTarget::UnsupportedImport)
    );
    assert_eq!(discover_code_with(b"plain", None), None);
    std::fs::remove_file(&path).unwrap();
}

fn codes_computation_matches_core_generators_and_never_the_substring_matcher() {
    let (path, s) = build(
        "codes-compute",
        &[
            (b"a/totp", b"\x0b"),                 // raw key: 1 byte
            (b"b/totp32", b"JBSWY3DPEHPK3PXP"),   // base32 seed
            (b"W/topt/x", b"\x0b"),               // alias: raw
            (b"i/totp", b""),                     // invalid seed
        ],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let rows = quick::codes(&mut store, &s, &index, 5).expect("codes");
    assert_eq!(rows.len(), 4, "invalid seed still produces a row");

    let row_of = |name: &[u8]| {
        rows.iter()
            .find(|row| row.link.name == name)
            .unwrap_or_else(|| panic!("code row {name:?}"))
    };

    // Raw component → the core `totp` generator (counter 5/30 = 0).
    let a = row_of(b"a/totp");
    assert_eq!(a.digits().unwrap(), totp(&[0x0b], 0).unwrap().as_slice());
    assert_eq!(a.valid_until, 30);

    // Base32 component → `totp32` (upstream quirk decode), pinned KAT.
    let b32 = row_of(b"b/totp32");
    assert_eq!(std::str::from_utf8(b32.digits().unwrap()).unwrap(), "282760");
    assert_eq!(
        b32.digits().unwrap(),
        totp32(b"JBSWY3DPEHPK3PXP", 0).unwrap().as_slice(),
        "the adapter uses the core Base32 generator verbatim"
    );

    // `topt` alias → raw TOTP, computed through the adapter even though the
    // CLI's historical substring matcher would reject the name entirely.
    let w = row_of(b"W/topt/x");
    assert_eq!(w.digits().unwrap(), totp(&[0x0b], 0).unwrap().as_slice());
    assert_eq!(totp_for(b"W/topt/x", &[0x0b], 5), None, "never pass topt to totp_for");

    // Invalid seed → "Code unavailable", never a seed fallback.
    let i = row_of(b"i/totp");
    assert!(matches!(i.state, CodeState::Invalid));
    assert!(matches!(i.digits(), Err(Error::InvalidTotp)));

    // No seed bytes in any code row (the view shows code + expiry only).
    for row in &rows {
        let rendered = format!("{row:?}");
        assert!(!rendered.contains("JBSWY3DPEHPK3PXP"));
        assert!(!rendered.contains("seed"));
    }

    // The index itself carries no values at all.
    assert!(!format!("{index:?}").contains("JBSWY3DPEHPK3PXP"));

    // Unsupported import parameters are a clear state, not a guess.
    let unsupported = quick::code_at(
        &mut store,
        &s,
        &NavRef {
            slot: rows[0].link.slot,
            name: rows[0].link.name.clone(),
        },
        CodeTarget::UnsupportedImport,
        0,
    )
    .expect("code_at unsupported");
    assert!(matches!(unsupported.state, CodeState::Unsupported));
    assert!(matches!(unsupported.digits(), Err(Error::InvalidTotp)));

    std::fs::remove_file(&path).unwrap();
}

fn code_links_need_a_unique_account_path_and_never_a_descendant() {
    let (path, s) = build(
        "codes-link",
        &[
            (b"test", b"hello"),            // account record
            (b"test/totp", &[0x0b][..]),
            (b"test/totp32", b"MY"),
            (b"x/a", b"not-the-account"),   // container child, NOT `x`
            (b"x/totp", &[0x0b][..]),
            (b"Work/topt/GitHub/alex", &[0x0b][..]),
            (b"Work/GitHub/alex", b"acct"),
            (b"Other/topt/GitHub/alex", &[0x0b][..]),
            (b"Work/GitHub/totp32", b"MY"),
            (b"Work/GitHub", b"virtual"),   // 2 segments → different root
        ],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let row_of = |name: &[u8]| {
        index
            .rows()
            .iter()
            .find(|row| row.r.name == name)
            .unwrap_or_else(|| panic!("row {name:?}"))
    };

    let test_slot = row_of(b"test").r.slot;
    let expected_test = NavRef {
        slot: test_slot,
        name: b"test".to_vec(),
    };
    // Both codes of the account link to the SAME unique account record.
    assert_eq!(
        quick::link_password(&index, row_of(b"test/totp")),
        LinkOutcome::Unique(expected_test.clone())
    );
    assert_eq!(
        quick::link_password(&index, row_of(b"test/totp32")),
        LinkOutcome::Unique(expected_test.clone())
    );

    // NO FIRST-DESCENDANT COPY: `x` does not exist as a record; `x/a` is a
    // descendant and must never be used as the link target.
    assert_eq!(
        quick::link_password(&index, row_of(b"x/totp")),
        LinkOutcome::Unlinked
    );

    // Alias namespace links through the unique full account path in the
    // same displayed vault...
    assert_eq!(
        quick::link_password(&index, row_of(b"Work/topt/GitHub/alex")),
        LinkOutcome::Unique(NavRef {
            slot: row_of(b"Work/GitHub/alex").r.slot,
            name: b"Work/GitHub/alex".to_vec(),
        })
    );
    // ...and identical service names across vaults never cross-link.
    assert_eq!(
        quick::link_password(&index, row_of(b"Other/topt/GitHub/alex")),
        LinkOutcome::Unlinked
    );
    // `Work/GitHub` is a 2-segment record → virtual root; the code record is
    // in the Work vault: different displayed vault → no link.
    assert_eq!(
        quick::link_password(&index, row_of(b"Work/GitHub/totp32")),
        LinkOutcome::Unlinked
    );

    // Ctrl+Enter chooser input: the account has exactly its own codes.
    let codes = quick::codes_for_account(&index, &expected_test);
    let mut names: Vec<&[u8]> = codes.iter().map(|row| row.r.name.as_slice()).collect();
    names.sort_unstable();
    assert_eq!(names, vec![&b"test/totp"[..], &b"test/totp32"[..]]);
    assert!(quick::codes_for_account(
        &index,
        &NavRef {
            slot: row_of(b"x/a").r.slot,
            name: b"x/a".to_vec(),
        }
    )
    .is_empty());

    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// Bounded index and ranked search
// ---------------------------------------------------------------------------

fn index_and_search_are_bounded_with_stable_ranking() {
    let (path, s) = build(
        "bounded",
        &[
            (b"test", b"v"),
            (b"testify", b"v"),
            (b"contest", b"v"),
            (b"test/x", b"v"),
            (b"DELETED:old", b"v"),
        ],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");

    // Tombstones are hidden from normal results.
    assert_eq!(index.rows().len(), 4);
    assert!(index.rows().iter().all(|row| !row.tombstone));
    assert!(!index.truncated());

    // Explicitly included tombstones are flagged, not silent.
    let with_tombs = store
        .navigate(
            &s,
            NavOptions {
                include_tombstones: true,
                max_rows: quick::INDEX_ROWS_MAX,
            },
        )
        .expect("navigate");
    assert_eq!(with_tombs.rows().len(), 5);
    assert!(with_tombs.rows().iter().any(|row| row.tombstone));

    // Row cap: partial indexing is visible and unambiguous.
    let capped = store
        .navigate(
            &s,
            NavOptions {
                include_tombstones: false,
                max_rows: 2,
            },
        )
        .expect("navigate");
    assert_eq!(capped.rows().len(), 2);
    assert!(capped.truncated());

    // Ranking: exact leaf, then leaf prefix, then path-component matches;
    // deterministic tie-break by name bytes.
    let hits = quick::search(&index, &SearchQuery::new(b"test")).expect("search");
    let names: Vec<&[u8]> = hits.rows.iter().map(|row| row.r.name.as_slice()).collect();
    assert_eq!(
        names,
        vec![&b"test"[..], &b"testify"[..], &b"contest"[..], &b"test/x"[..]]
    );
    assert!(!hits.truncated);

    // Result cap + truncation flag.
    let capped = quick::search(
        &index,
        &SearchQuery {
            needle: b"test",
            max_results: 2,
            include_tombstones: false,
        },
    )
    .expect("search");
    assert_eq!(capped.rows.len(), 2);
    assert!(capped.truncated);

    // Empty query matches everything (no tombstones).
    let all = quick::search(&index, &SearchQuery::new(b"")).expect("search all");
    assert_eq!(all.rows.len(), 4);

    // Oversized query: actionable resource-limit rejection.
    let needle = vec![b'q'; 300];
    match quick::search(&index, &SearchQuery::new(&needle)) {
        Err(Error::ResourceLimit(diag)) => {
            assert_eq!(diag.kind, LimitKind::SearchNeedle);
            assert_eq!(diag.actual, 300);
            assert_eq!(diag.limit, 255);
            assert_eq!(diag.remedy, LimitRemedy::ShortenQuery);
            assert_eq!(diag.to_string(),
                "Search query of 300 bytes exceeds the limit of 255 bytes; shorten the search query");
        }
        other => panic!("want SearchNeedle rejection, got {other:?}"),
    }

    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// Checked writes (compare-and-set under the writer lock)
// ---------------------------------------------------------------------------

fn checked_update_is_a_slot_cas_and_preserves_other_partitions() {
    // The fixture session (partition `PASS`) stays alive as the case's
    // residency anchor; the surplus B session is locked and dropped inside
    // its own scope, before any later unlock epoch.
    let (path, s) = build("cas-happy", &[(b"a1", b"A-one"), (b"a2", b"A-two")]);
    // A second passphrase partition in the same physical file.
    {
        let (mut store, header) = Store::open(&path).expect("open");
        let mut pass_b = PASS_B.to_vec();
        let mut s_b = Session::unlock(&header, &mut pass_b).expect("unlock B");
        store.append_or_reuse(None, &s_b, b"b1", b"B-one").expect("b1");
        store.append_or_reuse(None, &s_b, b"b2", b"B-two").expect("b2");
        s_b.lock();
    }

    let mut store = reopen(&path);
    let before = file_bytes(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let a1 = index.resolve_exact(b"a1");
    let a1 = match a1 {
        Resolution::Unique(row) => row.r.clone(),
        other => panic!("a1 unique, got {other:?}"),
    };

    // In-place value update through the checked path.
    let receipt = quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(a1.clone()),
            expect_value: Some(b"A-one"),
        },
        b"a1",
        b"A-one-2",
    )
    .expect("update commits");
    assert_eq!(receipt.state, CommitState::Committed);
    assert_eq!(value_at(&mut store, &s, b"a1").as_deref(), Some(&b"A-one-2"[..]));

    // Rename through the checked path: exact new name bytes.
    let receipt = quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(NavRef {
                slot: a1.slot,
                name: b"a1".to_vec(),
            }),
            expect_value: None,
        },
        b"a1x",
        b"A-one-2",
    )
    .expect("rename commits");
    assert_eq!(receipt.state, CommitState::Committed);
    assert_eq!(value_at(&mut store, &s, b"a1"), None);
    assert_eq!(value_at(&mut store, &s, b"a1x").as_deref(), Some(&b"A-one-2"[..]));

    // Other partition preserved byte-for-byte: only the target 512-byte
    // block changed; the B records' blocks are identical.
    let after = file_bytes(&path);
    assert_eq!(before.len(), after.len(), "in-place write, no growth");
    let changed: Vec<usize> = (0..before.len() / BLOCK as usize)
        .filter(|i| {
            before[i * BLOCK as usize..(i + 1) * BLOCK as usize]
                != after[i * BLOCK as usize..(i + 1) * BLOCK as usize]
        })
        .collect();
    assert_eq!(changed, vec![a1.slot as usize / BLOCK as usize]);

    // ...and the B partition still reads back under its own passphrase (the
    // fixture session keeps the residency anchor across this unlock epoch).
    let (mut store_b, s_b) = {
        let (store, header) = Store::open(&path).expect("open");
        let mut pass_b = PASS_B.to_vec();
        (store, Session::unlock(&header, &mut pass_b).expect("unlock B"))
    };
    assert_eq!(
        value_at(&mut store_b, &s_b, b"b1").as_deref(),
        Some(&b"B-one"[..])
    );
    assert_eq!(
        value_at(&mut store_b, &s_b, b"b2").as_deref(),
        Some(&b"B-two"[..])
    );
    drop(store_b);
    drop(s_b);

    // Create lands in the first tombstone slot or appends (parity) and
    // reports the upstream Exists error on collision.
    let receipt = quick::create_checked(&mut store, &s, b"new", b"fresh").expect("create");
    assert_eq!(receipt.state, CommitState::Committed);
    match quick::create_checked(&mut store, &s, b"new", b"again") {
        Err(WriteError::Exists(hits)) => {
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].name.as_slice(), &b"new"[..]);
        }
        other => panic!("want Exists, got {other:?}"),
    }

    std::fs::remove_file(&path).unwrap();
}

fn checked_writes_refuse_stale_identity_changed_values_and_ambiguity() {
    let (path, s) = build(
        "cas-stale",
        &[(b"p", b"v1"), (b"z", b"zv"), (b"q", b"q1")],
    );
    let mut store = reopen(&path);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    let p = match index.resolve_exact(b"p") {
        Resolution::Unique(row) => row.r.clone(),
        other => panic!("p unique, got {other:?}"),
    };

    // Stale identity: the slot is rebound underneath the caller's view by an
    // external writer — its own store handle and session, retired before any
    // later unlock epoch (the fixture session stays the residency anchor).
    let (mut other, header) = Store::open(&path).expect("open");
    let s2 = Session::unlock(&header, &mut PASS.to_vec()).expect("unlock external");
    other.write_slot(p.slot, &s2, b"rebound", b"taken").expect("rebind");
    drop(other);
    drop(s2);
    match quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(p.clone()),
            expect_value: None,
        },
        b"p",
        b"new",
    ) {
        Err(WriteError::Stale(quick::StaleKind::SlotRebound { found })) => {
            let found = found.expect("the rebound record is visible");
            assert_eq!(found.slot, p.slot);
            assert_eq!(found.name.as_slice(), &b"rebound"[..]);
        }
        other => panic!("want SlotRebound, got {other:?}"),
    }
    // Pre-write rejection: the store still holds the external write.
    assert_eq!(
        value_at(&mut store, &s, b"rebound").as_deref(),
        Some(&b"taken"[..])
    );

    // Value-level CAS: the value changed since the projection.
    match quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(NavRef {
                slot: p.slot,
                name: b"rebound".to_vec(),
            }),
            expect_value: Some(b"WRONG"),
        },
        b"rebound",
        b"new",
    ) {
        Err(WriteError::Stale(quick::StaleKind::ValueChanged)) => {}
        other => panic!("want ValueChanged, got {other:?}"),
    }
    assert_eq!(
        value_at(&mut store, &s, b"rebound").as_deref(),
        Some(&b"taken"[..])
    );

    // Renaming onto an existing name would create duplicate-name ambiguity.
    match quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(NavRef {
                slot: p.slot,
                name: b"rebound".to_vec(),
            }),
            expect_value: None,
        },
        b"z",
        b"v",
    ) {
        Err(WriteError::Exists(hits)) => {
            assert_eq!(hits.len(), 1);
            assert_eq!(hits[0].name.as_slice(), &b"z"[..]);
        }
        other => panic!("want Exists, got {other:?}"),
    }
    assert_eq!(value_at(&mut store, &s, b"z").as_deref(), Some(&b"zv"[..]));

    // Name-rule rejection is actionable and pre-write.
    match quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(NavRef {
                slot: p.slot,
                name: b"rebound".to_vec(),
            }),
            expect_value: None,
        },
        b"has space",
        b"v",
    ) {
        Err(WriteError::Invalid(NameError::SpecialChar)) => {}
        other => panic!("want Invalid, got {other:?}"),
    }

    // Duplicate names (upstream `update`-rename parity can create them):
    // name-only addressing is refused, the picked NavRef still commits to
    // exactly its own slot. Same external-writer shape: its session is again
    // retired before anything else unlocks.
    let (mut other, header) = Store::open(&path).expect("open");
    let s2 = Session::unlock(&header, &mut PASS.to_vec()).expect("unlock external");
    let q_slot = match other.find(&s2, b"q", false).expect("find q") {
        ScanOutcome::Found { slot, .. } => slot,
        _ => panic!("q exists"),
    };
    other.write_slot(q_slot, &s2, b"rebound", b"second").expect("dup");
    drop(other);
    drop(s2);
    let index = store.navigate(&s, NavOptions::default()).expect("navigate");
    match index.resolve_exact(b"rebound") {
        Resolution::Ambiguous(rows) => assert_eq!(rows.len(), 2),
        other => panic!("want Ambiguous, got {other:?}"),
    }
    match quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Name(b"rebound"),
            expect_value: None,
        },
        b"rebound",
        b"v",
    ) {
        Err(WriteError::Stale(quick::StaleKind::AmbiguousName)) => {}
        other => panic!("want AmbiguousName, got {other:?}"),
    }
    let before = file_bytes(&path);
    let receipt = quick::update_checked(
        &mut store,
        &s,
        WriteExpect {
            target: Target::Record(NavRef {
                slot: q_slot,
                name: b"rebound".to_vec(),
            }),
            expect_value: Some(b"second"),
        },
        b"rebound",
        b"second-2",
    )
    .expect("picked NavRef commits");
    assert_eq!(receipt.state, CommitState::Committed);
    let after = file_bytes(&path);
    let changed: Vec<usize> = (0..before.len() / BLOCK as usize)
        .filter(|i| {
            before[i * BLOCK as usize..(i + 1) * BLOCK as usize]
                != after[i * BLOCK as usize..(i + 1) * BLOCK as usize]
        })
        .collect();
    assert_eq!(changed, vec![q_slot as usize / BLOCK as usize], "exactly the picked slot");

    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// Store-size limit (finite default, explicit per-open override)
// ---------------------------------------------------------------------------

fn store_size_limit_is_finite_by_default_with_trusted_file_override() {
    assert_eq!(STORE_BYTES_MAX, 64 * 1024 * 1024);
    assert_eq!(Limits::default().max_store_bytes, Some(STORE_BYTES_MAX));

    // A store one block past the ceiling: refused BEFORE any allocation
    // with the full diagnosis; the explicit per-open override opens it.
    let path = temp_store("size-limit");
    let mut file = std::fs::File::create(&path).expect("create file");
    use std::io::Write as _;
    file.write_all(&Header::encode_init([0x2a; 32], OPS_LIMIT_MIN))
        .expect("header");
    file.set_len(STORE_BYTES_MAX + BLOCK).expect("grow store");
    drop(file);

    match Store::open(&path) {
        Err(Error::ResourceLimit(diag)) => {
            assert_eq!(diag.kind, LimitKind::StoreBytes);
            assert_eq!(diag.actual, STORE_BYTES_MAX + BLOCK);
            assert_eq!(diag.limit, STORE_BYTES_MAX);
            assert_eq!(diag.remedy, LimitRemedy::TrustedFileOverride);
            assert_eq!(
                diag.to_string(),
                "Store size 67109376 exceeds the limit of 67108864 bytes; \
                 reopen this file with the explicit trusted-file override to \
                 raise the store-size limit"
            );
        }
        Ok(_) => panic!("oversized store was accepted"),
        Err(other) => panic!("want StoreBytes rejection, got {other}"),
    }
    assert!(matches!(
        Store::open_read(&path),
        Err(Error::ResourceLimit(_))
    ));

    // The override is per-open and explicit: None lifts, Some raises.
    assert!(Store::open_with_limits(&path, Limits::trusted_file(None)).is_ok());
    assert!(
        Store::open_with_limits(&path, Limits::trusted_file(Some(STORE_BYTES_MAX + BLOCK))).is_ok()
    );
    assert!(matches!(
        Store::open_with_limits(&path, Limits::trusted_file(Some(STORE_BYTES_MAX))),
        Err(Error::ResourceLimit(_))
    ));

    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// Writer mutex ACL: fail closed before writes
// ---------------------------------------------------------------------------

fn a_squatted_writer_mutex_fails_closed_before_any_write() {
    use windows_sys::Win32::Foundation::CloseHandle;
    use windows_sys::Win32::System::Threading::CreateMutexExW;
    use wsecret_core::windows::file::final_path;
    use wsecret_core::windows::security::writer_mutex_name;

    let (path, s) = build("mutex-squat", &[(b"k", b"v")]);
    let mut store = reopen(&path);

    // Squat `Global\wsecret-store-*` with a FOREIGN DACL (the creator's
    // default descriptor, not the exact two-ACE contract).
    let canonical = {
        let file = std::fs::File::open(&path).expect("open file");
        final_path(&file).expect("canonical path")
    };
    let name = writer_mutex_name(&canonical);
    let wide: Vec<u16> = name.encode_utf16().chain(std::iter::once(0)).collect();
    // SAFETY: null security attributes = the caller's default DACL; the
    // returned handle is owned by the test and closed below.
    let squat = unsafe { CreateMutexExW(std::ptr::null(), wide.as_ptr(), 0, 0x1F0001) };
    assert!(!squat.is_null(), "squat mutex created");

    let before = file_bytes(&path);
    match store.append_or_reuse(None, &s, b"new", b"v") {
        Err(failure) => {
            // Fail closed: the writer mutex failed its ACL/effective-
            // permission validation, so no write path runs.
            assert_eq!(failure.error.status(), Status::MemoryProtection);
            assert_eq!(failure.state, CommitState::NotCommitted);
        }
        Ok(_) => panic!("a squatted writer mutex must disable writes"),
    }
    assert_eq!(file_bytes(&path), before, "store byte-unchanged");

    // SAFETY: owned test handle.
    unsafe {
        let _ = CloseHandle(squat);
    }
    std::fs::remove_file(&path).unwrap();
}

// ---------------------------------------------------------------------------
// Custom harness: one protected ROLE process per case (p4 / R2-A pattern)
// ---------------------------------------------------------------------------

/// Case table: the role name is the case function's name (and the parent's
/// substring filter target).
const CASES: &[(&str, fn())] = &[
    (
        "default_projection_maps_virtual_root_and_named_vault",
        default_projection_maps_virtual_root_and_named_vault,
    ),
    (
        "arbitrary_depth_is_supported_iteratively",
        arbitrary_depth_is_supported_iteratively,
    ),
    (
        "item_and_container_are_distinct_nodes_with_distinct_actions",
        item_and_container_are_distinct_nodes_with_distinct_actions,
    ),
    (
        "literal_and_synthetic_default_roots_stay_distinct_and_addressable",
        literal_and_synthetic_default_roots_stay_distinct_and_addressable,
    ),
    (
        "empty_and_deceptive_segments_are_data_with_distinct_displays",
        empty_and_deceptive_segments_are_data_with_distinct_displays,
    ),
    (
        "codes_discovery_is_exact_components_not_substrings",
        codes_discovery_is_exact_components_not_substrings,
    ),
    (
        "codes_computation_matches_core_generators_and_never_the_substring_matcher",
        codes_computation_matches_core_generators_and_never_the_substring_matcher,
    ),
    (
        "code_links_need_a_unique_account_path_and_never_a_descendant",
        code_links_need_a_unique_account_path_and_never_a_descendant,
    ),
    (
        "index_and_search_are_bounded_with_stable_ranking",
        index_and_search_are_bounded_with_stable_ranking,
    ),
    (
        "checked_update_is_a_slot_cas_and_preserves_other_partitions",
        checked_update_is_a_slot_cas_and_preserves_other_partitions,
    ),
    (
        "checked_writes_refuse_stale_identity_changed_values_and_ambiguity",
        checked_writes_refuse_stale_identity_changed_values_and_ambiguity,
    ),
    (
        "store_size_limit_is_finite_by_default_with_trusted_file_override",
        store_size_limit_is_finite_by_default_with_trusted_file_override,
    ),
    (
        "a_squatted_writer_mutex_fails_closed_before_any_write",
        a_squatted_writer_mutex_fails_closed_before_any_write,
    ),
];

/// Spawns this binary as a role process for one case and returns its outcome.
/// A failing case reports through its captured stderr (panic message included).
fn run_role(name: &str) -> Result<(), String> {
    let exe = std::env::current_exe().map_err(|e| e.to_string())?;
    let output = std::process::Command::new(exe)
        .arg("--quick-role")
        .arg(name)
        .output()
        .map_err(|e| format!("spawn role {name}: {e}"))?;
    if output.status.success() {
        Ok(())
    } else {
        Err(format!(
            "role {name} failed (exit {:?})\n--- stdout ---\n{}\n--- stderr ---\n{}",
            output.status.code(),
            String::from_utf8_lossy(&output.stdout),
            String::from_utf8_lossy(&output.stderr),
        ))
    }
}

/// Parent suite: one role process per case. `filter` narrows by substring,
/// mirroring a libtest name filter.
fn run_parent(filter: Option<&str>) -> Result<(), String> {
    let mut ran = 0usize;
    let mut failures: Vec<String> = Vec::new();
    for (name, _) in CASES {
        if let Some(filter) = filter {
            if !name.contains(filter) {
                continue;
            }
        }
        ran += 1;
        match run_role(name) {
            Ok(()) => eprintln!("quick-access {name}: PASS"),
            Err(error) => {
                eprintln!("quick-access {name}: FAIL\n{error}");
                failures.push((*name).to_owned());
            }
        }
    }
    if ran == 0 {
        return Err(format!("no quick-access case matches {filter:?}"));
    }
    if failures.is_empty() {
        eprintln!("quick-access: {ran} case(s) PASS");
        Ok(())
    } else {
        Err(format!(
            "{} of {ran} case(s) failed: {}",
            failures.len(),
            failures.join(", ")
        ))
    }
}

fn main() {
    let args: Vec<String> = std::env::args().collect();
    let mut role: Option<String> = None;
    let mut filter: Option<String> = None;
    let mut i = 1;
    while i < args.len() {
        match args[i].as_str() {
            "--quick-role" => {
                role = args.get(i + 1).cloned();
                i += 2;
            }
            // Cargo forwards test-args verbatim (e.g. `--test-threads=1`);
            // they name libtest knobs and are irrelevant to this harness.
            flag if flag.starts_with('-') => i += 1,
            name => {
                filter = Some(name.to_owned());
                i += 1;
            }
        }
    }
    let result = if let Some(name) = role {
        // FIRST ACTION in the role process: opt into the §5.8 boundary
        // before any secret material exists, exactly like a library host.
        init();
        match CASES.iter().find(|(case, _)| *case == name.as_str()) {
            Some((_, case)) => {
                case();
                Ok(())
            }
            None => Err(format!("unknown quick-access case {name}")),
        }
    } else {
        run_parent(filter.as_deref())
    };
    if let Err(error) = result {
        eprintln!("quick-access FAILURE: {error}");
        std::process::exit(1);
    }
}

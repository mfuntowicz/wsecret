//! Quick Access metadata projection (spec: the WSecret Quick Access
//! requirements, §6 key paths / §7 Codes / §8 index): a bounded names-only
//! index over one unlocked session, the navigation tree, bounded ranked
//! search, the one Codes discovery/computation adapter, and the checked
//! (compare-and-set) write helpers.
//!
//! Ground rules this module encodes:
//!
//! - **Names and identity are exact bytes.** A record is identified by
//!   `slot` + its exact name bytes ([`NavRef`]); display strings are
//!   injective renderings and NEVER identity. Nothing is reconstructed from
//!   a breadcrumb.
//! - **No values in the projection.** The index, tree, search hits and Codes
//!   rows carry no record values; secret bytes are read only for a specific
//!   record (broker/CLI-side) or to derive one code at the moment of the
//!   action. `Debug` output contains no record values.
//! - **No recursive traversal.** The tree is built and walked iteratively
//!   (untrusted depth: a valid name may carry up to 255 path segments).
//! - **A slash-delimited tree is a navigation projection**, not the store.
//!   The default projection (per record) is the spec table below; a virtual
//!   root never adds bytes to a stored name.
//! - **CLI behavior is untouched**: the historical substring TOTP matcher
//!   ([`crate::totp::totp_for`]) stays exactly as it is for `show`; the
//!   Codes adapter here is component-exact and separate.
//!
//! Default projection for raw keys without source metadata (per record):
//!
//! | Stored name | Visible result |
//! |---|---|
//! | `token` | Virtual **Default** → item **token** at the root. |
//! | `GitHub/password` | Virtual **Default** → **GitHub** → **password**. |
//! | `Work/GitHub/password` | **Work** → **GitHub** → **password**. |
//! | any depth | every component preserved in order (no 3-level model). |
//! | `Work/GitHub/key` + `Work/GitHub/key/public` | **key** is both an item and a container: distinct actions. |
//! | `Default/GitHub/password` + `GitHub/password` | literal vs synthesized Default roots are distinct internal roots, visibly disambiguated (`Default (named)` / `Default (ungrouped)`); both records stay addressable. |
//! | `Work//GitHub/token`, leading/trailing slashes, dots, backslashes, non-UTF-8 | split ONLY on ASCII `/`; empty segments get an explicit display marker; dots and backslashes are data; deceptive bytes are escaped injectively. |
//!
//! One or two segments use the virtual root; at three or more the first
//! segment is the displayed vault and the remainder keeps its order. A
//! short record and a longer record sharing a raw prefix therefore appear
//! under different roots — intentionally (the rule is per record).

use std::collections::HashMap;

use crate::error::{
    Error, LimitExceeded, LimitKind, LimitRemedy, NameError, CommitFailure, CommitReceipt,
};
use crate::format::{ENTRY_DATA_LEN, NAME_MAX, check_name};
use crate::session::{SecretBytes, Session};
use crate::store::{CasFailure, CasMismatch, Store};
use crate::totp::{totp, totp32};

/// Row cap for the bounded metadata index ([`NavOptions::max_rows`] is
/// clamped to it). 4096 rows × ≤256 segments bounds every derived structure.
pub const INDEX_ROWS_MAX: usize = 4096;

/// Default result cap for one search.
pub const SEARCH_RESULTS_DEFAULT: usize = 128;

/// Hard clamp for [`SearchQuery::max_results`].
pub const SEARCH_RESULTS_MAX: usize = 1024;

/// Longest accepted search query (byte-identical bound to a record name:
/// a longer query can never match). Above this: [`LimitKind::SearchNeedle`].
pub const SEARCH_NEEDLE_MAX: usize = NAME_MAX;

/// Display marker for an empty path segment. Because `\` is escaped as
/// `\\` in [`display_segment`], literal marker text (a segment whose bytes
/// are `\empty`) renders differently (`\\empty`) and can never collide with
/// the marker.
pub const EMPTY_SEGMENT_DISPLAY: &str = r"\empty";

/// Display label of the synthesized root (records of one or two segments).
/// The space makes it impossible to equal any escaped segment rendering.
pub const VIRTUAL_ROOT_LABEL: &str = "Default (ungrouped)";

/// Display label of a literal vault named exactly `Default`, disambiguated
/// from [`VIRTUAL_ROOT_LABEL`].
pub const NAMED_DEFAULT_LABEL: &str = "Default (named)";

// ---------------------------------------------------------------------------
// Display rendering (injective; identity stays the raw bytes)
// ---------------------------------------------------------------------------

/// Renders one path segment for display: printable ASCII `0x21..=0x7E`
/// literally except `\`, which renders as `\\`; every other byte (including
/// DEL, non-ASCII bytes, bidi-capable bytes and — defensively — the control
/// range a valid name cannot contain) renders as `\xNN` (uppercase hex).
/// Empty segments render as [`EMPTY_SEGMENT_DISPLAY`].
///
/// Distinct byte strings always render distinctly, and literal marker text
/// is always distinguishable from the marker (the `\\` rule).
pub fn display_segment(seg: &[u8]) -> String {
    if seg.is_empty() {
        return EMPTY_SEGMENT_DISPLAY.to_string();
    }
    let mut out = String::with_capacity(seg.len());
    for &b in seg {
        match b {
            b'\\' => out.push_str("\\\\"),
            0x21..=0x7e => out.push(b as char),
            _ => {
                use std::fmt::Write as _;
                let _ = write!(out, "\\x{b:02X}");
            }
        }
    }
    out
}

/// Renders a whole record name for display: [`display_segment`] per
/// `/`-separated component joined with `/`. Injective over valid record
/// names (segments cannot contain `/`, and `/` is never emitted by
/// [`display_segment`] for any other byte).
pub fn display_name(name: &[u8]) -> String {
    split_segments(name)
        .into_iter()
        .map(display_segment)
        .collect::<Vec<_>>()
        .join("/")
}

/// Splits a raw name into its `/`-separated components (ASCII slash only;
/// no normalization of any kind). Always at least one (possibly empty)
/// component.
fn split_segments(name: &[u8]) -> Vec<&[u8]> {
    name.split(|&b| b == b'/').collect()
}

// ---------------------------------------------------------------------------
// Codes discovery (the one adapter)
// ---------------------------------------------------------------------------

/// TOTP seed encoding.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeKind {
    /// Raw key bytes (upstream `totp`).
    Raw,
    /// Base32 text decoded first (upstream `totp32`).
    Base32,
}

/// How one Codes entry was discovered.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeVia {
    /// An exact `totp` path component (raw).
    Totp,
    /// An exact `totp32` path component (Base32; wins over `totp`).
    Totp32,
    /// An exact `topt` path component: the requested alias display
    /// namespace. Raw TOTP by default (consistent with `totp`); Base32 only
    /// through explicit import metadata.
    ToptAlias,
    /// Explicit import metadata (no code component in the name).
    Import,
}

/// One Codes entry: the single adapter's discovery result.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum CodeTarget {
    /// Supported by the core generator (30 s period, 6 digits, HMAC-SHA-1 —
    /// [`crate::totp::totp`] / [`crate::totp::totp32`], never a guess).
    Supported {
        /// Seed encoding.
        kind: CodeKind,
        /// Discovery provenance.
        via: CodeVia,
    },
    /// An explicit import whose parameters the core generator does not
    /// support: surfaced as a clear unsupported state, never silently
    /// mapped to different parameters.
    UnsupportedImport,
}

/// Explicit import metadata for one record (the "explicit import type"
/// discovery input). v0 raw-key stores carry no metadata; this is the hook
/// an importer uses so the rule stays in ONE adapter.
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub enum ImportCode {
    /// The import declares TOTP with supported parameters and this encoding.
    Kind(CodeKind),
    /// The import declares TOTP with parameters the core generator does not
    /// support.
    Unsupported,
}

/// The ONE Codes discovery adapter: exact, case-sensitive path components.
/// A record is a code when one `/`-separated component is exactly `totp32`
/// (Base32), `totp` (raw), or `topt` (alias, raw). Precedence `totp32` >
/// `totp` > `topt`. A label such as `totp-notes` is NOT an exact component
/// and never enters the Codes list; nor do substring names like `mytotp32`.
///
/// This is deliberately NOT the CLI's historical substring rule
/// ([`crate::totp::totp_for`] matches any name containing `totp` and misses
/// `topt` entirely): that rule is unchanged for `show`, and a `topt` name
/// must never be passed blindly to it.
pub fn discover_code(name: &[u8]) -> Option<CodeTarget> {
    let segments = split_segments(name);
    let has = |c: &[u8]| segments.iter().any(|s| *s == c);
    let (kind, via) = if has(b"totp32") {
        (CodeKind::Base32, CodeVia::Totp32)
    } else if has(b"totp") {
        (CodeKind::Raw, CodeVia::Totp)
    } else if has(b"topt") {
        (CodeKind::Raw, CodeVia::ToptAlias)
    } else {
        return None;
    };
    Some(CodeTarget::Supported { kind, via })
}

/// [`discover_code`] with explicit import metadata: explicit metadata is
/// authoritative for the encoding (this is the only way a `topt` alias entry
/// becomes Base32) and can discover entries that carry no code component.
/// Unsupported import parameters map to [`CodeTarget::UnsupportedImport`].
pub fn discover_code_with(name: &[u8], explicit: Option<ImportCode>) -> Option<CodeTarget> {
    let found = discover_code(name);
    match explicit {
        None => found,
        Some(ImportCode::Unsupported) => Some(CodeTarget::UnsupportedImport),
        Some(ImportCode::Kind(kind)) => Some(match found {
            Some(CodeTarget::Supported { via, .. }) => CodeTarget::Supported { kind, via },
            _ => CodeTarget::Supported {
                kind,
                via: CodeVia::Import,
            },
        }),
    }
}

// ---------------------------------------------------------------------------
// The bounded metadata index
// ---------------------------------------------------------------------------

/// A record's identity: the slot AND the exact name bytes. Both fields are
/// identity — name-only addressing cannot separate duplicate names
/// (upstream first-match shadowing).
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavRef {
    /// Byte offset of the record block (multiple of 512, >= 512).
    pub slot: u64,
    /// The exact record name bytes as stored.
    pub name: Vec<u8>,
}

/// One index row: metadata only — never a record value.
#[derive(Clone, Debug, PartialEq, Eq)]
pub struct NavRow {
    /// Identity (slot + exact name bytes).
    pub r: NavRef,
    /// The record carries the raw `DELETED:` tombstone prefix (hidden from
    /// normal results unless explicitly included).
    pub tombstone: bool,
    /// Codes discovery result for this name (component-exact).
    pub code: Option<CodeTarget>,
    /// The exact name occurs on more than one indexed record: mutation or
    /// copy by name is impossible; the caller must pick a [`NavRef`].
    pub ambiguous: bool,
}

/// Options for [`Store::navigate`].
#[derive(Clone, Copy, Debug, PartialEq, Eq)]
pub struct NavOptions {
    /// Include `DELETED:`-prefixed tombstone records (hidden by default).
    pub include_tombstones: bool,
    /// Row cap for the bounded index; clamped to [`INDEX_ROWS_MAX`].
    pub max_rows: usize,
}

impl Default for NavOptions {
    fn default() -> Self {
        NavOptions {
            include_tombstones: false,
            max_rows: INDEX_ROWS_MAX,
        }
    }
}

/// The result of resolving one exact name against the index.
#[derive(Debug)]
pub enum Resolution<'i> {
    /// Exactly one (non-tombstone) row carries this exact name.
    Unique(&'i NavRow),
    /// More than one row carries this exact name: the caller must pick a
    /// [`NavRef`] — never guess, never take the first.
    Ambiguous(Vec<&'i NavRow>),
    /// No indexed record carries this exact name.
    NotFound,
}

/// The bounded, names-only index of one unlocked session (one passphrase
/// partition; other partitions are cryptographically invisible).
#[derive(Debug)]
pub struct NavIndex {
    rows: Vec<NavRow>,
    truncated: bool,
}

impl NavIndex {
    /// The indexed rows, in physical slot order.
    pub fn rows(&self) -> &[NavRow] {
        &self.rows
    }

    /// True when the row cap dropped at least one further matching record:
    /// partial indexing is visible and unambiguous.
    pub fn truncated(&self) -> bool {
        self.truncated
    }

    /// The row for an exact identity (slot + name), if indexed.
    pub fn get(&self, r: &NavRef) -> Option<&NavRow> {
        self.rows.iter().find(|row| &row.r == r)
    }

    /// Exact-byte resolution over non-tombstone rows. Never silently
    /// first-match: duplicates come back as [`Resolution::Ambiguous`].
    pub fn resolve_exact(&self, name: &[u8]) -> Resolution<'_> {
        let mut hits = self.rows.iter().filter(|row| !row.tombstone && row.r.name == name);
        match (hits.next(), hits.next()) {
            (Some(only), None) => Resolution::Unique(only),
            (Some(a), Some(b)) => Resolution::Ambiguous(
                [a, b].into_iter().chain(hits).collect(),
            ),
            (None, _) => Resolution::NotFound,
        }
    }

    /// The navigation tree for this index (iterative construction).
    pub fn tree(&self) -> NavTree {
        let mut roots: Vec<NavNode> = Vec::new();
        for row in &self.rows {
            insert_row(&mut roots, row);
        }
        NavTree { roots }
    }
}

impl Store {
    /// Builds the bounded names-only index for the unlocked session: one
    /// streaming pass with a fixed 512-byte read buffer, ≤
    /// `opts.max_rows.clamp(1, INDEX_ROWS_MAX)` rows, no record values.
    /// Other passphrase partitions stay invisible; a decryptable but
    /// structurally invalid record aborts the scan (upstream `s_keylen`
    /// parity) with [`crate::error::FormatError::MalformedRecord`].
    pub fn navigate(&mut self, s: &Session, opts: NavOptions) -> Result<NavIndex, Error> {
        let cap = opts.max_rows.clamp(1, INDEX_ROWS_MAX);
        let mut rows: Vec<NavRow> = Vec::new();
        let mut truncated = false;
        self.scan_each_at(s, None, &mut |slot, name, tombstone| {
            if tombstone && !opts.include_tombstones {
                return Ok(true);
            }
            if rows.len() >= cap {
                // One row past the cap proves the index is partial, exactly.
                truncated = true;
                return Ok(false);
            }
            rows.push(NavRow {
                r: NavRef {
                    slot,
                    name: name.to_vec(),
                },
                tombstone,
                code: discover_code(name),
                ambiguous: false,
            });
            Ok(true)
        })?;
        // Duplicate exact names are the ambiguous-identity hazard: flag all
        // of them (on a truncated index, ambiguity is known for indexed rows).
        let mut counts: HashMap<&[u8], usize> = HashMap::new();
        for row in &rows {
            *counts.entry(row.r.name.as_slice()).or_insert(0) += 1;
        }
        let ambiguous: Vec<bool> = rows
            .iter()
            .map(|row| counts[row.r.name.as_slice()] > 1)
            .collect();
        for (row, ambiguous) in rows.iter_mut().zip(ambiguous) {
            row.ambiguous = ambiguous;
        }
        Ok(NavIndex { rows, truncated })
    }
}

// ---------------------------------------------------------------------------
// Navigation tree (the default projection; iterative)
// ---------------------------------------------------------------------------

/// The key of a tree node. Roots are distinct internal keys: the synthesized
/// virtual root and each literal vault (first segment of a 3+-segment name)
/// never merge, even when their labels look alike.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum NodeKey {
    /// The synthesized root for one/two-segment records.
    VirtualRoot,
    /// A literal vault root: the exact first-segment bytes of 3+-segment
    /// records.
    Vault(Vec<u8>),
    /// One path segment below a root.
    Segment(Vec<u8>),
}

impl NodeKey {
    fn sort_pair(&self) -> (u8, &[u8]) {
        match self {
            NodeKey::VirtualRoot => (0, &[]),
            NodeKey::Vault(bytes) => (1, bytes),
            NodeKey::Segment(bytes) => (2, bytes),
        }
    }
}

/// One navigation node. A node is a container when it has `children`, an
/// item when `item` is set; `Work/GitHub/key` + `Work/GitHub/key/public`
/// make **key** both (distinct actions: copy the item's value vs browse the
/// children). There is deliberately NO "value of this container" and NO
/// "first descendant" accessor: copying always addresses one picked item.
#[derive(Clone, Debug)]
pub struct NavNode {
    /// The node's identity within its parent.
    pub key: NodeKey,
    /// Display label (injective rendering; never identity).
    pub label: String,
    /// The record mapped to this node, if any.
    pub item: Option<NavRef>,
    /// More than one record maps to this item slot (duplicate exact names):
    /// mutation/copy of the item is disabled until the caller disambiguates.
    pub item_ambiguous: bool,
    /// Child nodes, kept in sorted (ordinal byte) order by construction.
    pub children: Vec<NavNode>,
}

impl NavNode {
    /// The child container/item under exactly `segment` bytes (binary search
    /// over the sorted children).
    pub fn child(&self, segment: &[u8]) -> Option<&NavNode> {
        self.children
            .binary_search_by(|node| key_bytes(&node.key).cmp(&Some(segment)))
            .ok()
            .map(|i| &self.children[i])
    }
}

fn key_bytes(key: &NodeKey) -> Option<&[u8]> {
    match key {
        NodeKey::VirtualRoot => None,
        NodeKey::Vault(bytes) | NodeKey::Segment(bytes) => Some(bytes),
    }
}

/// The navigation forest: the virtual root and the literal vault roots.
#[derive(Clone, Debug)]
pub struct NavTree {
    /// Roots: the virtual root (if any 1/2-segment record exists) first,
    /// then literal vaults in ordinal byte order.
    pub roots: Vec<NavNode>,
}

impl NavTree {
    /// The synthesized root ([`VIRTUAL_ROOT_LABEL`]), if present.
    pub fn virtual_root(&self) -> Option<&NavNode> {
        self.roots
            .iter()
            .find(|node| node.key == NodeKey::VirtualRoot)
    }

    /// The literal vault root with exactly these first-segment bytes, if
    /// present. A vault named `Default` is a different root from
    /// [`Self::virtual_root`] and displays as [`NAMED_DEFAULT_LABEL`].
    pub fn vault(&self, name: &[u8]) -> Option<&NavNode> {
        self.roots.iter().find(|node| match &node.key {
            NodeKey::Vault(bytes) => bytes == name,
            _ => false,
        })
    }
}

/// The default projection of one record name (per record): one or two
/// segments map under the virtual root; at three or more the FIRST segment
/// is the displayed vault and the remainder keep their order. Returns the
/// root identity and the node path below it (always non-empty).
fn project(name: &[u8]) -> (NodeKey, Vec<&[u8]>) {
    let segments = split_segments(name);
    if segments.len() <= 2 {
        (NodeKey::VirtualRoot, segments)
    } else {
        (NodeKey::Vault(segments[0].to_vec()), segments[1..].to_vec())
    }
}

/// Iterative (never recursive) insert of one record into the forest; nodes
/// are kept sorted by exact key bytes as they are created.
fn insert_row(roots: &mut Vec<NavNode>, row: &NavRow) {
    let (root_key, path) = project(&row.r.name);
    let mut node = find_or_insert_root(roots, root_key);
    for i in 0..path.len() - 1 {
        node = find_or_insert_child(node, path[i]);
    }
    let leaf = find_or_insert_child(node, path[path.len() - 1]);
    if leaf.item.is_some() {
        leaf.item_ambiguous = true;
    } else {
        leaf.item = Some(row.r.clone());
    }
}

fn root_label(key: &NodeKey) -> String {
    match key {
        NodeKey::VirtualRoot => VIRTUAL_ROOT_LABEL.to_string(),
        NodeKey::Vault(bytes) if bytes == b"Default" => NAMED_DEFAULT_LABEL.to_string(),
        NodeKey::Vault(bytes) => display_segment(bytes),
        NodeKey::Segment(bytes) => display_segment(bytes),
    }
}

fn find_or_insert_root<'n>(roots: &'n mut Vec<NavNode>, key: NodeKey) -> &'n mut NavNode {
    let (kind, bytes) = key.sort_pair();
    let at = roots
        .binary_search_by(|node| node.key.sort_pair().cmp(&(kind, bytes)))
        .unwrap_or_else(|i| i);
    if roots.get(at).is_some_and(|node| node.key.sort_pair() == (kind, bytes)) {
        return &mut roots[at];
    }
    roots.insert(
        at,
        NavNode {
            label: root_label(&key),
            key,
            item: None,
            item_ambiguous: false,
            children: Vec::new(),
        },
    );
    &mut roots[at]
}

fn find_or_insert_child<'n>(parent: &'n mut NavNode, segment: &[u8]) -> &'n mut NavNode {
    let at = parent
        .children
        .binary_search_by(|node| key_bytes(&node.key).cmp(&Some(segment)))
        .unwrap_or_else(|i| i);
    if parent
        .children
        .get(at)
        .is_some_and(|node| key_bytes(&node.key) == Some(segment))
    {
        return &mut parent.children[at];
    }
    parent.children.insert(
        at,
        NavNode {
            key: NodeKey::Segment(segment.to_vec()),
            label: display_segment(segment),
            item: None,
            item_ambiguous: false,
            children: Vec::new(),
        },
    );
    &mut parent.children[at]
}

// ---------------------------------------------------------------------------
// Bounded ranked search over the index
// ---------------------------------------------------------------------------

/// One search request (search runs over the index only — no file I/O while
/// typing).
#[derive(Clone, Copy, Debug)]
pub struct SearchQuery<'a> {
    /// Query bytes: ASCII case-insensitive comparison for SEARCH ONLY —
    /// identity and every operation stay ordinal byte identity.
    pub needle: &'a [u8],
    /// Result cap; clamped to [`SEARCH_RESULTS_MAX`].
    pub max_results: usize,
    /// Include `DELETED:`-prefixed tombstones (hidden by default).
    pub include_tombstones: bool,
}

impl<'a> SearchQuery<'a> {
    /// A query with the ordinary caps ([`SEARCH_RESULTS_DEFAULT`], no
    /// tombstones).
    pub fn new(needle: &'a [u8]) -> Self {
        SearchQuery {
            needle,
            max_results: SEARCH_RESULTS_DEFAULT,
            include_tombstones: false,
        }
    }
}

/// Ranked search hits referencing the index rows (no values, no copies of
/// name bytes beyond the index itself).
#[derive(Debug)]
pub struct SearchHits<'i> {
    /// Hit rows, best rank first.
    pub rows: Vec<&'i NavRow>,
    /// More matches existed than [`SearchQuery::max_results`] allowed.
    pub truncated: bool,
}

/// Rank of one row for a query: 0 = exact leaf/title, 1 = leaf prefix,
/// 2 = path-component match. `None` = no match.
fn match_rank(name: &[u8], needle: &[u8]) -> Option<u8> {
    if needle.is_empty() {
        return Some(2);
    }
    let segments = split_segments(name);
    let leaf = segments[segments.len() - 1];
    let ascii_eq = |a: &[u8], b: &[u8]| a.len() == b.len() && a.eq_ignore_ascii_case(b);
    let ascii_starts = |hay: &[u8], pre: &[u8]| {
        hay.len() >= pre.len() && hay[..pre.len()].eq_ignore_ascii_case(pre)
    };
    if ascii_eq(leaf, needle) {
        Some(0)
    } else if ascii_starts(leaf, needle) {
        Some(1)
    } else if segments
        .iter()
        .any(|seg| ascii_contains(seg, needle))
    {
        Some(2)
    } else {
        None
    }
}

/// ASCII case-insensitive substring test (search parity with `list`'s
/// folding, spec §4).
fn ascii_contains(hay: &[u8], needle: &[u8]) -> bool {
    if needle.is_empty() {
        return true;
    }
    if needle.len() > hay.len() {
        return false;
    }
    hay.windows(needle.len())
        .any(|w| w.eq_ignore_ascii_case(needle))
}

/// Bounded ranked search over the index (spec §8: exact leaf/title first,
/// then prefix, then path-component matches, deterministic tie-break by
/// exact name bytes then slot). A query longer than
/// [`SEARCH_NEEDLE_MAX`] is refused with a full diagnosis
/// ([`LimitKind::SearchNeedle`]).
pub fn search<'i>(
    index: &'i NavIndex,
    query: &SearchQuery<'_>,
) -> Result<SearchHits<'i>, Error> {
    if query.needle.len() > SEARCH_NEEDLE_MAX {
        return Err(Error::ResourceLimit(LimitExceeded {
            kind: LimitKind::SearchNeedle,
            actual: query.needle.len() as u64,
            limit: SEARCH_NEEDLE_MAX as u64,
            remedy: LimitRemedy::ShortenQuery,
        }));
    }
    let cap = query.max_results.min(SEARCH_RESULTS_MAX);
    let mut hits: Vec<(u8, &NavRow)> = Vec::new();
    for row in index.rows() {
        if row.tombstone && !query.include_tombstones {
            continue;
        }
        if let Some(rank) = match_rank(&row.r.name, query.needle) {
            hits.push((rank, row));
        }
    }
    hits.sort_by(|a, b| {
        a.0.cmp(&b.0)
            .then_with(|| a.1.r.name.cmp(&b.1.r.name))
            .then_with(|| a.1.r.slot.cmp(&b.1.r.slot))
    });
    let truncated = hits.len() > cap;
    hits.truncate(cap);
    Ok(SearchHits {
        rows: hits.into_iter().map(|(_, row)| row).collect(),
        truncated,
    })
}

// ---------------------------------------------------------------------------
// Codes: computation (reads only; zero writes/imports/duplications)
// ---------------------------------------------------------------------------

/// One computed code row. Carries no seed: the derived digits (or the
/// unavailable state) and display metadata only.
#[derive(Debug)]
pub struct CodeRow {
    /// The linked record (slot + exact name) — read AT `link.slot`, never
    /// by name (name-only lookup would hit first-match shadowing).
    pub link: NavRef,
    /// How the entry was discovered and how its seed is encoded.
    pub target: CodeTarget,
    /// The derived code (or why there is none).
    pub state: CodeState,
    /// Unix seconds at which the current code expires
    /// (`unix_now / 30 + 1) * 30`).
    pub valid_until: u64,
}

/// The state of one Codes entry.
#[derive(Debug)]
pub enum CodeState {
    /// The 6 ASCII digits (leading zeros preserved), zeroizing owner.
    Code(SecretBytes),
    /// The seed does not produce a code (upstream "Invalid secret"): the UI
    /// shows "Code unavailable"; the seed is never a fallback copy result.
    Invalid,
    /// Explicit import parameters are unsupported: a clear unsupported
    /// state, never a guessed mapping.
    Unsupported,
}

impl CodeRow {
    /// The 6 ASCII digits for a copy action. [`Error::InvalidTotp`] when no
    /// digits exist (invalid seed or unsupported import parameters), the
    /// upstream "Invalid secret" status parity.
    pub fn digits(&self) -> Result<&[u8], Error> {
        match &self.state {
            CodeState::Code(digits) => Ok(digits.as_slice()),
            CodeState::Invalid | CodeState::Unsupported => Err(Error::InvalidTotp),
        }
    }
}

/// Computes the current code for one linked record: reads the record AT
/// `link.slot` and derives at the moment of the call. A slot that no longer
/// holds `link.name` is a stale link ([`Error::Conflict`]) — never a guess.
pub fn code_at(
    store: &mut Store,
    s: &Session,
    link: &NavRef,
    target: CodeTarget,
    unix_now: u64,
) -> Result<CodeRow, Error> {
    let record = store.read_at(s, link.slot)?.ok_or(Error::Conflict)?;
    if record.meta.name != link.name {
        return Err(Error::Conflict);
    }
    let counter = unix_now / 30;
    let state = match target {
        CodeTarget::UnsupportedImport => CodeState::Unsupported,
        CodeTarget::Supported { kind, .. } => {
            let digits = match kind {
                CodeKind::Raw => totp(record.value.as_slice(), counter),
                CodeKind::Base32 => totp32(record.value.as_slice(), counter),
            };
            match digits {
                Some(digits) => CodeState::Code(SecretBytes::from_slice(&digits)?),
                None => CodeState::Invalid,
            }
        }
    };
    // The seed (`record`) drops here, zeroized.
    Ok(CodeRow {
        link: link.clone(),
        target,
        state,
        valid_until: (counter + 1) * 30,
    })
}

/// The Codes view for one index: one row per discovered entry, computed at
/// `unix_now`. Opening the view performs zero imports, duplications or store
/// writes — read-only derivation.
pub fn codes(
    store: &mut Store,
    s: &Session,
    index: &NavIndex,
    unix_now: u64,
) -> Result<Vec<CodeRow>, Error> {
    let mut rows = Vec::new();
    for row in index.rows() {
        if let Some(target) = row.code {
            rows.push(code_at(store, s, &row.r, target, unix_now)?);
        }
    }
    Ok(rows)
}

// ---------------------------------------------------------------------------
// Code ↔ account linking (explicit, conservative: never a descendant guess)
// ---------------------------------------------------------------------------

/// Outcome of linking a code entry to its account's password record.
#[derive(Debug, PartialEq, Eq)]
pub enum LinkOutcome {
    /// Exactly one record carries the full account path in the SAME
    /// displayed vault and this cryptographic partition.
    Unique(NavRef),
    /// More than one record carries that exact name: the caller must
    /// disambiguate; never guess.
    Ambiguous(Vec<NavRef>),
    /// No unique link. Includes: no record at the exact account path, a
    /// different displayed vault, or discovery that yields no account path
    /// (explicit-import entries need explicit link metadata). A container's
    /// descendants are NEVER link targets — there is no first-descendant
    /// copy anywhere in this module.
    Unlinked,
}

/// The account path of a code record: its exact name with the FIRST
/// occurrence of its winning discovery component removed. `None` when the
/// entry was discovered without a code component (import-type entries link
/// only through explicit metadata — out of this adapter).
fn account_name(name: &[u8], target: CodeTarget) -> Option<Vec<u8>> {
    let marker: &[u8] = match target {
        CodeTarget::Supported {
            via: CodeVia::Totp32,
            ..
        } => b"totp32",
        CodeTarget::Supported { via: CodeVia::Totp, .. } => b"totp",
        CodeTarget::Supported {
            via: CodeVia::ToptAlias,
            ..
        } => b"topt",
        CodeTarget::Supported {
            via: CodeVia::Import,
            ..
        }
        | CodeTarget::UnsupportedImport => return None,
    };
    let segments = split_segments(name);
    let at = segments.iter().position(|seg| *seg == marker)?;
    let mut out: Vec<u8> = Vec::new();
    for (i, seg) in segments.iter().enumerate() {
        if i == at {
            continue;
        }
        if !out.is_empty() {
            out.push(b'/');
        }
        out.extend_from_slice(seg);
    }
    Some(out)
}

/// Links one code row to its account's password record under the spec rule:
/// explicit metadata (not derivable here → [`LinkOutcome::Unlinked`]) or a
/// UNIQUE full account path in the SAME displayed vault and this partition.
/// Identical service names across vaults never cross-link, and nothing ever
/// falls back to a descendant record.
pub fn link_password(index: &NavIndex, code: &NavRow) -> LinkOutcome {
    let Some(target) = code.code else {
        return LinkOutcome::Unlinked;
    };
    let Some(account) = account_name(&code.r.name, target) else {
        return LinkOutcome::Unlinked;
    };
    // Same displayed vault: the projection root of the account path must be
    // the projection root of the code record (per-record rule).
    if project(&code.r.name).0 != project(&account).0 {
        return LinkOutcome::Unlinked;
    }
    match index.resolve_exact(&account) {
        Resolution::Unique(row) => LinkOutcome::Unique(row.r.clone()),
        Resolution::Ambiguous(rows) => {
            LinkOutcome::Ambiguous(rows.into_iter().map(|row| row.r.clone()).collect())
        }
        Resolution::NotFound => LinkOutcome::Unlinked,
    }
}

/// The code entries linked to one account record (the Ctrl+Enter chooser
/// input): exactly the entries whose [`link_password`] resolves to
/// `account`. Never a descendant guess.
pub fn codes_for_account<'i>(index: &'i NavIndex, account: &NavRef) -> Vec<&'i NavRow> {
    let wanted = LinkOutcome::Unique(account.clone());
    index
        .rows()
        .iter()
        .filter(|row| row.code.is_some() && link_password(index, row) == wanted)
        .collect()
}

// ---------------------------------------------------------------------------
// Checked writes (safe write helpers)
// ---------------------------------------------------------------------------

/// How a checked write addresses its record.
#[derive(Clone, Debug, PartialEq, Eq)]
pub enum Target<'a> {
    /// The picked record: slot + exact name bytes (unique addressing — the
    /// way UI results address records).
    Record(NavRef),
    /// Address by exact name bytes only; accepted only when exactly one
    /// record carries the name (duplicate names are never guessed).
    Name(&'a [u8]),
}

/// The identity (and optional value) a checked write must observe at the
/// target before it commits.
#[derive(Clone, Debug)]
pub struct WriteExpect<'a> {
    /// The record to update.
    pub target: Target<'a>,
    /// `Some` = value-level compare-and-set: the value must still equal
    /// these bytes (constant-time compare) at commit time.
    pub expect_value: Option<&'a [u8]>,
}

/// Why a checked write refused before write initiation (the store is
/// byte-unchanged in every case).
#[derive(Debug, PartialEq, Eq)]
pub enum StaleKind {
    /// The target slot no longer holds the expected record (absent/opaque,
    /// or rebound to another name).
    SlotRebound {
        /// What the slot holds now, if a record of this session does.
        found: Option<NavRef>,
    },
    /// The record's value changed since the projection was taken
    /// (value-level compare-and-set).
    ValueChanged,
    /// The exact name occurs on more than one record: name-only addressing
    /// is impossible; the caller must pick a [`NavRef`].
    AmbiguousName,
}

/// Failure of [`update_checked`] / [`create_checked`].
#[derive(Debug)]
pub enum WriteError {
    /// Stale identity/value — pre-write, store unchanged. Maps to
    /// [`crate::error::Status::Conflict`].
    Stale(StaleKind),
    /// The target name is already carried by (at least) one other record:
    /// creating or renaming onto it would produce duplicate-name ambiguity.
    /// Maps to [`crate::error::Status::AlreadyExists`]; the colliding
    /// records are reported so the UI can offer them.
    Exists(Vec<NavRef>),
    /// Name-rule or entry-size rejection (pre-write, store unchanged).
    Invalid(NameError),
    /// The write protocol's failure: the §5.6 point 5 commit trichotomy is
    /// preserved unchanged inside.
    Commit(CommitFailure),
}

/// The one-record shape rules (mirroring [`crate::format::Entry::encode`]'s
/// upstream checks) so rejections are actionable BEFORE any write.
fn validate_entry(name: &[u8], value: &[u8]) -> Result<(), NameError> {
    check_name(name)?;
    if name.len() + value.len() + 1 > ENTRY_DATA_LEN {
        return Err(NameError::EntryTooBig);
    }
    Ok(())
}

fn stale_from_mismatch(mismatch: CasMismatch) -> StaleKind {
    if mismatch.value_changed {
        StaleKind::ValueChanged
    } else {
        StaleKind::SlotRebound {
            found: mismatch
                .found
                .map(|meta| NavRef {
                    slot: meta.slot,
                    name: meta.name,
                }),
        }
    }
}

fn scan_exact_names(
    store: &mut Store,
    s: &Session,
    name: &[u8],
    stop_at: usize,
) -> Result<Vec<NavRef>, Error> {
    let mut hits = Vec::new();
    store.scan_each_at(s, None, &mut |slot, found, _tombstone| {
        if found == name {
            hits.push(NavRef {
                slot,
                name: found.to_vec(),
            });
        }
        Ok(hits.len() < stop_at)
    })?;
    Ok(hits)
}

/// Checked update of one record: the writer mutex spans resolve + content
/// compare-and-set + write, §5.6 6b revalidation runs before the write, and
/// the CAS proves the target identity (and optionally the value) is still
/// what the caller saw. Exactly one 512-byte block is rewritten — other
/// records and other passphrase partitions are preserved byte-for-byte, and
/// the commit trichotomy is unchanged.
///
/// Renaming onto a name another record already carries is refused with
/// [`WriteError::Exists`] (it would create duplicate-name ambiguity);
/// updating in place keeps the exact name bytes.
pub fn update_checked(
    store: &mut Store,
    s: &Session,
    expect: WriteExpect<'_>,
    new_name: &[u8],
    new_value: &[u8],
) -> Result<CommitReceipt, WriteError> {
    validate_entry(new_name, new_value).map_err(WriteError::Invalid)?;
    let WriteExpect {
        target,
        expect_value,
    } = expect;
    let mut guard = store
        .lock_writers_scoped()
        .map_err(|e| WriteError::Commit(CommitFailure::before_write(e)))?;

    let (slot, expect_name) = match target {
        Target::Record(r) => (r.slot, r.name.clone()),
        Target::Name(name) => {
            let hits = scan_exact_names(&mut guard, s, name, 2)
                .map_err(|e| WriteError::Commit(CommitFailure::before_write(e)))?;
            match hits.len() {
                0 => {
                    return Err(WriteError::Stale(StaleKind::SlotRebound { found: None }));
                }
                1 => (hits[0].slot, hits[0].name.clone()),
                _ => return Err(WriteError::Stale(StaleKind::AmbiguousName)),
            }
        }
    };

    // A rename may not create duplicate-name ambiguity. In-place saves
    // (same exact name bytes) keep the record's identity untouched.
    if new_name != expect_name.as_slice() {
        let taken = scan_exact_names(&mut guard, s, new_name, usize::MAX)
            .map_err(|e| WriteError::Commit(CommitFailure::before_write(e)))?;
        if !taken.is_empty() {
            return Err(WriteError::Exists(taken));
        }
    }

    guard
        .cas_slot(slot, s, &expect_name, expect_value, new_name, new_value)
        .map_err(|e| match e {
            CasFailure::Mismatch(mismatch) => WriteError::Stale(stale_from_mismatch(mismatch)),
            CasFailure::Write(failure) => WriteError::Commit(failure),
        })
}

/// Checked create of one record (upstream `set`/`new` parity under the
/// writer mutex): an existing decryptable record with this exact name is
/// [`WriteError::Exists`] (upstream `Secret %s exists!`); otherwise the
/// value lands in the first `DELETED:` tombstone slot or appends at EOF —
/// one block, commit trichotomy unchanged.
///
/// The create-side confirmation gate (empty partition evidence) stays the
/// caller's responsibility ([`crate::session::UnlockEvidence`]).
pub fn create_checked(
    store: &mut Store,
    s: &Session,
    name: &[u8],
    value: &[u8],
) -> Result<CommitReceipt, WriteError> {
    validate_entry(name, value).map_err(WriteError::Invalid)?;
    let mut guard = store
        .lock_writers_scoped()
        .map_err(|e| WriteError::Commit(CommitFailure::before_write(e)))?;

    let mut taken: Vec<NavRef> = Vec::new();
    let mut tombstone: Option<u64> = None;
    guard
        .scan_each_at(s, None, &mut |slot, found, is_tombstone| {
            if found == name {
                taken.push(NavRef {
                    slot,
                    name: found.to_vec(),
                });
            }
            if is_tombstone && tombstone.is_none() {
                tombstone = Some(slot);
            }
            Ok(true)
        })
        .map_err(|e| WriteError::Commit(CommitFailure::before_write(e)))?;
    if !taken.is_empty() {
        return Err(WriteError::Exists(taken));
    }
    guard
        .append_or_reuse(tombstone, s, name, value)
        .map_err(WriteError::Commit)
}

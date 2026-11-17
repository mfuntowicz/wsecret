//! `argz`-exact command-line parser for `wsecret`.
//!
//! This module reproduces the dispatch semantics of the pinned upstream
//! parser and command table verbatim (`wsecret-src/argz.c` @
//! `9aeb9e035c80236dfc86c2b3bd124044419d9531` and the `struct argz z[]` table
//! and command bodies in `wsecret-src/secret.c` @
//! `e98103def4e062a6f9a8fa5e7693abe15f20817a`), mapped to u32 Windows exit
//! codes ([`EXIT_OK`] / [`EXIT_FATAL`] / [`EXIT_USAGE`] / [`EXIT_HELP`], plan
//! §4). No store I/O, prompting, or output encoding lives here: [`Dispatch`]
//! executes the selected command.
//!
//! Control flow preserved from the C (each rule is pinned to a source line
//! and pinned by a test):
//! - The walk starts at `argv[1]` and compares whole words against the table
//!   (`argz()` L184–231); only the current walk position is tested against
//!   `help`, so `help` is parser-level (exit 254) at `argv[1]` and at inner
//!   walk positions, while a `help` anywhere inside a command's operand list
//!   is caught by that command's `argz_help()` guard (per-command branch,
//!   exit 255 or the completion path).
//! - `argz_print()` (L81–88) skips entries that `argz_is_available()` (L68–79)
//!   rejects: already-set entries and entries whose group is occupied by a
//!   set entry. Consequences (upstream quirks, preserved): `init help` prints
//!   the `opslimit` row only (the `init` row is set and every other command
//!   row shares its group); `version help` and `init opslimit 50000 help`
//!   print nothing at all; bare `help` prints all 11 rows.
//! - A command's parser that leaves words unconsumed returns the leftover
//!   count (`argz()` L225–228), so the walk resumes at the first unconsumed
//!   word and can then match another table entry (`init version` →
//!   `Option version is not compatible with init`, `init init` → `Option init
//!   is already set`) or stop the walk and be reported by `argz_main()`
//!   (`init opslimit 50000 junk help` → `Option junk is unknown`). A `help`
//!   word can never be the resume word: every inner walk consumes `help` at
//!   its own walk position first, and an unmatched word breaks the walk
//!   before any later `help` is tested — so `init foo help` reports
//!   `Option foo is unknown` and `bogus help` reports `Option bogus is
//!   unknown`.
//! - `init`'s `opslimit` is parsed by `argz_ull()` (L126–166) with base 0
//!   (`strtoull`), `min = 10000`, default `value = 100000`, no suffix
//!   handler: trailing bytes are `badly suffixed`, its `help` slot prints the
//!   value and returns the usage exit.
//! - Commands with an `argz_help(argc, argv)` guard reject a literal `help`
//!   anywhere in their operands (`s_list` L648, `s_do` L683, `s_show` L719,
//!   `s_pass` L769, `s_agent` L792) and apply the plan §4 usage/completion
//!   matrix.

use std::io::Write;

use wsecret_core::format::{OPS_LIMIT_DEFAULT, OPS_LIMIT_MIN};

/// Success: a command ran to completion, or the bare-invocation table.
pub const EXIT_OK: u32 = 0;
/// `Fatal: …` condition (store errors, passphrase mismatch, key errors).
pub const EXIT_FATAL: u32 = 1;
/// Usage error: unknown word, bad option value, help/arity branch.
pub const EXIT_USAGE: u32 = 255;
/// Parser-level help: the argz `help` slot (argz returns -2).
pub const EXIT_HELP: u32 = 254;

/// Upstream `ARGZ_LEN` (`argz.h`): name column width in the help table.
const ARGZ_LEN: usize = 14;
/// Upstream `s_fatal` buffer (`secret.c:291`): `char tmp[256]` holding the
/// `Fatal: ` prefix, the message, and the newline.
const FATAL_CAP: usize = 256;

/// The top-level command table in upstream `main()` order (`secret.c:914`).
pub const COMMANDS: [(&str, &str); 11] = [
    ("init", "Initialize secret"),
    ("list", "List all secrets for a given passphrase"),
    ("show", "Print a secret"),
    ("dump", "Dump a raw secret"),
    ("new", "Generate a new random secret"),
    ("set", "Set a new secret"),
    ("renew", "Regenerate an existing secret"),
    ("update", "Update an existing secret"),
    ("pass", "Print a deterministic secret"),
    ("agent", "Run a process in a trusted zone"),
    ("version", "Show version"),
];

/// The `init` inner table row (`secret.c:618`).
const OPSLIMIT_NAME: &str = "opslimit";
const OPSLIMIT_HELP: &str = "Number of iterations to perform";

/// A dispatched command with its argument words as raw bytes.
///
/// Names stay byte-oriented: keys are arbitrary non-control bytes up to 255
/// (plan §4 key rules), never re-encoded as text here.
#[derive(Debug, PartialEq, Eq)]
pub enum Command<'a> {
    /// `init [opslimit N]` — `ops_limit` is validated (`min` 10000).
    Init { ops_limit: u64 },
    /// `list [NEEDLE]`.
    List { needle: Option<&'a [u8]> },
    /// `show KEY`.
    Show { key: &'a [u8] },
    /// `dump KEY`.
    Dump { key: &'a [u8] },
    /// `new KEY` — generate a random secret into `KEY`.
    New { key: &'a [u8] },
    /// `set KEY` — set `KEY` from stdin/console.
    Set { key: &'a [u8] },
    /// `renew KEY` — regenerate `KEY` in place (name kept).
    Renew { key: &'a [u8] },
    /// `update KEY [NEWKEY]`.
    ///
    /// `new_key: None` is the bare `update KEY` form (empty input exits 0
    /// with no write); `Some` is the rename form where empty input keeps the
    /// old value (`s_do` `secret.c:733`, the rename-keeps-value rule).
    Update {
        key: &'a [u8],
        new_key: Option<&'a [u8]>,
    },
    /// `pass KEY [SUBKEY…]` — `keys` is every operand including `KEY`; the
    /// derivation chain covers all of them (`s_pass` `secret.c:785`).
    Pass { keys: &'a [&'a [u8]] },
    /// `agent [CMD [ARG…]]` — `cmd` empty means the `$SHELL` fallback.
    Agent { cmd: &'a [&'a [u8]] },
    /// `version`.
    Version,
}

/// Non-tty completion branch of a per-command help matrix (plan §4).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub enum NamesAction {
    /// No name output at all (`list`, `pass`, `new`, `set`, and the
    /// multi-word help forms): exit [`EXIT_USAGE`] silently.
    None,
    /// Print the given word (`CMD` for `agent`), then [`EXIT_USAGE`].
    Word(&'static str),
    /// List every stored name to stdout (`show/dump/renew/update help`):
    /// authorized → [`EXIT_USAGE`] after listing (argz propagates -1);
    /// unauthorized non-interactive → silent [`EXIT_OK`].
    List,
}

/// A per-command help/usage branch (the upstream `argz_help(argc, argv)`
/// guards plus their arity conditions).
#[derive(Debug, Clone, Copy, PartialEq, Eq)]
pub struct HelpBranch {
    /// The command whose usage would be printed.
    pub command: &'static str,
    /// The exact upstream usage line (`argv[0]` is the command word; the C
    /// `Usage: %s KEY %s\n` keeps a trailing space before `\n` when the tail
    /// argument is empty).
    pub usage: &'static str,
    /// What a non-tty stdout must produce instead of usage.
    pub names: NamesAction,
}

/// Parser result: everything [`run`] needs to finish without re-parsing.
#[derive(Debug, PartialEq, Eq)]
pub enum Outcome<'a> {
    /// No arguments at all (`main` `secret.c:927`): print the 11-row table,
    /// exit [`EXIT_OK`].
    BareTable,
    /// argz `help` handling (argz returns -2): print these bytes to stdout,
    /// exit [`EXIT_HELP`]. May be EMPTY — see the module docs; upstream
    /// prints whatever `argz_print()` emits for the current set state.
    HelpRows(Vec<u8>),
    /// `init opslimit help` (`argz_ull` help slot): print the clamped value
    /// and a newline to stdout, exit [`EXIT_USAGE`] (argz_ull returns -1).
    OptionValue(u64),
    /// Per-command `help`/arity branch (plan §4 matrix).
    Help(HelpBranch),
    /// A fully parsed command.
    Command(Command<'a>),
    /// A parser error: write these raw bytes plus `\n` to stderr, exit
    /// [`EXIT_USAGE`]. Bytes (not `String`) because `Option %s is unknown`
    /// echoes an arbitrary argv word.
    Error(Vec<u8>),
}

/// Where [`run`] writes and whether stdout is a console (usage matrix input).
pub struct Cli<'a> {
    /// `isatty(1)` equivalent: gates usage text vs. name completion.
    pub stdout_is_tty: bool,
    /// stdout (table, usage, completion names, option values).
    pub stdout: &'a mut dyn Write,
    /// stderr (parser errors and `Fatal: …` lines).
    pub stderr: &'a mut dyn Write,
}

/// Command executor supplied by the binary's dispatch.
pub trait Dispatch {
    /// Execute one parsed command; return its process exit code
    /// ([`EXIT_OK`] on success, [`EXIT_FATAL`] on a `Fatal: …` condition).
    fn execute(&mut self, command: Command<'_>) -> u32;

    /// Non-tty `… help` completion: list every stored name to stdout.
    ///
    /// Return [`EXIT_OK`] for the silent unauthorized case, [`EXIT_USAGE`]
    /// after listing (upstream argz propagates -1), [`EXIT_FATAL`] on a
    /// fatal store condition.
    fn complete_names(&mut self) -> u32;
}

/// The upstream `argz_print_help` line (`argz.c:74`): `"  %-14s  %s\n"`.
fn help_row(name: &str, help: &str) -> String {
    format!("  {:<width$}  {}\n", name, help, width = ARGZ_LEN)
}

/// The 11-row top-level table, byte-exact (`argz_print` with nothing set).
pub fn table_text() -> String {
    let mut out = String::new();
    for (name, help) in COMMANDS {
        out.push_str(&help_row(name, help));
    }
    out
}

/// The rows `argz_print(z)` emits over the top-level table with `set` filled
/// in: a row is dropped if it is set or if any set row shares its group
/// (`argz_is_available` `argz.c:68`). Every command row has group 1, so one
/// set command drops ALL rows.
fn outer_rows(set_command: Option<usize>) -> Vec<u8> {
    if set_command.is_some() {
        Vec::new()
    } else {
        table_text().into_bytes()
    }
}

/// The `Fatal: ` line `s_fatal` writes (`secret.c:291`): prefix, message
/// truncated to the buffer budget, newline — no extra formatting.
pub fn fatal_line(msg: &[u8]) -> Vec<u8> {
    let budget = FATAL_CAP - 7 - 1;
    let mut line = Vec::with_capacity(FATAL_CAP);
    line.extend_from_slice(b"Fatal: ");
    line.extend_from_slice(&msg[..msg.len().min(budget)]);
    line.push(b'\n');
    line
}

/// What `strtoull(s, &end, 0)` reports to `argz_ull` (`argz.c:144`).
enum Ull {
    /// Parsed `value`, `end` offset of the first unconverted byte.
    Value(u64, usize),
    /// `errno == ERANGE`.
    Range,
    /// No conversion (`end == start`).
    NoDigits,
}

/// `strtoull(s, &end, 0)` as glibc implements it (base 0: `0x`/`0X` hex
/// prefix only when followed by a hex digit, else leading `0` octal, else
/// decimal; optional `+`/`-` sign; leading `isspace` skipped; magnitude
/// overflow sets ERANGE and returns `ULLONG_MAX`; the negation wraps).
fn strtoull_base0(s: &[u8]) -> Ull {
    let mut i = 0;
    while i < s.len() && matches!(s[i], b' ' | b'\t' | b'\n' | 0x0b | 0x0c | b'\r') {
        i += 1;
    }
    let mut neg = false;
    if i < s.len() && (s[i] == b'+' || s[i] == b'-') {
        neg = s[i] == b'-';
        i += 1;
    }
    let mut base = 10u64;
    if i < s.len() && s[i] == b'0' {
        if i + 2 < s.len()
            && (s[i + 1] == b'x' || s[i + 1] == b'X')
            && s[i + 2].is_ascii_hexdigit()
        {
            base = 16;
            i += 2;
        } else {
            base = 8;
        }
    }
    let mut value: u64 = 0;
    let mut any = false;
    while i < s.len() {
        let d = match s[i] {
            b'0'..=b'9' => u64::from(s[i] - b'0'),
            b'a'..=b'f' => u64::from(s[i] - b'a') + 10,
            b'A'..=b'F' => u64::from(s[i] - b'A') + 10,
            _ => break,
        };
        if d >= base {
            break;
        }
        any = true;
        i += 1;
        match value.checked_mul(base).and_then(|v| v.checked_add(d)) {
            Some(v) => value = v,
            None => return Ull::Range,
        }
    }
    if !any {
        return Ull::NoDigits;
    }
    Ull::Value(if neg { value.wrapping_neg() } else { value }, i)
}

/// `argz_ull` for `init`'s `opslimit` (`secret.c:613`: `min = S_OPS_LIMIT`,
/// `value = S_OPS_LIMIT * 10`, base 0, no suffix handler). On success the
/// value and the number of slots consumed (`2`); otherwise the exact
/// upstream stderr message without its trailing newline, or the help value.
fn parse_ull(words: &[&[u8]]) -> UllResult {
    let name = words[0];
    let msg = |tail: &[u8]| {
        let mut m = b"Option ".to_vec();
        m.extend_from_slice(name);
        m.push(b' ');
        m.extend_from_slice(tail);
        m
    };
    if words.len() < 2 {
        return UllResult::Err(msg(b"requires a number"));
    }
    let raw = words[1];
    if raw == b"help" {
        // `argz_help_me` (argz.c:88) checks only the value slot; `argz_ull`
        // prints the clamped `z->value` and returns -1.
        return UllResult::Help(OPS_LIMIT_DEFAULT);
    }
    match strtoull_base0(raw) {
        Ull::Range => UllResult::Err(msg(b"is out of range")),
        Ull::NoDigits => UllResult::Err(msg(b"is not a valid number")),
        Ull::Value(value, end) => {
            if end < raw.len() {
                // `!z->suffix && end && *end` (argz.c:156).
                return UllResult::Err(msg(b"is badly suffixed"));
            }
            if value < OPS_LIMIT_MIN {
                return UllResult::Err(msg(
                    format!("must be a number greater than or equal to {OPS_LIMIT_MIN}").as_bytes(),
                ));
            }
            UllResult::Value(value, 2)
        }
    }
}

enum UllResult {
    /// Parsed value and slots consumed.
    Value(u64, usize),
    /// Help slot: print this value and a newline, exit [`EXIT_USAGE`].
    Help(u64),
    /// Error message (no trailing newline).
    Err(Vec<u8>),
}

/// What an inner `argz()` walk (`init`'s table or `version`'s NULL table)
/// reports back to the outer walk.
enum Inner {
    /// The command's operands were fully parsed (carrying `init`'s parsed
    /// opslimit; `version` reports 0 and ignores it).
    Parsed(u64),
    /// argz returned -2: these rows (the outer `argz_print(z)` always adds
    /// nothing here because the command that emitted -2 is set and occupies
    /// the whole group).
    Help(Vec<u8>),
    /// argz returned -1 with a message.
    Err(Vec<u8>),
    /// `argz_ull` help slot printed a value and returned -1.
    OptionValue(u64),
    /// argz returned a positive leftover count; the outer walk resumes at
    /// `words[0] + consumed`.
    Leftover(usize),
}

/// The inner `argz()` walk over `init`'s table (`opslimit` only).
///
/// `words[0]` is `init`. Returns [`Inner::Leftover`] with the number of words
/// consumed from `words` when unconsumed words remain (upstream returns the
/// leftover count and `s_init` forwards it, `secret.c:621`).
fn init_inner(words: &[&[u8]]) -> Inner {
    let mut ops_set = false;
    let mut value = OPS_LIMIT_DEFAULT;
    let mut i = 1;
    while i < words.len() {
        if words[i] == b"help" {
            // argz() L184-187: print the inner table (the `opslimit` row is
            // dropped once it is set) and return -2.
            let rows = if ops_set {
                Vec::new()
            } else {
                help_row(OPSLIMIT_NAME, OPSLIMIT_HELP).into_bytes()
            };
            return Inner::Help(rows);
        }
        if words[i] == OPSLIMIT_NAME.as_bytes() {
            if ops_set {
                // argz_is_available: the entry itself is set, `k == -1`.
                return Inner::Err(format!("Option {OPSLIMIT_NAME} is already set").into_bytes());
            }
            match parse_ull(&words[i..]) {
                UllResult::Value(v, used) => {
                    value = v;
                    ops_set = true;
                    i += used;
                }
                UllResult::Err(msg) => return Inner::Err(msg),
                UllResult::Help(v) => return Inner::OptionValue(v),
            }
            continue;
        }
        break;
    }
    if i < words.len() {
        return Inner::Leftover(i);
    }
    Inner::Parsed(value)
}

/// The inner `argz(argc, argv, NULL)` walk inside `s_version`
/// (`secret.c:853`): only the `help` slot exists; anything else is an
/// unconsumed word for the outer walk.
fn version_inner(words: &[&[u8]]) -> Inner {
    if words.len() > 1 && words[1] == b"help" {
        return Inner::Help(Vec::new());
    }
    if words.len() > 1 {
        return Inner::Leftover(1);
    }
    Inner::Parsed(0)
}

/// Per-command `help` / arity branches (the upstream guards, plan §4).
fn command_help(command: &'static str, argc: usize) -> HelpBranch {
    // `argc` is the command's own argument count including the command word
    // (`s_*` receive `argv + a`).
    let names = |list_on_two: bool| {
        if argc == 2 && list_on_two {
            NamesAction::List
        } else {
            NamesAction::None
        }
    };
    match command {
        // s_list L648: `argz_help || argc > 2`; usage only, never names.
        "list" => HelpBranch {
            command,
            usage: "Usage: list [NEEDLE]\n",
            names: NamesAction::None,
        },
        // s_show L719: `argz_help || argc != 2`; non-tty names at argc == 2.
        "show" => HelpBranch {
            command,
            usage: "Usage: show KEY\n",
            names: names(true),
        },
        "dump" => HelpBranch {
            command,
            usage: "Usage: dump KEY\n",
            names: names(true),
        },
        // s_do L683: `argz_help || (argc != 2 && (op || argc != 3))`.
        // new/set/renew only accept `KEY` (their `op` is truthy); the
        // non-tty names line needs `!(op & s_op_create)` — true for
        // renew/update only (secret.c:688).
        "new" => HelpBranch {
            command,
            usage: "Usage: new KEY \n",
            names: NamesAction::None,
        },
        "set" => HelpBranch {
            command,
            usage: "Usage: set KEY \n",
            names: NamesAction::None,
        },
        "renew" => HelpBranch {
            command,
            usage: "Usage: renew KEY \n",
            names: names(true),
        },
        "update" => HelpBranch {
            command,
            usage: "Usage: update KEY NEWKEY\n",
            names: names(true),
        },
        // s_pass L769: `argz_help || argc < 2`; usage only.
        "pass" => HelpBranch {
            command,
            usage: "Usage: pass KEY [SUBKEY...]\n",
            names: NamesAction::None,
        },
        // s_agent L792: `argz_help`; non-tty prints the literal `CMD`.
        "agent" => HelpBranch {
            command,
            usage: "Usage: agent CMD [ARG...]\n",
            names: if argc == 2 {
                NamesAction::Word("CMD")
            } else {
                NamesAction::None
            },
        },
        _ => unreachable!("no help branch for {command}"),
    }
}

fn unknown_word(word: &[u8]) -> Outcome<'static> {
    let mut msg = b"Option ".to_vec();
    msg.extend_from_slice(word);
    msg.extend_from_slice(b" is unknown");
    Outcome::Error(msg)
}

/// Build the `Command` for a matched table entry whose operands passed the
/// help/arity guards.
fn build_command<'a>(name: &str, rest: &'a [&'a [u8]]) -> Command<'a> {
    match name {
        "list" => Command::List {
            needle: rest.first().copied(),
        },
        "show" => Command::Show { key: rest[0] },
        "dump" => Command::Dump { key: rest[0] },
        "new" => Command::New { key: rest[0] },
        "set" => Command::Set { key: rest[0] },
        "renew" => Command::Renew { key: rest[0] },
        "update" => Command::Update {
            key: rest[0],
            new_key: rest.get(1).copied(),
        },
        "pass" => Command::Pass { keys: rest },
        "agent" => Command::Agent { cmd: rest },
        _ => unreachable!("no command body for {name}"),
    }
}

/// Parse `argv` exactly as upstream `argz_main(argc, argv, z)` plus the
/// `s_*` command guards would (argv[0] is the program name).
pub fn parse<'a>(argv: &'a [&'a [u8]]) -> Outcome<'a> {
    let argc = argv.len();
    if argc < 2 {
        return Outcome::BareTable;
    }
    // The outer `argz()` walk (`argz.c:210-231`) with its set state; every
    // top-level entry shares group 1, so at most one can be set. There is NO
    // global `argz_help` scan in upstream `main`: `help` is parser-level only
    // at the current walk position, so `show help` reaches `s_show`'s own
    // guard (per-command branch) while `bogus help` stops at `bogus`.
    let mut set_command: Option<usize> = None;
    let mut a = 1;
    while a < argc {
        if argv[a] == b"help" {
            // argz() L184-187.
            return Outcome::HelpRows(outer_rows(set_command));
        }
        let Some(idx) = COMMANDS.iter().position(|(n, _)| n.as_bytes() == argv[a]) else {
            // `if (!set) break;` — an unmatched word stops the walk.
            break;
        };
        if let Some(prev) = set_command {
            // argz() L195-203 (`argz_is_available` with `&k`).
            return Outcome::Error(if prev == idx {
                format!("Option {} is already set", COMMANDS[idx].0).into_bytes()
            } else {
                format!(
                    "Option {} is not compatible with {}",
                    COMMANDS[idx].0, COMMANDS[prev].0
                )
                .into_bytes()
            });
        }
        set_command = Some(idx);
        let name = COMMANDS[idx].0;
        let argc_c = argc - a;
        let rest = &argv[a + 1..];

        // Inner walks can consume part of their words and hand the rest back
        // to this walk; the guard commands consume everything or exit.
        if name == "init" || name == "version" {
            let inner = if name == "init" {
                init_inner(&argv[a..])
            } else {
                version_inner(&argv[a..])
            };
            match inner {
                Inner::Parsed(ops) => {
                    return if name == "init" {
                        Outcome::Command(Command::Init { ops_limit: ops })
                    } else {
                        Outcome::Command(Command::Version)
                    };
                }
                Inner::Help(rows) => return Outcome::HelpRows(rows),
                Inner::Err(msg) => return Outcome::Error(msg),
                Inner::OptionValue(v) => return Outcome::OptionValue(v),
                Inner::Leftover(consumed) => {
                    a += consumed;
                    continue;
                }
            }
        }

        // `argz_help(argc, argv)` scans every operand for a literal `help`.
        if rest.iter().any(|w| *w == b"help") {
            return Outcome::Help(command_help(name, argc_c));
        }
        let arity_ok = match name {
            "list" => argc_c <= 2,
            "show" | "dump" | "new" | "set" | "renew" => argc_c == 2,
            "update" => (2..=3).contains(&argc_c),
            "pass" => argc_c >= 2,
            "agent" => true,
            _ => unreachable!("no arity rule for {name}"),
        };
        if !arity_ok {
            return Outcome::Help(command_help(name, argc_c));
        }
        return Outcome::Command(build_command(name, rest));
    }
    if a < argc {
        // argz_main() L238: `argv[argc - ret]` is the word that stopped the
        // walk.
        return unknown_word(argv[a]);
    }
    unreachable!("the walk consumed every word without dispatching")
}

/// Run the parse → dispatch pipeline and return the process exit code.
pub fn run(argv: &[&[u8]], cli: &mut Cli<'_>, commands: &mut dyn Dispatch) -> u32 {
    match parse(argv) {
        Outcome::BareTable => {
            let _ = cli.stdout.write_all(table_text().as_bytes());
            EXIT_OK
        }
        Outcome::HelpRows(rows) => {
            let _ = cli.stdout.write_all(&rows);
            EXIT_HELP
        }
        Outcome::OptionValue(value) => {
            let _ = writeln!(cli.stdout, "{value}");
            EXIT_USAGE
        }
        Outcome::Error(msg) => {
            let _ = cli.stderr.write_all(&msg);
            let _ = cli.stderr.write_all(b"\n");
            EXIT_USAGE
        }
        Outcome::Command(command) => commands.execute(command),
        Outcome::Help(branch) => {
            if cli.stdout_is_tty {
                let _ = cli.stdout.write_all(branch.usage.as_bytes());
                return EXIT_USAGE;
            }
            match branch.names {
                NamesAction::None => EXIT_USAGE,
                NamesAction::Word(word) => {
                    let _ = cli.stdout.write_all(word.as_bytes());
                    let _ = cli.stdout.write_all(b"\n");
                    EXIT_USAGE
                }
                NamesAction::List => commands.complete_names(),
            }
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;

    fn argv_of(args: &[&'static str]) -> Vec<&'static [u8]> {
        let mut v: Vec<&'static [u8]> = vec![b"wsecret"];
        v.extend(args.iter().map(|s| s.as_bytes()));
        v
    }

    /// Compare a parsed command against an expected one in one scope (the
    /// parsed words borrow `argv`, which must outlive the comparison).
    fn assert_cmd(args: &[&'static str], want: Command<'static>) {
        let argv = argv_of(args);
        match parse(&argv) {
            Outcome::Command(got) => assert_eq!(got, want, "args: {args:?}"),
            other => panic!("expected a command for {args:?}, got {other:?}"),
        }
    }

    #[derive(Default)]
    struct Recording {
        calls: Vec<String>,
        names_code: u32,
        names_called: bool,
    }

    impl Dispatch for Recording {
        fn execute(&mut self, command: Command<'_>) -> u32 {
            self.calls.push(match &command {
                Command::Init { ops_limit } => format!("init {ops_limit}"),
                Command::Show { key } => format!("show {}", String::from_utf8_lossy(key)),
                other => format!("{other:?}"),
            });
            0
        }
        fn complete_names(&mut self) -> u32 {
            self.names_called = true;
            self.names_code
        }
    }

    fn run_words(args: &[&'static str], tty: bool) -> (u32, Vec<u8>, Vec<u8>, Recording) {
        let argv = argv_of(args);
        let (mut out, mut err) = (Vec::new(), Vec::new());
        let mut rec = Recording::default();
        let code = {
            let mut cli = Cli {
                stdout_is_tty: tty,
                stdout: &mut out,
                stderr: &mut err,
            };
            run(&argv, &mut cli, &mut rec)
        };
        (code, out, err, rec)
    }

    fn err_of(args: &[&'static str]) -> Vec<u8> {
        match parse(&argv_of(args)) {
            Outcome::Error(msg) => msg,
            other => panic!("expected an error for {args:?}, got {other:?}"),
        }
    }

    fn help_of(args: &[&'static str]) -> HelpBranch {
        match parse(&argv_of(args)) {
            Outcome::Help(b) => b,
            other => panic!("expected a help branch for {args:?}, got {other:?}"),
        }
    }

    // ---- exit codes ----------------------------------------------------

    #[test]
    fn exit_code_constants_match_upstream_mapping() {
        assert_eq!(EXIT_OK, 0);
        assert_eq!(EXIT_FATAL, 1);
        assert_eq!(EXIT_USAGE, 255);
        assert_eq!(EXIT_HELP, 254);
    }

    // ---- bare invocation and the top-level table ----------------------

    #[test]
    fn bare_invocation_prints_table_and_exits_zero() {
        assert_eq!(parse(&[b"wsecret"]), Outcome::BareTable);
        let (code, out, err, rec) = run_words(&[], false);
        assert_eq!(code, EXIT_OK);
        assert_eq!(String::from_utf8_lossy(&out), table_text());
        assert!(err.is_empty());
        assert!(rec.calls.is_empty());
    }

    #[test]
    fn table_rows_use_exact_upstream_format() {
        let table = table_text();
        assert!(table.starts_with("  init            Initialize secret\n"));
        assert!(table.contains("  update          Update an existing secret\n"));
        assert!(table.ends_with("  version         Show version\n"));
        assert_eq!(table.lines().count(), 11);
    }

    // ---- parser-level `help` (exit 254) --------------------------------

    #[test]
    fn root_help_lists_all_rows_and_exits_254() {
        for args in [&["help"][..], &["help", "extra"][..]] {
            let (code, out, err, _) = run_words(args, false);
            assert_eq!(code, EXIT_HELP, "args: {args:?}");
            assert_eq!(String::from_utf8_lossy(&out), table_text());
            assert!(err.is_empty());
        }
    }

    #[test]
    fn init_help_prints_the_opslimit_row_only() {
        // Inner argz_print prints the `opslimit` row; the outer argz_print
        // drops every row (init is set and the group is occupied).
        let (code, out, err, _) = run_words(&["init", "help"], false);
        assert_eq!(code, EXIT_HELP);
        assert_eq!(
            String::from_utf8_lossy(&out),
            "  opslimit        Number of iterations to perform\n"
        );
        assert!(err.is_empty());
        // Words after the inner `help` slot are never examined.
        let (_, out2, _, _) = run_words(&["init", "help", "extra"], false);
        assert_eq!(out2, out);
    }

    #[test]
    fn version_help_prints_nothing_and_exits_254() {
        // `argz_print(NULL)` prints nothing; the outer print is filtered.
        let (code, out, err, _) = run_words(&["version", "help"], false);
        assert_eq!(code, EXIT_HELP);
        assert!(out.is_empty());
        assert!(err.is_empty());
    }

    #[test]
    fn help_after_a_parsed_opslimit_prints_nothing() {
        // `init opslimit 50000 help`: the inner walk hits `help` with
        // opslimit already set → its row is filtered → no output at all.
        let (code, out, _, _) = run_words(&["init", "opslimit", "50000", "help"], false);
        assert_eq!(code, EXIT_HELP);
        assert!(out.is_empty());
    }

    #[test]
    fn leftover_bubbles_to_the_outer_walk() {
        // `init foo`: the inner walk stops at `foo` (s_init forwards the
        // positive leftover, secret.c:621), the outer walk resumes at `foo`,
        // matches no table entry, and `argz_main` reports the resume word.
        assert_eq!(err_of(&["init", "foo"]), b"Option foo is unknown");
        assert_eq!(
            err_of(&["init", "opslimit", "50000", "junk"]),
            b"Option junk is unknown"
        );
        assert_eq!(err_of(&["version", "x"]), b"Option x is unknown");
        // A `help` AFTER the resume word is never examined: the walk breaks
        // at the unmatched word first (`if (!set) break;`).
        for (args, tail) in [
            (&["init", "foo", "help"][..], "foo"),
            (&["init", "opslimit", "50000", "junk", "help"][..], "junk"),
            (&["version", "foo", "help"][..], "foo"),
        ] {
            assert_eq!(
                err_of(args),
                format!("Option {tail} is unknown").as_bytes(),
                "{args:?}"
            );
        }
    }

    // ---- command recognition ------------------------------------------

    #[test]
    fn all_eleven_commands_are_recognized() {
        assert_cmd(&["init"], Command::Init {
            ops_limit: OPS_LIMIT_DEFAULT,
        });
        assert_cmd(&["list"], Command::List { needle: None });
        assert_cmd(&["show", "k"], Command::Show { key: b"k" });
        assert_cmd(&["dump", "k"], Command::Dump { key: b"k" });
        assert_cmd(&["new", "k"], Command::New { key: b"k" });
        assert_cmd(&["set", "k"], Command::Set { key: b"k" });
        assert_cmd(&["renew", "k"], Command::Renew { key: b"k" });
        assert_cmd(&["update", "k", "n"], Command::Update {
            key: b"k",
            new_key: Some(b"n"),
        });
        assert_cmd(&["pass", "k"], Command::Pass { keys: &[b"k"] });
        assert_cmd(&["agent"], Command::Agent { cmd: &[] });
        assert_cmd(&["version"], Command::Version);
    }

    #[test]
    fn list_needle_is_the_second_word() {
        assert_cmd(&["list", "NEEDLE"], Command::List {
            needle: Some(b"NEEDLE"),
        });
    }

    #[test]
    fn update_key_only_and_rename_forms_are_distinguished() {
        // `update KEY` alone: empty input exits 0 with no write.
        assert_cmd(&["update", "old"], Command::Update {
            key: b"old",
            new_key: None,
        });
        // `update KEY NEWKEY`: empty input keeps the old value.
        assert_cmd(&["update", "old", "new"], Command::Update {
            key: b"old",
            new_key: Some(b"new"),
        });
    }

    #[test]
    fn pass_chains_every_operand_including_key() {
        assert_cmd(&["pass", "k", "a", "b"], Command::Pass {
            keys: &[b"k", b"a", b"b"],
        });
    }

    #[test]
    fn agent_takes_cmd_and_args_with_shell_fallback() {
        assert_cmd(&["agent", "cmd", "-x"], Command::Agent {
            cmd: &[b"cmd", b"-x"],
        });
        assert_cmd(&["agent"], Command::Agent { cmd: &[] });
    }

    // ---- opslimit (argz_ull) ------------------------------------------

    #[test]
    fn opslimit_accepts_valid_values() {
        for (text, want) in [
            ("10000", 10_000u64),
            ("50000", 50_000),
            ("0x2710", 10_000),
            ("036411", 15_625),
            ("18446744073709551615", u64::MAX), // quirk: accepted, no max
        ] {
            assert_cmd(
                &["init", "opslimit", text],
                Command::Init { ops_limit: want },
            );
        }
    }

    #[test]
    fn opslimit_below_minimum_is_rejected() {
        for text in ["5000", "9999", "0", "0x"] {
            // `0x` is "badly suffixed", not below-min: assert the exact
            // message per input below instead of a shared one.
            let want: &[u8] = if text == "0x" {
                b"Option opslimit is badly suffixed"
            } else {
                b"Option opslimit must be a number greater than or equal to 10000"
            };
            assert_eq!(err_of(&["init", "opslimit", text]), want, "{text}");
            let (code, _, err, _) = run_words(&["init", "opslimit", text], false);
            assert_eq!(code, EXIT_USAGE);
            let mut want_nl = want.to_vec();
            want_nl.push(b'\n');
            assert_eq!(err, want_nl, "{text}");
        }
    }

    #[test]
    fn opslimit_non_numeric_is_rejected() {
        for text in ["banana", "", "+", "-x"] {
            assert_eq!(
                err_of(&["init", "opslimit", text]),
                b"Option opslimit is not a valid number",
                "{text:?}"
            );
        }
    }

    #[test]
    fn opslimit_suffixed_value_is_rejected() {
        for text in ["5000k", "0xZZ", "50000 "] {
            assert_eq!(
                err_of(&["init", "opslimit", text]),
                b"Option opslimit is badly suffixed",
                "{text:?}"
            );
        }
    }

    #[test]
    fn opslimit_overflow_reports_out_of_range() {
        assert_eq!(
            err_of(&["init", "opslimit", "99999999999999999999999"]),
            b"Option opslimit is out of range"
        );
    }

    #[test]
    fn opslimit_missing_value_reports_requires_a_number() {
        assert_eq!(
            err_of(&["init", "opslimit"]),
            b"Option opslimit requires a number"
        );
    }

    #[test]
    fn opslimit_help_prints_default_value_and_exits_255() {
        let (code, out, err, _) = run_words(&["init", "opslimit", "help"], false);
        assert_eq!(code, EXIT_USAGE);
        assert_eq!(String::from_utf8_lossy(&out), "100000\n");
        assert!(err.is_empty());
    }

    #[test]
    fn opslimit_twice_is_already_set() {
        assert_eq!(
            err_of(&["init", "opslimit", "20000", "opslimit", "30000"]),
            b"Option opslimit is already set"
        );
    }

    // ---- unknown words and table conflicts ----------------------------

    #[test]
    fn unknown_first_word_reports_option_unknown() {
        assert_eq!(err_of(&["bogus"]), b"Option bogus is unknown");
        let (code, out, err, _) = run_words(&["bogus"], true);
        assert_eq!(code, EXIT_USAGE);
        assert!(out.is_empty());
        // No `Fatal: ` prefix on argz errors (argz_main, argz.c:239).
        assert_eq!(err, b"Option bogus is unknown\n");
    }

    #[test]
    fn unknown_first_word_swallows_a_later_help() {
        // The walk examines only its current position: an unmatched first
        // word breaks the walk (argz.c `if (!set) break;`) BEFORE any later
        // `help` is ever tested — so `bogus help` is the unknown word, not
        // parser-level help (upstream-faithful quirk).
        assert_eq!(err_of(&["bogus", "help"]), b"Option bogus is unknown");
    }

    #[test]
    fn table_conflicts_are_reported_like_argz_is_available() {
        // A leftover word that matches the already-set command:
        assert_eq!(
            err_of(&["init", "init"]),
            b"Option init is already set"
        );
        // A leftover word matching another command in the same group:
        assert_eq!(
            err_of(&["init", "version"]),
            b"Option version is not compatible with init"
        );
        assert_eq!(
            err_of(&["init", "opslimit", "50000", "version"]),
            b"Option version is not compatible with init"
        );
    }

    // ---- help matrix (plan §4) ----------------------------------------

    #[test]
    fn help_word_anywhere_in_operands_triggers_the_branch() {
        for args in [
            &["list", "x", "help"][..],
            &["show", "help", "x"][..],
            &["pass", "k", "help"][..],
            &["agent", "cmd", "help"][..],
            &["update", "k", "help"][..], // NOT a rename to `help`
            &["new", "k", "help"][..],
        ] {
            assert!(
                matches!(parse(&argv_of(args)), Outcome::Help(_)),
                "args: {args:?}"
            );
        }
    }

    #[test]
    fn arity_violations_are_help_branches_not_unknown_words() {
        for args in [
            &["show"][..],
            &["show", "k", "x"][..],
            &["new", "k", "n"][..],
            &["set", "k", "x"][..],
            &["renew", "k", "n"][..],
            &["update", "k", "n", "x"][..],
            &["pass"][..],
            &["list", "a", "b"][..],
        ] {
            assert!(
                matches!(parse(&argv_of(args)), Outcome::Help(_)),
                "args: {args:?}"
            );
        }
    }

    #[test]
    fn usage_lines_match_upstream_bytes() {
        assert_eq!(help_of(&["list", "help"]).usage, "Usage: list [NEEDLE]\n");
        assert_eq!(help_of(&["show", "help"]).usage, "Usage: show KEY\n");
        assert_eq!(help_of(&["dump", "help"]).usage, "Usage: dump KEY\n");
        // Trailing space from `Usage: %s KEY %s\n` with an empty tail.
        assert_eq!(help_of(&["new", "help"]).usage, "Usage: new KEY \n");
        assert_eq!(help_of(&["set", "help"]).usage, "Usage: set KEY \n");
        assert_eq!(help_of(&["renew", "help"]).usage, "Usage: renew KEY \n");
        assert_eq!(help_of(&["update", "help"]).usage, "Usage: update KEY NEWKEY\n");
        assert_eq!(help_of(&["pass", "help"]).usage, "Usage: pass KEY [SUBKEY...]\n");
        assert_eq!(help_of(&["agent", "help"]).usage, "Usage: agent CMD [ARG...]\n");
    }

    #[test]
    fn names_actions_follow_the_upstream_condition() {
        // Names only for `… help` (argc == 2) of the generate/rename family.
        for args in [
            &["show", "help"][..],
            &["dump", "help"][..],
            &["renew", "help"][..],
            &["update", "help"][..],
        ] {
            assert_eq!(help_of(args).names, NamesAction::List, "{args:?}");
        }
        // new/set never list; multi-word help forms never list.
        for args in [
            &["new", "help"][..],
            &["set", "help"][..],
            &["list", "help"][..],
            &["pass", "help"][..],
            &["show", "help", "x"][..],
            &["agent", "cmd", "help"][..],
        ] {
            assert_eq!(help_of(args).names, NamesAction::None, "{args:?}");
        }
        assert_eq!(help_of(&["agent", "help"]).names, NamesAction::Word("CMD"));
    }

    #[test]
    fn run_non_tty_list_names_delegates_to_dispatch() {
        for code in [EXIT_OK, EXIT_USAGE, EXIT_FATAL] {
            let mut rec = Recording {
                names_code: code,
                ..Default::default()
            };
            let argv = argv_of(&["show", "help"]);
            let (mut out, mut err) = (Vec::new(), Vec::new());
            let rc = {
                let mut cli = Cli {
                    stdout_is_tty: false,
                    stdout: &mut out,
                    stderr: &mut err,
                };
                run(&argv, &mut cli, &mut rec)
            };
            assert!(rec.names_called);
            assert_eq!(rc, code);
            assert!(out.is_empty());
            assert!(err.is_empty());
        }
    }

    #[test]
    fn run_non_tty_word_and_none_branches() {
        let (code, out, err, rec) = run_words(&["agent", "help"], false);
        assert_eq!(code, EXIT_USAGE);
        assert_eq!(String::from_utf8_lossy(&out), "CMD\n");
        assert!(err.is_empty());
        assert!(!rec.names_called);

        let (code, out, err, rec) = run_words(&["new", "help"], false);
        assert_eq!(code, EXIT_USAGE);
        assert!(out.is_empty());
        assert!(err.is_empty());
        assert!(!rec.names_called);
    }

    #[test]
    fn run_tty_prints_usage_line_and_255() {
        let (code, out, err, _) = run_words(&["new", "help"], true);
        assert_eq!(code, EXIT_USAGE);
        assert_eq!(String::from_utf8_lossy(&out), "Usage: new KEY \n");
        assert!(err.is_empty());
    }

    // ---- dispatch wiring ----------------------------------------------

    #[test]
    fn run_dispatches_parsed_commands() {
        let (code, _, _, rec) = run_words(&["show", "mykey"], false);
        assert_eq!(code, EXIT_OK);
        assert_eq!(rec.calls, ["show mykey"]);

        let (_, _, _, rec) = run_words(&["init", "opslimit", "12345"], false);
        assert_eq!(rec.calls, ["init 12345"]);
    }

    #[test]
    fn run_error_writes_stderr_and_255() {
        let (code, out, err, rec) = run_words(&["nonesuch"], true);
        assert_eq!(code, EXIT_USAGE);
        assert!(out.is_empty());
        assert_eq!(err, b"Option nonesuch is unknown\n");
        assert!(rec.calls.is_empty());
    }

    // ---- fatal line formatting ---------------------------------------

    #[test]
    fn fatal_line_matches_s_fatal_shape() {
        assert_eq!(
            fatal_line(b"Store opslimit is below the minimum of 10000"),
            b"Fatal: Store opslimit is below the minimum of 10000\n"
        );
        // Truncation to the 256-byte buffer: 7 prefix + 248 message + newline.
        let line = fatal_line(&vec![b'x'; 400]);
        assert_eq!(line.len(), 256);
        assert_eq!(&line[..7], b"Fatal: ");
        assert_eq!(line[7..255].iter().filter(|&&b| b == b'x').count(), 248);
        assert_eq!(line[255], b'\n');
    }
}

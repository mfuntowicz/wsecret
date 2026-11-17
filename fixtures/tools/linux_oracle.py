#!/usr/bin/env python3
"""Linux-side upstream oracle helper (runs inside WSL).

Drives the PINNED upstream `secret` binary (angt/secret @
e98103def4e062a6f9a8fa5e7693abe15f20817a, vendored at `wsecret-src/`) over a
pty so that the upstream `/dev/tty` passphrase prompts work while stdin
carries byte-exact secret values and stdout carries byte-exact results.

Subcommands (argv[1]):
  generate      build `upstream-linux-origin.secret` following the EXACT
                upstream command sequence recorded in
                `fixtures/stores/manifest.json` (plan §7.2 record set), then
                self-check every record with the upstream tool itself and
                print the store bytes as base64 on stdout (everything else
                goes to stderr)
  show NAME     run `secret show NAME` on the generated store and print the
                exact stdout bytes as hex
  dump NAME     same, with `secret dump NAME`

This tool is test infrastructure only (provenance record for the fixture it
generates: the command sequence below IS the manifest's `upstream_commands`
sequence, executed for real on Linux). The upstream binary and a copy of the
store persist in ~/.cache/wsecret-oracle/ (WSL home).
"""

import base64
import hashlib
import os
import select
import shutil
import subprocess
import sys
import time

REPO = "/mnt/f/Workspace/wsecret"
CACHE = os.path.expanduser("~/.cache/wsecret-oracle")
UP_SRC = os.path.join(CACHE, "src")
SECRET = os.path.join(CACHE, "secret")
STORE = os.path.join(CACHE, "upstream-linux-origin.secret")

PASS_A = b"correct horse battery staple"
PASS_B = b"second"

MYKEY = bytes(range(32))
TOTP_KEY = b"12345678901234567890"
TOTP32 = b"GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ\n"
B1 = b"beta one\n"
B2 = b"beta two\n"
B3 = bytes(range(256))

# The manifest's `upstream_commands.linux_origin` sequence, as Python:
# (argv, stdin value, passphrase, needs new-partition confirmation)
FIXTURE_STEPS = [
    (["init", "opslimit", "100000"], None, None, False),
    (["set", "test"], b"hello\n", PASS_A, True),
    (["set", "mykey"], MYKEY, PASS_A, False),
    (["set", "test/totp"], TOTP_KEY, PASS_A, False),
    (["set", "test/totp32"], TOTP32, PASS_A, False),
    (["set", "test-old"], b"old\n", PASS_A, False),
    (["update", "test-old", "DELETED:test"], b"", PASS_A, False),
    (["set", "b1"], B1, PASS_B, True),
    (["set", "b2"], B2, PASS_B, False),
    (["set", "b3"], B3, PASS_B, False),
]

LIST_A = b"test\nmykey\ntest/totp\ntest/totp32\nDELETED:test\n"
LIST_B = b"b1\nb2\nb3\n"

PROMPT_PASS = b"Passphrase: "
PROMPT_CONFIRM = b"confirm: "


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def retry_fs(fn, what, attempts=4):
    for i in range(attempts):
        try:
            return fn()
        except OSError as e:
            log(f"fs retry {i + 1}/{attempts} for {what}: {e}")
            time.sleep(1.5)
    raise RuntimeError(f"filesystem operation failed after {attempts} attempts: {what}")


def ensure_upstream():
    if os.path.isfile(SECRET) and os.access(SECRET, os.X_OK):
        return
    log("building upstream secret ...")

    def stage():
        os.makedirs(os.path.join(UP_SRC, "argz"), exist_ok=True)
        os.makedirs(os.path.join(UP_SRC, "libhydrogen"), exist_ok=True)
        shutil.copyfile(os.path.join(REPO, "wsecret-src", "secret.c"),
                        os.path.join(UP_SRC, "secret.c"))
        for f in ("argz.c", "argz.h"):
            shutil.copyfile(os.path.join(REPO, "wsecret-src", f),
                            os.path.join(UP_SRC, "argz", f))
        for f in ("hydrogen.c", "hydrogen.h"):
            shutil.copyfile(os.path.join(REPO, "crates", "libhydrogen-sys", "vendor", f),
                            os.path.join(UP_SRC, "libhydrogen", f))
        impl_src = os.path.join(REPO, "crates", "libhydrogen-sys", "vendor", "impl")
        impl_dst = os.path.join(UP_SRC, "libhydrogen", "impl")
        if os.path.isdir(impl_dst):
            shutil.rmtree(impl_dst)
        shutil.copytree(impl_src, impl_dst)

    retry_fs(stage, "stage upstream sources")
    subprocess.run(
        ["gcc", "-O2", "-o", SECRET, os.path.join(UP_SRC, "secret.c")],
        check=True, cwd=UP_SRC,
    )
    log(f"built {SECRET}")


def ensure_store():
    if os.path.isfile(STORE):
        return
    src = os.path.join(REPO, "fixtures", "stores", "upstream-linux-origin.secret")
    retry_fs(lambda: shutil.copyfile(src, STORE), "copy fixture store")
    log(f"copied fixture store to {STORE}")


def run_upstream(args, value=None, answers=(), capture=None):
    """Runs `secret ARGS` under a pty.

    `value` (when not None) is the raw stdin byte stream (s_read path);
    `answers` are the /dev/tty prompt replies (passphrase / confirmation);
    `capture` is a path receiving the exact stdout bytes (s_write(1)).

    Returns (tty_output, exit_status).
    """
    value_file = None
    if value is not None:
        value_file = os.path.join(CACHE, "value.bin")
        with open(value_file, "wb") as f:
            f.write(value)

    import pty
    pid, fd = pty.fork()
    if pid == 0:
        # child: controlling tty is the pty slave (fds 0..2)
        try:
            if value_file is not None:
                v = os.open(value_file, os.O_RDONLY)
                os.dup2(v, 0)
                os.close(v)
            if capture is not None:
                o = os.open(capture, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.dup2(o, 1)
                os.close(o)
            env = {"SECRET_STORE": STORE, "PATH": "/usr/bin:/bin"}
            os.execve(SECRET, ["secret"] + args, env)
        except Exception as e:  # pragma: no cover
            print(f"exec failed: {e}", file=sys.stderr)
            os._exit(127)

    # parent: drive the pty
    tty_out = bytearray()
    answered = 0
    status = None
    deadline = time.time() + 120
    while time.time() < deadline:
        r, _, _ = select.select([fd], [], [], 0.5)
        if r:
            try:
                chunk = os.read(fd, 65536)
            except OSError:
                chunk = b""
            if not chunk:
                break
            tty_out += chunk
        # answer any prompt that has appeared
        while answered < len(answers):
            seen = tty_out.count(PROMPT_PASS) + tty_out.count(PROMPT_CONFIRM)
            if seen <= answered:
                break
            os.write(fd, answers[answered] + b"\n")
            answered += 1
        wpid, st = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            status = st
            # drain the tail
            while True:
                r, _, _ = select.select([fd], [], [], 0.2)
                if not r:
                    break
                try:
                    chunk = os.read(fd, 65536)
                except OSError:
                    chunk = b""
                if not chunk:
                    break
                tty_out += chunk
            break
    if status is None:
        _, status = os.waitpid(pid, 0)
    try:
        os.close(fd)
    except OSError:
        pass
    code = os.waitstatus_to_exitcode(status) if hasattr(os, "waitstatus_to_exitcode") else status
    return bytes(tty_out), code


def read_capture(path):
    with open(path, "rb") as f:
        return f.read()


def cmd_generate():
    ensure_upstream()
    if os.path.exists(STORE):
        os.remove(STORE)
    capture = os.path.join(CACHE, "capture.bin")

    for args, value, pw, confirm in FIXTURE_STEPS:
        if args[0] == "init":
            out, code = run_upstream(args)
        else:
            answers = (pw, pw) if confirm else (pw,)
            out, code = run_upstream(args, value=value, answers=answers)
        assert code == 0, f"{args} failed: {code}\n{out!r}"
        log(f"{' '.join(args)} ok")

    # Self-check with the upstream tool itself (the compatibility oracle):
    for args, pw, expected in (
        (["list"], PASS_A, LIST_A),
        (["list"], PASS_B, LIST_B),
    ):
        out, code = run_upstream(args, answers=(pw,), capture=capture)
        got = read_capture(capture)
        assert code == 0 and got == expected, (
            f"{args} + {pw!r} mismatch: code={code} got={got!r} want={expected!r}"
        )
        log(f"self-check list + {pw!r} ok")

    checks = [
        (["dump", "test"], PASS_A, b"hello\n"),
        (["dump", "mykey"], PASS_A, MYKEY),
        (["dump", "test/totp"], PASS_A, TOTP_KEY),
        (["dump", "test/totp32"], PASS_A, TOTP32),
        (["dump", "DELETED:test"], PASS_A, b"old\n"),
        (["dump", "b1"], PASS_B, B1),
        (["dump", "b2"], PASS_B, B2),
        (["dump", "b3"], PASS_B, B3),
    ]
    for args, pw, expected in checks:
        out, code = run_upstream(args, answers=(pw,), capture=capture)
        got = read_capture(capture)
        assert code == 0 and got == expected, (
            f"{args} mismatch: code={code} got={got!r} want={expected!r}\n{out!r}"
        )
        log(f"self-check {' '.join(args)} ok")

    with open(STORE, "rb") as f:
        blob = f.read()
    assert len(blob) == 512 * 9, f"unexpected store length {len(blob)}"
    log(f"store sha256 {hashlib.sha256(blob).hexdigest()}")
    log(f"store size {len(blob)}")
    print(base64.b64encode(blob).decode())


def cmd_show(dump, name):
    ensure_upstream()
    ensure_store()
    capture = os.path.join(CACHE, "capture.bin")
    pw = PASS_B if name in ("b1", "b2", "b3") else PASS_A
    args = ["dump" if dump else "show", name]
    out, code = run_upstream(args, answers=(pw,), capture=capture)
    if code != 0:
        log(f"upstream {args} failed: {code}\n{out!r}")
        sys.exit(1)
    got = read_capture(capture)
    print(got.hex())


def main():
    if len(sys.argv) < 2:
        log("usage: linux_oracle.py generate|show NAME|dump NAME")
        sys.exit(2)
    sub = sys.argv[1]
    if sub == "generate":
        cmd_generate()
    elif sub == "show" and len(sys.argv) == 3:
        cmd_show(False, sys.argv[2])
    elif sub == "dump" and len(sys.argv) == 3:
        cmd_show(True, sys.argv[2])
    else:
        log(f"unknown subcommand {sub!r}")
        sys.exit(2)


if __name__ == "__main__":
    main()

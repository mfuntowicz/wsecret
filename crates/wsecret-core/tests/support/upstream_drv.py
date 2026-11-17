#!/usr/bin/env python3
"""WSL-side driver for the PINNED upstream `secret` binary (E4/E5/E7 rows).

Runs `angt/secret` @ e98103def4e062a6f9a8fa5e7693abe15f20817a (built on demand
from the repo's pinned sources, cached at ~/.cache/wsecret-oracle/secret —
the same cache `fixtures/tools/linux_oracle.py` uses) against an ARBITRARY
store path, over a pty so upstream's /dev/tty passphrase prompts work while
stdin carries byte-exact secret values.

Subcommands (argv[1]):
  dump STORE NAME_HEX PASS_HEX               -> stdout = hex of `secret dump
                                                NAME` bytes; exit 1 when
                                                upstream reports it missing
  set STORE NAME_HEX PASS_HEX VALUE_HEX      -> stdout = upstream exit code
  update STORE NAME_HEX PASS_HEX VALUE_HEX   -> stdout = upstream exit code

STORE is a Windows path (F:\\...\\x.secret) or an /mnt/... path.
Everything else goes to stderr. Test infrastructure only.
"""

import hashlib
import os
import select
import shutil
import subprocess
import sys
import time

REPO = os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))))
CACHE = os.path.expanduser("~/.cache/wsecret-oracle")
UP_SRC = os.path.join(CACHE, "src")
SECRET = os.path.join(CACHE, "secret")

PROMPT_PASS = b"Passphrase: "
PROMPT_CONFIRM = b"confirm: "


def log(msg):
    print(msg, file=sys.stderr, flush=True)


def to_wsl_path(store):
    if store.startswith("/mnt/"):
        return store
    drive = store[0].lower()
    rest = store[2:].replace("\\", "/")
    return f"/mnt/{drive}{rest}"


def ensure_upstream():
    """Builds the pinned upstream binary once (same recipe/cache as
    fixtures/tools/linux_oracle.py's ensure_upstream)."""
    if os.path.isfile(SECRET) and os.access(SECRET, os.X_OK):
        return
    log("building pinned upstream secret ...")
    os.makedirs(os.path.join(UP_SRC, "argz"), exist_ok=True)
    os.makedirs(os.path.join(UP_SRC, "libhydrogen"), exist_ok=True)
    shutil.copyfile(os.path.join(REPO, "fixtures", "upstream", "secret.c"),
                    os.path.join(UP_SRC, "secret.c"))
    for f in ("argz.c", "argz.h"):
        shutil.copyfile(os.path.join(REPO, "fixtures", "upstream", f),
                        os.path.join(UP_SRC, "argz", f))
    for f in ("hydrogen.c", "hydrogen.h"):
        shutil.copyfile(os.path.join(REPO, "crates", "libhydrogen-sys", "vendor", f),
                        os.path.join(UP_SRC, "libhydrogen", f))
    impl_src = os.path.join(REPO, "crates", "libhydrogen-sys", "vendor", "impl")
    impl_dst = os.path.join(UP_SRC, "libhydrogen", "impl")
    if os.path.isdir(impl_dst):
        shutil.rmtree(impl_dst)
    shutil.copytree(impl_src, impl_dst)
    subprocess.run(
        ["gcc", "-O2", "-o", SECRET, os.path.join(UP_SRC, "secret.c")],
        check=True, cwd=UP_SRC,
    )
    log(f"built {SECRET} (sha256 {hashlib.sha256(open(SECRET, 'rb').read()).hexdigest()[:16]}…)")


def run_upstream(store, args, value=None, answers=(), capture=None):
    """Runs `secret ARGS` with SECRET_STORE=store under a pty.

    `value` (when not None) is the raw stdin byte stream; `answers` are the
    /dev/tty prompt replies; `capture` is a path receiving stdout bytes.
    Returns (tty_output, exit_status).
    """
    value_file = None
    if value is not None:
        value_file = os.path.join(CACHE, f"value-{os.getpid()}.bin")
        with open(value_file, "wb") as f:
            f.write(value)

    import pty
    pid, fd = pty.fork()
    if pid == 0:
        try:
            if value_file is not None:
                v = os.open(value_file, os.O_RDONLY)
                os.dup2(v, 0)
                os.close(v)
            if capture is not None:
                o = os.open(capture, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
                os.dup2(o, 1)
                os.close(o)
            env = {"SECRET_STORE": store, "PATH": "/usr/bin:/bin"}
            os.execve(SECRET, ["secret"] + args, env)
        except Exception as e:  # pragma: no cover
            print(f"exec failed: {e}", file=sys.stderr)
            os._exit(127)

    tty_out = bytearray()
    answered = 0
    status = None
    deadline = time.time() + 60
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
        while answered < len(answers):
            seen = tty_out.count(PROMPT_PASS) + tty_out.count(PROMPT_CONFIRM)
            if seen <= answered:
                break
            os.write(fd, answers[answered] + b"\n")
            answered += 1
        wpid, st = os.waitpid(pid, os.WNOHANG)
        if wpid == pid:
            status = st
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


def cmd_dump(store, name, pw):
    ensure_upstream()
    capture = os.path.join(CACHE, f"drv-capture-{os.getpid()}.bin")
    out, code = run_upstream(store, ["dump", name], answers=(pw, pw), capture=capture)
    if code != 0:
        log(f"upstream dump {name!r} -> exit {code}: {out!r}")
        sys.exit(1)
    with open(capture, "rb") as f:
        data = f.read()
    os.remove(capture)
    print(data.hex())


def cmd_write(store, verb, name, pw, value):
    ensure_upstream()
    out, code = run_upstream(store, [verb, name], value=value, answers=(pw, pw))
    if code != 0:
        log(f"upstream {verb} {name!r} -> exit {code}: {out!r}")
    print(code)


def unhex(s):
    return bytes(int(s[i:i + 2], 16) for i in range(0, len(s), 2))


def main():
    if len(sys.argv) < 2:
        log("usage: upstream_drv.py dump|set|update STORE NAME_HEX PASS_HEX [VALUE_HEX]")
        sys.exit(2)
    sub = sys.argv[1]
    store = to_wsl_path(sys.argv[2])
    name = unhex(sys.argv[3])
    pw = unhex(sys.argv[4])
    if sub == "dump" and len(sys.argv) == 5:
        cmd_dump(store, name.decode(), pw)
    elif sub in ("set", "update") and len(sys.argv) == 6:
        cmd_write(store, sub, name.decode(), pw, unhex(sys.argv[5]))
    else:
        log(f"bad invocation {sys.argv!r}")
        sys.exit(2)


if __name__ == "__main__":
    main()

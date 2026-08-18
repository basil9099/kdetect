#!/usr/bin/env python3
"""Build a curated /proc fixture tree for kdetect's tests.

A lab utility, not part of kdetect. Run as root on the lab VM:

    sudo .venv/bin/python tools/capture_fixture.py tests/fixtures/proc-trees/clean-vm-6.1.0-10

Fixtures are curated, not dumped. A full /proc is ~1000 files and tests nothing
that seven chosen processes do not. Each entry below exists to cover one case:

    1      systemd        ordinary process, readable exe
    2      kthreadd       kernel thread: empty cmdline, exe -> ENOENT
    <kw>   kworker/...    second kernel thread, different flags value
    <sl>   sleep          ordinary user-owned process
    <pc>   ev (il) proc   parens in comm - the parse_stat trap, end to end
    812    sshd           synthetic: readable stat, exe -> EACCES
    4171   -              synthetic: listed but unreadable, simulating a
                          process that exited mid-scan

Symlinks are stored as <name>.readlink text files because Windows cannot
create real symlinks without elevated privileges, and this tree is read on
the Windows host.
"""

from __future__ import annotations

import json
import os
import shutil
import subprocess
import sys
import time
from pathlib import Path

FILES = ("stat", "cmdline", "status")
PAREN_BINARY = "/tmp/ev (il) proc"


def read_proc(pid: int, name: str) -> str | None:
    try:
        with open(f"/proc/{pid}/{name}", encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError:
        return None


def first_kworker() -> int | None:
    for entry in sorted(int(n) for n in os.listdir("/proc") if n.isdigit()):
        comm = read_proc(entry, "comm")
        if comm and comm.startswith("kworker/"):
            return entry
    return None


def capture(dest: Path, pid: int, errors: dict[str, str]) -> None:
    """Copy one real process's files, recording any failure in `errors`."""
    pid_dir = dest / "proc" / str(pid)
    pid_dir.mkdir(parents=True, exist_ok=True)

    for name in FILES:
        text = read_proc(pid, name)
        if text is None:
            errors[f"{pid}/{name}"] = "ENOENT"
        else:
            (pid_dir / name).write_text(text, encoding="utf-8")

    try:
        (pid_dir / "exe.readlink").write_text(
            os.readlink(f"/proc/{pid}/exe") + "\n", encoding="utf-8"
        )
    except OSError as exc:
        # ENOENT for a kernel thread, EACCES if we lacked permission.
        errors[f"{pid}/exe"] = "ENOENT" if exc.errno == 2 else "EACCES"


def synthesise_denied(dest: Path, errors: dict[str, str]) -> None:
    """PID 812: readable stat/cmdline/status, but exe denied.

    Built by renumbering PID 1's files rather than capturing a real sshd, so
    the fixture is reproducible on any host. This is the common real case for
    an unprivileged reader: you may read another user's stat, but not
    readlink its exe.
    """
    pid_dir = dest / "proc" / "812"
    pid_dir.mkdir(parents=True, exist_ok=True)

    stat = read_proc(1, "stat") or ""
    tail = stat[stat.rfind(")") + 1:]
    (pid_dir / "stat").write_text(f"812 (sshd){tail}", encoding="utf-8")
    (pid_dir / "cmdline").write_text("/usr/sbin/sshd\x00-D\x00", encoding="utf-8")
    (pid_dir / "status").write_text(read_proc(1, "status") or "", encoding="utf-8")

    # No exe.readlink file: the read is recorded as denied instead.
    errors["812/exe"] = "EACCES"


def synthesise_vanished(dest: Path, errors: dict[str, str]) -> None:
    """PID 4171: appears in list_pids(), but every read fails.

    Simulates a process that exited between the directory listing and the
    read. An empty directory is exactly what that looks like from outside.
    git does not track empty directories, hence the .gitkeep.
    """
    pid_dir = dest / "proc" / "4171"
    pid_dir.mkdir(parents=True, exist_ok=True)
    (pid_dir / ".gitkeep").write_text("", encoding="utf-8")
    errors["4171/stat"] = "ENOENT"


def main(argv: list[str]) -> int:
    if len(argv) != 2:
        print(__doc__)
        return 2

    dest = Path(argv[1])
    if dest.exists():
        shutil.rmtree(dest)
    (dest / "proc").mkdir(parents=True)

    errors: dict[str, str] = {}

    # Spawn the two processes we need to exist.
    shutil.copy("/bin/sleep", PAREN_BINARY)
    sleeper = subprocess.Popen(["/bin/sleep", "60"])
    parened = subprocess.Popen([PAREN_BINARY, "60"])
    time.sleep(0.5)

    try:
        roster = [1, 2, first_kworker(), sleeper.pid, parened.pid]
        for pid in roster:
            if pid is None:
                print("warning: no kworker found, skipping", file=sys.stderr)
                continue
            capture(dest, pid, errors)
    finally:
        sleeper.terminate()
        parened.terminate()
        os.unlink(PAREN_BINARY)

    synthesise_denied(dest, errors)
    synthesise_vanished(dest, errors)

    (dest / "_errors.json").write_text(
        json.dumps(errors, indent=2, sort_keys=True) + "\n", encoding="utf-8"
    )

    print(f"wrote {dest}")
    for path in sorted(dest.rglob("*")):
        if path.is_file():
            print(f"  {path.relative_to(dest)}  ({path.stat().st_size} bytes)")
    print("\n_errors.json:")
    print((dest / "_errors.json").read_text())
    return 0


if __name__ == "__main__":
    raise SystemExit(main(sys.argv))

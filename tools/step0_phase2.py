#!/usr/bin/env python3
"""Collect phase 2 Step 0 evidence: hidden-process and hidden-module channels.

A lab utility, not part of kdetect. Run as root on the lab VM:

    sudo python3 tools/step0_phase2.py --label clean
    sudo python3 tools/step0_phase2.py --label infected --hidden-pid 1234

Writes numbered evidence files to docs/step0-phase2/<label>/. Every file
carries the commands that produced it, so a reader can reproduce it by hand.

Phase 1's schema was derived from docs/step0/. Phase 2's differ is derived from
this. The two questions it has to answer:

  processes - which channels see a process, and how far do they disagree on a
              CLEAN machine? Every difference here is a false positive waiting
              to happen.
  modules   - /proc/modules, /sys/module and /proc/kallsyms all read the same
              kernel `modules` list. A rootkit that unlinks itself from that
              list hides from all three at once. Is there an independent
              channel that still sees it?

This script only reads. The one exception is --race-load, which forks a few
hundred short-lived children of its own to make mid-capture races observable.
It loads no modules and changes no settings; loading Diamorphine is a manual
step in the runbook (docs/step0-phase2/README.md).
"""

from __future__ import annotations

import argparse
import os
import subprocess
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

#: Where the tracefs might be. Debian 12 mounts the first; older setups the
#: second. Recorded as missing rather than mounted if neither is present -
#: this script does not change the machine's state.
TRACING_DIRS = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")

#: Kernel taint bits, from Documentation/admin-guide/tainted-kernels.rst.
#: Bits 12 (out-of-tree) and 13 (unsigned) are the ones an LKM rootkit sets
#: merely by being loaded, and it cannot clear them by unlinking itself from
#: the module list. That asymmetry is a candidate detection channel.
TAINT_BITS = {
    0: "G/P  proprietary module loaded",
    1: "F    module force loaded",
    2: "S    SMP kernel on unsupported CPU",
    3: "R    module force unloaded",
    4: "M    machine check exception",
    5: "B    bad page referenced",
    6: "U    taint requested by userspace",
    7: "D    kernel died recently (oops/BUG)",
    8: "A    ACPI table overridden",
    9: "W    warning issued",
    10: "C   staging driver loaded",
    11: "I   workaround for firmware bug",
    12: "O   OUT-OF-TREE MODULE LOADED",
    13: "E   UNSIGNED MODULE LOADED",
    14: "L   soft lockup",
    15: "K   live patched",
    16: "X   auxiliary taint",
    17: "T   built with struct randomisation",
    18: "N   test module loaded",
}


# ---------------------------------------------------------------------------
# Small helpers
# ---------------------------------------------------------------------------


def read_file(path: str) -> str | None:
    """Read a file, returning None rather than raising.

    Evidence collection must never abort halfway because one path was
    root-only or absent - "could not read this" is itself a finding, and the
    caller records which errno it got.
    """
    try:
        with open(path, encoding="utf-8", errors="replace") as fh:
            return fh.read()
    except OSError as exc:
        return f"<<UNREADABLE: {exc.strerror} (errno {exc.errno})>>"


def run(cmd: list[str]) -> str:
    """Run a command and capture both streams as text."""
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as exc:
        return f"<<FAILED: {exc}>>"
    return proc.stdout + proc.stderr


def proc_tgid(task_id: int) -> int | None:
    """Read Tgid straight out of /proc/<id>/status.

    This is the third channel described in the design discussion. It does not
    go through readdir(), so a rootkit that hides entries by filtering
    getdents64 - which is what Diamorphine does - does not hide from it. It
    also tells a thread apart from a process: a thread's Tgid is its leader's
    pid, not its own.
    """
    text = read_file(f"/proc/{task_id}/status")
    if text is None or text.startswith("<<"):
        return None
    for line in text.splitlines():
        if line.startswith("Tgid:"):
            return int(line.split()[1])
    return None


def listing_pids() -> list[int]:
    """Channel 1 (LOW): the numeric entries of /proc, via readdir.

    This is what ps, top and phase 1's collector see, and it is the channel a
    getdents-hooking rootkit filters.
    """
    return sorted(int(n) for n in os.listdir("/proc") if n.isdigit())


def task_ids(pids: list[int]) -> dict[int, int]:
    """Every task id under the given pids, mapped to its leader.

    /proc's top level lists thread group leaders only. The other threads exist
    as /proc/<tgid>/task/<tid>, and - crucially - also as /proc/<tid>/, which
    readdir never shows.
    """
    tasks: dict[int, int] = {}
    for pid in pids:
        try:
            for name in os.listdir(f"/proc/{pid}/task"):
                if name.isdigit():
                    tasks[int(name)] = pid
        except OSError:
            continue  # process exited while we walked it - normal
    return tasks


def sweep(pid_max: int) -> tuple[list[int], float]:
    """Channel 2 (MEDIUM): kill(id, 0) across the whole pid space.

    Returns the ids that responded, and how long it took.

    Signal 0 performs the permission and existence checks and delivers
    nothing. Three outcomes matter:

        returns cleanly  -> the id exists and we may signal it
        EPERM            -> the id EXISTS, we are not allowed to signal it
        ESRCH            -> no such id

    EPERM counts as existence. Treating it as absence would blind an
    unprivileged sweep to every process it does not own.
    """
    alive: list[int] = []
    started = time.monotonic()
    for task_id in range(1, pid_max + 1):
        try:
            os.kill(task_id, 0)
        except ProcessLookupError:
            continue
        except PermissionError:
            alive.append(task_id)
        except OSError:
            continue
        else:
            alive.append(task_id)
    return alive, time.monotonic() - started


def start_noise(seconds: int) -> subprocess.Popen | None:
    """Spawn a helper that churns short-lived processes for `seconds`.

    The noise has to run CONCURRENTLY with the sweep or it demonstrates
    nothing: a process that starts and exits before the capture begins is
    invisible to every channel and races with nothing. So this returns a
    running helper that the caller stops afterwards, rather than forking a
    batch up front.

    start_new_session puts the helper in its own process group, so one
    killpg at the end takes the subshells with it instead of leaving
    orphaned sleeps behind.
    """
    if seconds <= 0:
        return None
    script = (
        f"end=$(( $(date +%s) + {seconds} )); "
        "while [ $(date +%s) -lt $end ]; do "
        "  for i in 1 2 3 4 5; do (sleep 0.05) & done; "
        "  sleep 0.05; "
        "done; wait"
    )
    return subprocess.Popen(
        ["sh", "-c", script],
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        start_new_session=True,
    )


def stop_noise(proc: subprocess.Popen | None) -> None:
    """Tear down the noise helper and its whole process group."""
    if proc is None:
        return
    try:
        os.killpg(os.getpgid(proc.pid), 15)
    except OSError:
        pass
    try:
        proc.wait(timeout=10)
    except subprocess.TimeoutExpired:
        proc.kill()


# ---------------------------------------------------------------------------
# Evidence files
# ---------------------------------------------------------------------------


class Evidence:
    """Accumulates one numbered evidence file at a time."""

    def __init__(self, outdir: Path, label: str, header: str) -> None:
        self.outdir = outdir
        self.label = label
        self.header = header
        self.lines: list[str] = []
        self.name: str | None = None

    def open(self, name: str, title: str, commands: str) -> None:
        self.name = name
        self.lines = [
            f"# {title}",
            "",
            self.header,
            f"label: {self.label}",
            "",
            "Reproduce by hand:",
            *(f"    {line}" for line in commands.strip().splitlines()),
            "",
            "-" * 70,
            "",
        ]

    def say(self, text: str = "") -> None:
        self.lines.append(text)

    def close(self) -> None:
        assert self.name is not None
        path = self.outdir / self.name
        path.write_text("\n".join(self.lines) + "\n", encoding="utf-8")
        print(f"  wrote {path}")
        self.name = None


def file_00_host(ev: Evidence, pid_max: int) -> None:
    ev.open(
        "00-host-facts.txt",
        "Host facts and kernel taint state",
        "uname -a; cat /proc/sys/kernel/pid_max; cat /proc/sys/kernel/tainted",
    )
    ev.say(run(["uname", "-a"]).rstrip())
    ev.say(f"pid_max          : {pid_max}")
    ev.say(f"euid             : {os.geteuid()}")
    ev.say(f"boot_id          : {read_file('/proc/sys/kernel/random/boot_id').strip()}")
    ev.say(f"kptr_restrict    : {read_file('/proc/sys/kernel/kptr_restrict').strip()}")
    ev.say(
        f"perf_event_paranoid: {read_file('/proc/sys/kernel/perf_event_paranoid').strip()}"
    )
    ev.say()

    raw = read_file("/proc/sys/kernel/tainted").strip()
    ev.say(f"tainted (raw)    : {raw}")
    try:
        value = int(raw)
    except ValueError:
        value = 0
    if value == 0:
        ev.say("  no taint bits set")
    for bit, meaning in TAINT_BITS.items():
        if value & (1 << bit):
            ev.say(f"  bit {bit:>2} set: {meaning}")
    unknown = value >> (max(TAINT_BITS) + 1)
    if unknown:
        ev.say(f"  bits above {max(TAINT_BITS)} also set (raw >> shift = {unknown})")
    ev.say()
    ev.say("dmesg lines mentioning modules or taint:")
    dmesg = run(["dmesg"])
    for line in dmesg.splitlines():
        low = line.lower()
        if "taint" in low or "module verification" in low or "loading out-of-tree" in low:
            ev.say(f"  {line}")
    ev.close()


def file_01_tasks(ev: Evidence) -> None:
    ev.open(
        "01-listing-vs-tasks.txt",
        "False-positive class #1: /proc lists processes, the sweep finds tasks",
        "ls /proc | grep '^[0-9]' | wc -l\n"
        "awk '/^Threads:/{s+=$2} END{print s}' /proc/[0-9]*/status\n"
        "ls -d /proc/<tid>   # a thread id absent from the listing above",
    )
    pids = listing_pids()
    tasks = task_ids(pids)
    unlisted = sorted(set(tasks) - set(pids))

    ev.say(f"/proc top-level numeric entries (thread group leaders): {len(pids)}")
    ev.say(f"task ids under /proc/<pid>/task/                      : {len(tasks)}")
    ev.say(f"task ids NOT present in the top-level listing         : {len(unlisted)}")
    ev.say()
    ev.say("Those unlisted task ids are ordinary threads of visible processes.")
    ev.say("A sweep compared naively against the /proc listing reports every one")
    ev.say("of them as a hidden process. On this machine that is the false-")
    ev.say("positive count above, on an idle system, with nothing malicious loaded.")
    ev.say()
    ev.say("Proof that an unlisted task id is still directly reachable:")
    for task_id in unlisted[:5]:
        leader = tasks[task_id]
        directly = proc_tgid(task_id)
        comm = read_file(f"/proc/{task_id}/comm")
        comm = comm.strip() if comm else "?"
        ev.say(
            f"  tid {task_id:>7}  in listing: no   "
            f"/proc/{task_id}/status readable: {'yes' if directly else 'no'}   "
            f"Tgid: {directly}  (leader {leader})  comm: {comm}"
        )
    ev.say()
    ev.say("Reading Tgid directly is what separates 'a thread' from 'a hidden")
    ev.say("process': a thread's Tgid names a leader that IS in the listing.")
    ev.close()


def file_02_sweep(ev: Evidence, pid_max: int) -> None:
    ev.open(
        "02-sweep-vs-listing.txt",
        "Channel 2: full pid-space sweep with kill(id, 0)",
        "python3 -c 'import os\\nfor p in range(1, PID_MAX+1):\\n"
        "    try: os.kill(p, 0)\\n    except OSError: pass'",
    )
    pids_before = listing_pids()
    alive, seconds = sweep(pid_max)
    pids_after = listing_pids()
    tasks = task_ids(pids_after)

    ev.say(f"pid_max swept          : {pid_max}")
    ev.say(f"sweep duration         : {seconds:.2f} s")
    ev.say(f"ids that responded     : {len(alive)}")
    ev.say(f"/proc listing before   : {len(pids_before)}")
    ev.say(f"/proc listing after    : {len(pids_after)}")
    ev.say(f"known task ids after   : {len(tasks)}")
    ev.say()

    sweep_set = set(alive)
    only_sweep = sorted(sweep_set - set(pids_after))
    only_listing = sorted(set(pids_after) - sweep_set)

    ev.say(f"in sweep, not in listing : {len(only_sweep)}")
    ev.say(f"in listing, not in sweep : {len(only_listing)}")
    ev.say()
    ev.say("Classifying every id the sweep saw but the listing did not:")

    threads = hidden = gone = 0
    unexplained: list[int] = []
    for task_id in only_sweep:
        tgid = proc_tgid(task_id)
        if tgid is None:
            gone += 1  # exited between the sweep and this read
        elif tgid in pids_after or tgid in tasks:
            threads += 1
        else:
            hidden += 1
            unexplained.append(task_id)

    ev.say(f"  thread of a visible process (Tgid is listed): {threads}")
    ev.say(f"  vanished before we could resolve it         : {gone}")
    ev.say(f"  UNEXPLAINED - candidate hidden process      : {hidden}")
    ev.say()
    for task_id in unexplained[:20]:
        comm = read_file(f"/proc/{task_id}/comm")
        cmdline = read_file(f"/proc/{task_id}/cmdline")
        ev.say(f"  id {task_id}")
        ev.say(f"    comm    : {comm.strip() if comm else '?'}")
        ev.say(f"    cmdline : {cmdline.replace(chr(0), ' ').strip() if cmdline else '?'}")
        ev.say(f"    exe     : {run(['readlink', f'/proc/{task_id}/exe']).strip()}")
    if not unexplained:
        ev.say("  (none)")
    ev.close()


def file_03_race(ev: Evidence, pid_max: int, noise: int) -> None:
    ev.open(
        "03-sandwich-race.txt",
        "Why the capture runs procfs -> sweep -> procfs",
        "read /proc listing (pass A); sweep the pid space; read it again (pass B)",
    )
    ev.say("A sweep takes seconds; a /proc walk takes milliseconds. Processes")
    ev.say("start and exit in between, so the two views disagree on a clean")
    ev.say("machine for reasons that have nothing to do with hiding.")
    ev.say()
    ev.say("The sandwich distinguishes them: an id the sweep saw that is absent")
    ev.say("from BOTH walks, and still resolvable, cannot be explained by timing.")
    ev.say()

    for run_label, noisy in (("idle", False), ("under process churn", True)):
        helper = start_noise(noise) if noisy else None
        pass_a = set(listing_pids())
        alive, seconds = sweep(pid_max)
        pass_b = set(listing_pids())
        stop_noise(helper)
        sweep_set = set(alive)

        missing_from_both = sweep_set - pass_a - pass_b
        missing_from_a_only = (sweep_set & pass_b) - pass_a
        missing_from_b_only = (sweep_set & pass_a) - pass_b
        in_a_not_sweep = pass_a - sweep_set
        in_b_not_sweep = pass_b - sweep_set

        ev.say(f"--- {run_label} ---")
        ev.say(f"  sweep duration          : {seconds:.2f} s")
        ev.say(f"  walk A / walk B sizes   : {len(pass_a)} / {len(pass_b)}")
        ev.say(f"  sweep saw               : {len(sweep_set)}")
        ev.say(f"  absent from A only      : {len(missing_from_a_only)}  (started mid-capture)")
        ev.say(f"  absent from B only      : {len(missing_from_b_only)}  (exited mid-capture)")
        ev.say(f"  absent from BOTH walks  : {len(missing_from_both)}  <- threads + anything hidden")
        ev.say(f"  in walk A, sweep missed : {len(in_a_not_sweep)}")
        ev.say(f"  in walk B, sweep missed : {len(in_b_not_sweep)}")

        resolved = [t for t in missing_from_both if proc_tgid(t) is not None]
        leaders = {proc_tgid(t) for t in resolved}
        ev.say(f"  of those, still resolvable: {len(resolved)}")
        ev.say(
            f"  whose Tgid is a listed pid: "
            f"{len([l for l in leaders if l in pass_b])} distinct leaders"
        )
        ev.say()
    ev.close()


def file_04_direct(ev: Evidence, hidden_pid: int | None) -> None:
    ev.open(
        "04-direct-access-channel.txt",
        "Channel 3: reading /proc/<pid> without listing /proc",
        "ls /proc | grep '^<pid>$'   # readdir - hookable\n"
        "stat /proc/<pid>            # direct path lookup - different code path\n"
        "kill -0 <pid>               # existence via the signal path",
    )
    ev.say("Diamorphine hides processes by filtering the results of getdents64.")
    ev.say("A direct path lookup does not go through getdents64 at all, so the")
    ev.say("same kernel that refuses to list a pid will happily answer questions")
    ev.say("about it. Three channels, one filesystem.")
    ev.say()

    targets: list[tuple[str, int]] = [("self", os.getpid())]
    if hidden_pid is not None:
        targets.append(("--hidden-pid", hidden_pid))

    for why, pid in targets:
        listed = pid in listing_pids()
        try:
            os.kill(pid, 0)
            signalled = "yes"
        except OSError as exc:
            signalled = f"no (errno {exc.errno})"
        status_readable = proc_tgid(pid) is not None
        comm = read_file(f"/proc/{pid}/comm")

        ev.say(f"pid {pid}  ({why})")
        ev.say(f"  appears in readdir(/proc) : {'yes' if listed else 'NO'}")
        ev.say(f"  kill(pid, 0) succeeds     : {signalled}")
        ev.say(f"  /proc/<pid>/status readable: {'yes' if status_readable else 'no'}")
        ev.say(f"  comm                      : {comm.strip() if comm else '?'}")
        ev.say(f"  exe                       : {run(['readlink', f'/proc/{pid}/exe']).strip()}")
        ev.say(f"  starttime (stat field 22) : {(read_file(f'/proc/{pid}/stat') or '').split(') ')[-1].split()[19] if status_readable else '?'}")
        ev.say()
    ev.close()


def _proc_modules() -> dict[str, str]:
    """Parse /proc/modules into name -> raw line."""
    text = read_file("/proc/modules") or ""
    out: dict[str, str] = {}
    for line in text.splitlines():
        parts = line.split()
        if parts:
            out[parts[0]] = line
    return out


def file_05_module_lists(ev: Evidence) -> None:
    ev.open(
        "05-module-three-lists.txt",
        "Three module lists that share one source",
        "cat /proc/modules | awk '{print $1}' | sort\n"
        "ls /sys/module | sort\n"
        "awk '{print $4}' /proc/kallsyms | grep '^\\[' | sort -u",
    )
    from_proc = _proc_modules()
    try:
        from_sysfs = set(os.listdir("/sys/module"))
    except OSError as exc:
        from_sysfs = set()
        ev.say(f"<<could not list /sys/module: {exc}>>")

    kallsyms = read_file("/proc/kallsyms") or ""
    from_kallsyms: set[str] = set()
    zeroed = 0
    for line in kallsyms.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[3].startswith("[") and parts[3].endswith("]"):
            from_kallsyms.add(parts[3][1:-1])
        if parts and parts[0] == "0000000000000000":
            zeroed += 1

    ev.say(f"/proc/modules entries   : {len(from_proc)}")
    ev.say(f"/sys/module entries     : {len(from_sysfs)}")
    ev.say(f"modules named in kallsyms: {len(from_kallsyms)}")
    ev.say(f"kallsyms symbols with a zeroed address: {zeroed}")
    ev.say("  (a non-zero count means this capture cannot do address work - L4)")
    ev.say()
    ev.say("In /sys/module but NOT in /proc/modules:")
    ev.say("  Expected on a clean system: built-in code registers a sysfs")
    ev.say("  directory for its parameters without ever being a loadable module.")
    ev.say("  This is false-positive class #2 for the module view.")
    for name in sorted(from_sysfs - set(from_proc)):
        loaded_marker = Path(f"/sys/module/{name}/initstate").exists()
        ev.say(f"    {name:<32} has initstate: {loaded_marker}")
    ev.say()
    ev.say("In /proc/modules but NOT in /sys/module:")
    for name in sorted(set(from_proc) - from_sysfs):
        ev.say(f"    {name}")
    ev.say("    (none)" if not (set(from_proc) - from_sysfs) else "")
    ev.say()
    ev.say("Named in kallsyms but absent from /proc/modules:")
    ev.say("  False-positive class #3: the fourth column of /proc/kallsyms is")
    ev.say("  not exclusively module names. JIT-compiled BPF programs are tagged")
    ev.say("  [bpf], and ftrace trampolines get tags of their own. A differ that")
    ev.say("  treats every bracketed tag as a module invents one on a clean host.")
    for name in sorted(from_kallsyms - set(from_proc)):
        ev.say(f"    {name}")
    if not from_kallsyms - set(from_proc):
        ev.say("    (none)")
    ev.close()


def file_06_ftrace(ev: Evidence) -> None:
    ev.open(
        "06-ftrace-module-tags.txt",
        "Candidate independent channel: ftrace's function records",
        "cat /sys/kernel/tracing/available_filter_functions | grep '\\[' | "
        "sed 's/.*\\[//;s/\\]//' | sort | uniq -c",
    )
    ev.say("ftrace records a module's traceable functions when the module is")
    ev.say("LOADED, and drops them when it is UNLOADED. Unlinking a module from")
    ev.say("the kernel's `modules` list is neither, so if these records survive")
    ev.say("hiding, this is a channel that does not share a source with")
    ev.say("/proc/modules. That is the whole question this file answers.")
    ev.say()

    tracing = next((d for d in TRACING_DIRS if Path(d).is_dir()), None)
    if tracing is None:
        ev.say(f"<<no tracefs found at any of {TRACING_DIRS}>>")
        ev.say("Without tracefs this channel is unavailable on this host.")
        ev.close()
        return

    ev.say(f"tracefs: {tracing}")
    text = read_file(f"{tracing}/available_filter_functions")
    if text is None or text.startswith("<<"):
        ev.say(str(text))
        ev.close()
        return

    counts: dict[str, int] = {}
    untagged = 0
    for line in text.splitlines():
        if line.endswith("]") and "[" in line:
            name = line[line.rindex("[") + 1 : -1]
            counts[name] = counts.get(name, 0) + 1
        else:
            untagged += 1

    ev.say(f"total records            : {untagged + sum(counts.values())}")
    ev.say(f"untagged (core kernel)   : {untagged}")
    ev.say(f"distinct modules tagged  : {len(counts)}")
    ev.say()
    from_proc = set(_proc_modules())
    ev.say("Per module: traceable function count, and whether /proc/modules")
    ev.say("still admits the module exists.")
    for name, count in sorted(counts.items()):
        mark = "" if name in from_proc else "   <-- NOT IN /proc/modules"
        ev.say(f"  {name:<32} {count:>6}{mark}")
    ev.say()
    ev.say("Modules in /proc/modules with no ftrace records:")
    for name in sorted(from_proc - set(counts)):
        ev.say(f"  {name}")
    ev.close()


def file_07_vmalloc(ev: Evidence) -> None:
    ev.open(
        "07-vmallocinfo-modules.txt",
        "Candidate independent channel: module memory in /proc/vmallocinfo",
        "grep -E 'module_alloc|load_module' /proc/vmallocinfo",
    )
    ev.say("Module code lives in a vmalloc region allocated at load time. The")
    ev.say("allocation is released on unload, not on unlinking, so a hidden")
    ev.say("module should still own a region here. Unlike ftrace this needs no")
    ev.say("tracing subsystem, but it gives an address range rather than a name.")
    ev.say()

    text = read_file("/proc/vmallocinfo")
    if text is None or text.startswith("<<"):
        ev.say(str(text))
        ev.say("This file is root-only (mode 0400). Re-run under sudo.")
        ev.close()
        return

    module_lines = [
        line for line in text.splitlines() if "module_alloc" in line or "load_module" in line
    ]
    ev.say(f"total vmallocinfo lines   : {len(text.splitlines())}")
    ev.say(f"module-allocation lines   : {len(module_lines)}")
    ev.say()
    for line in module_lines:
        ev.say(f"  {line}")
    ev.say()
    ev.say("Base addresses claimed by /proc/modules, for correlation:")
    for name, line in sorted(_proc_modules().items()):
        parts = line.split()
        addr = parts[5] if len(parts) > 5 else "?"
        ev.say(f"  {name:<32} {addr}")
    ev.close()


def file_08_taint(ev: Evidence) -> None:
    ev.open(
        "08-taint-accounting.txt",
        "Candidate independent channel: taint set, but nothing to blame",
        "cat /proc/sys/kernel/tainted\n"
        "cat /proc/modules            # taint flags in the trailing (...)\n"
        "cat /sys/module/*/taint",
    )
    ev.say("Loading an out-of-tree unsigned module sets taint bits 12 and 13.")
    ev.say("Unlinking the module from the list does not clear them. So a kernel")
    ev.say("that admits to an out-of-tree module while no listed module carries")
    ev.say("an (O) or (E) marker is accounting for something it will not name.")
    ev.say("This costs two file reads and needs no tracing and no addresses.")
    ev.say()

    raw = (read_file("/proc/sys/kernel/tainted") or "0").strip()
    try:
        value = int(raw)
    except ValueError:
        value = 0
    ev.say(f"/proc/sys/kernel/tainted : {raw}")
    ev.say(f"  bit 12 (out-of-tree)   : {'SET' if value & (1 << 12) else 'clear'}")
    ev.say(f"  bit 13 (unsigned)      : {'SET' if value & (1 << 13) else 'clear'}")
    ev.say()
    ev.say("Per-module taint, from the trailing parenthesis of /proc/modules:")
    tainted_modules = 0
    for name, line in sorted(_proc_modules().items()):
        marker = line.rsplit(" ", 1)[-1] if line.endswith(")") else ""
        if marker:
            tainted_modules += 1
            ev.say(f"  {name:<32} {marker}")
    if tainted_modules == 0:
        ev.say("  (no listed module carries a taint marker)")
    ev.say()
    ev.say("Per-module taint, from sysfs:")
    try:
        for name in sorted(os.listdir("/sys/module")):
            taint = read_file(f"/sys/module/{name}/taint")
            if taint and not taint.startswith("<<") and taint.strip():
                ev.say(f"  /sys/module/{name}/taint = {taint.strip()}")
    except OSError as exc:
        ev.say(f"  <<{exc}>>")
    ev.say()
    ev.say(f"CONCLUSION FOR THIS RUN: taint bits 12/13 "
           f"{'SET' if value & (3 << 12) else 'clear'}, "
           f"listed modules carrying a taint marker: {tainted_modules}")
    ev.close()


# ---------------------------------------------------------------------------
# Entry point
# ---------------------------------------------------------------------------


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument(
        "--label",
        required=True,
        help="clean or infected-<rootkit>; names the output directory",
    )
    parser.add_argument(
        "--hidden-pid",
        type=int,
        default=None,
        help="a pid you have asked the rootkit to hide, for file 04",
    )
    parser.add_argument(
        "--race-load",
        type=int,
        default=8,
        help="seconds of process churn to run during the second sandwich run; "
        "must outlast the sweep (~4 s here) or it races with nothing",
    )
    parser.add_argument(
        "--outdir",
        default="docs/step0-phase2",
        help="where to write evidence (default: docs/step0-phase2)",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        print(
            "warning: not running as root. /proc/vmallocinfo, the tracefs and "
            "kallsyms addresses will be unreadable, and the module channels are "
            "exactly what this pass exists to test.",
            file=sys.stderr,
        )

    outdir = Path(args.outdir) / args.label
    outdir.mkdir(parents=True, exist_ok=True)

    pid_max = int((read_file("/proc/sys/kernel/pid_max") or "32768").strip())
    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")
    header = (
        f"captured: {stamp}\n"
        f"kernel:   {os.uname().release}\n"
        f"euid:     {os.geteuid()}"
    )

    ev = Evidence(outdir, args.label, header)
    print(f"writing evidence to {outdir}/")
    file_00_host(ev, pid_max)
    file_01_tasks(ev)
    file_02_sweep(ev, pid_max)
    file_03_race(ev, pid_max, args.race_load)
    file_04_direct(ev, args.hidden_pid)
    file_05_module_lists(ev)
    file_06_ftrace(ev)
    file_07_vmalloc(ev)
    file_08_taint(ev)
    print("done")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

# Limitations

A running log, kept from day one. Every entry is something observed while
building kdetect that constrains what it can honestly claim to detect.

Deliverable 8 of the original brief asks for exactly this document.

## Lab environment

**L1 — The baseline has unverifiable provenance.** The phase 1 lab VM is a
prebuilt LinuxVMImages.com Debian 12 image with publicly documented default
credentials (`debian`/`debian`, root `linuxvmimages.com`) and passwordless sudo.
A rootkit detector rests on knowing what uncompromised looks like; a third-party
image cannot supply that. Acceptable for phase 1, which performs no detection.
Rebuild from Debian netinst before phase 2.

**L2 — The VM holds a GitHub deploy key with write access.** It must be rotated
or removed before any live rootkit runs on this machine.

**L3 — Passwordless sudo is enabled.** Any local code execution is trivially
root, which makes this host a weaker test of privilege boundaries than a
default install would be.

## Observation limits

**L4 — Kernel address visibility is gated by two sysctls, not one.** On this host
`kptr_restrict=0` but `perf_event_paranoid=3`, and unprivileged reads of
`/proc/kallsyms` and `/proc/modules` still return zeroed addresses.
`kallsyms_show_value()` only honours `kptr_restrict=0` when
`perf_event_paranoid <= 1`; otherwise it requires `CAP_SYSLOG`. **kdetect needs
root, or `CAP_SYSLOG`, for any address-based detection.**
Evidence: `docs/step0/09-kallsyms-user-vs-root.txt`

**L5 — `comm` truncates at 15 characters.** It cannot identify longer process
names, and two differently-named processes can share a `comm`.

**L6 — The observer appears in the observation.** kdetect's own process and
threads are in every capture, as are the VS Code Remote-SSH `node` processes.
Detection logic must expect to find itself.

**L7 — The invocation environment is recorded in the output.** The same collector
run interactively versus over SSH reports different `tty_nr` and `tpgid` for its
own shell — `34816` (a pty) versus `0`/`-1` (none). Captures are not directly
comparable unless invoked the same way.

**L8 — A process can vanish mid-scan.** This is normal Linux behaviour, counted
under `stats.vanished` and deliberately left at `status: OK`. It does mean a
capture is never a true instant — it is a sweep taken over tens of milliseconds,
and a process that starts and exits inside that window may be missed entirely.

## Data fidelity

**L9 — `/proc/[pid]/cmdline` is raw bytes and may not be valid UTF-8.** Phase 1
decodes with `errors="replace"`, so a process with non-UTF-8 arguments is
recorded lossily. A rootkit could use this deliberately to make a command line
unreproducible.

**L10 — Empty command-line arguments are dropped.** `parse_cmdline` filters all
empty strings to remove the trailing NUL terminator, which also discards
legitimately empty `argv` entries. A process invoked with an empty argument
records fewer arguments than it was given.

**L11 — `comm`, `cmdline` and `exe` are forgeable to different degrees.**
`argv[0]` is freely rewritable by the process; `comm` requires
`prctl(PR_SET_NAME)` and truncates; `exe` is a kernel-maintained symlink and
cannot be forged from userspace. kdetect stores all three precisely because
their disagreement is the signal.
Evidence: `docs/step0/02-comm-vs-cmdline.txt`

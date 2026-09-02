# Limitations

A running log, kept from day one. Every entry is something observed while
building kdetect that constrains what it can honestly claim to detect.

Deliverable 8 of the original brief asks for exactly this document.

## Lab environment

**L1 — The baseline has unverifiable provenance.** ~~Current~~ **RESOLVED
2026-08-19**: rebuilt from a signature-verified Debian 12.12.0 netinst. See the
verification record in [`lab-setup.md`](lab-setup.md). Retained below for the
history.

 The phase 1 lab VM is a
prebuilt LinuxVMImages.com Debian 12 image with publicly documented default
credentials (`debian`/`debian`, root `linuxvmimages.com`) and passwordless sudo.
A rootkit detector rests on knowing what uncompromised looks like; a third-party
image cannot supply that. Acceptable for phase 1, which performs no detection.
Rebuild from Debian netinst before phase 2.

**L2 — The VM holds a GitHub deploy key with write access.** **RESOLVED
2026-08-19**: the old key was deleted and a new repository-scoped key generated
on the rebuilt VM. It still grants write access to one private repository, so
the working procedure in [`threat-model.md`](threat-model.md) applies — push
from `clean-baseline`, never from an infected snapshot.

**L3 — Passwordless sudo is enabled.** **RESOLVED 2026-08-19**: the rebuilt VM
requires a password for `sudo`, as a stock Debian install does. Note the
practical consequence — automated capture runs cannot silently escalate, so
root captures are an explicit, interactive act.

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

**L12 — Unprivileged captures cannot distinguish "no exe" from "denied exe".**
As root, a kernel thread's `exe` gives `ENOENT` and `partial` stays empty. As an
ordinary user the same read gives `EACCES`, so every kernel thread is recorded
`partial: ["exe"]`. Measured on this host: 152 processes, 131 with partial reads
and status `PARTIAL` as uid 1000, versus 154 processes, 0 partial and status `OK`
as root. Kernel-thread identity survives regardless, because `PF_KTHREAD` lives
in world-readable `stat` field 9 - which is why that field is stored raw rather
than derived from `exe` and `cmdline`.

**L13 — Captures contain whatever processes put in their command lines.**
`/proc/[pid]/cmdline` is recorded verbatim (P1), so any credential passed as an
argument is in the snapshot: database passwords, API keys, bearer tokens. The
phase 1 fixture had to have a VS Code Remote-SSH session token redacted before
it could be committed. This is a property of `/proc`, not of kdetect, and it
means **a snapshot must be treated as sensitive by default**. Phase 4's
reporting will need a redaction pass before any report is shareable.

**L14 — A baseline inherits its installer's choices, not only its packages.**
Comparing the vendor image against the rebuilt VM: the old one carried five
device-mapper devices (LVM) contributing ten `kdmflush`/`jbd2` kernel threads,
an AHCI controller VMware attaches by default contributing about sixty
`scsi_eh_`/`scsi_tmf_` threads, and a `xenbus_probe` thread on a VMware host.
None were malicious; none were chosen; all would have been noise to explain
away in phase 2. Measured totals: 154 processes and 452 packages on the vendor
image against 120 and 338 on the rebuilt one.

**L15 — vmallocinfo addresses are hash-obfuscated.** `/proc/vmallocinfo` prints
its region addresses as hashed pointers (e.g. `0x12b28f67`), not real kernel
addresses (`0xffffffffc0...`), independent of `kptr_restrict` — `%p` hashing is
a separate mechanism from `kptr_restrict`. So the vmalloc channel can yield a
**count** of `load_module` regions but never a name or an address to correlate
against `/proc/modules`. Count-mismatch is still a valid signal; attribution
comes from the ftrace channel, not this one.
Evidence: `docs/step0-phase2/clean/07-vmallocinfo-modules.txt`

**L16 — Diamorphine's process-hiding hooks did not engage on kernel 6.1.0-52.**
During the phase 2 ground-truth run, Diamorphine loaded and hid its own module
(a direct `list_del` in `init`, needing no syscall hook), but its
syscall-hooking for process and file hiding never took effect: sending
SIGINVIS (signal 31) to a target delivered it as `SIGSYS` ("Bad system call")
and killed the process instead of hiding it. So kdetect's cross-view process
detection could not be exercised against this rootkit on this kernel; it
remains validated by the synthetic differ tests
(`tests/unit/test_diff_processes.py`) and by the clean-baseline zero-findings
guard. This is a property of classic m0nad/Diamorphine syscall-table hooking on
modern (6.x) kernels, not of kdetect. The module-hiding detection **was**
exercised against real ground truth and succeeded — three channels, `HIGH`
confidence. Rootkits not surviving kernel updates is itself a documentable
reality of this problem space.

**L17 — Taint stickiness makes `module_taint_mismatch` a false-positive-prone
signal on its own.** Taint bits 12 (out-of-tree) and 13 (unsigned) are set
permanently for the rest of the boot when such a module loads, and are NOT
cleared when it unloads. kdetect's `module_taint_mismatch` fires when a taint
bit is set but no currently-listed module carries the `(O)`/`(E)` marker —
which is true of a genuinely hidden module, but ALSO true of a host that
merely loaded and then unloaded a legitimate out-of-tree or unsigned module
earlier in the boot (VirtualBox additions, nvidia, vmware, a local dev build).
On such a host `module_taint_mismatch` fires with no rootkit present. The
clean-baseline fixture avoids this only because the freshly-rebuilt VM has
`taint=0`. A taint-only hit therefore corroborates just one channel and is
reported at LOW confidence; the `load_module` region-count and ftrace
channels, which track currently-loaded state rather than sticky history, are
the robust ones. Treat a lone `module_taint_mismatch` as a prompt to
investigate, not proof.

## Phase 3a — baseline store and hook surfaces

**L18 — On-host baseline signing detects forgery only from an attacker without
the signing key.** kdetect signs a baseline with an ed25519 private key and
verifies it on load with the public key (`baseline/store.py`, spec §6). Keeping
the public (verify) key on the inspected host and the private (sign) key
**off-host** means a baseline cannot be forged on the host, only verified: an
attacker at root can read and rewrite files (A2) but cannot mint a baseline that
certifies their own compromise. If the private key is left on the inspected host,
or the attacker obtains it, the guarantee degrades to detecting accidental
corruption. The honest strengthening is off-host key storage (A3), a phase-5
concern. Phase 3a delivers the mechanism and states its boundary; it does not
claim to have closed A3.

**L19 — The intra-snapshot orphan-hook check fires only on a hook whose callback
attributes to a *named, currently-unlisted* module.** `diff_hooks` reports
`unexpected_hook` (orphan) when a registered ftrace op's callback resolves — via
the ftrace `[module]` tag or `/proc/kallsyms` — to a module that is not in
`/proc/modules`. This is the Diamorphine analog and what caught the phase-3a test
module. Two classes are deliberately **not** orphaned on this basis, to avoid
clean-machine false positives: (a) a legitimate core-kernel ftrace op, whose
callback is in the core kernel with no module tag (`owner_module` None) — flagging
it would fire on any host running function tracing; (b) kprobes, which the parser
records with no callback symbol (`owner_module` None). Both are caught only via
the **baseline-drift** channel, never intra-snapshot. Calibration on the clean lab
VM (6.1.0-52, idle): `enabled_functions` and `kprobes/list` are both **empty**, so
on a clean idle host the orphan check has nothing to attribute and yields no
finding; the `owner_module`-must-be-named rule keeps a tracing-active host from
false-positiving on core-kernel ops. Composing an orphan hook with the module-view
channels into a single HIGH finding is deferred to phase 3b.

**L20 — Development runs Python 3.12; the lab VM runs Python 3.11.** Some 3.12
syntax parses on the Windows dev box but is a `SyntaxError` on the VM — notably a
multi-line expression inside an f-string replacement field (PEP 701). Such a
construct passes the entire Windows unit suite and only fails when kdetect is
imported on the VM. Observed once during phase 3a, in a `diff_hooks` summary
string. Guarded by `tests/unit/test_python311_compat.py`, which enforces 3.11
grammar and rejects multi-line f-string fields at the token level even while
running on 3.12. The ultimate backstop is running the suite on the VM.

**L21 — Anonymous hidden-module signals cannot be attributed when more than one
module is hidden.** The taint word is a single global bit set, and vmalloc region
addresses are hash-obfuscated (L15), so `taint` and `vmalloc_region` indicate
*that* a module is hidden, never *which*. The scorer folds them into a named
suspect only when exactly one module is hidden; with two or more hidden modules
they collapse into a single `suspected_hidden_module` finding that counts the
anonymous channels but names no module.

## Verified properties

**V1 — The unit suite runs without Linux.** Measured 2026-08-18: 55 passed,
11 skipped on Windows 11 / Python 3.12.10, against a clone of this repository.
The 11 skips are exactly the integration tier, gated on
`Path("/proc/self/stat").exists()` rather than on `sys.platform`. The full
`ProcfsProcessCollector` runs on Windows against a captured fixture tree, and a
snapshot captured on Linux/Python 3.11 re-serialises byte-identically on
Windows/Python 3.12.

This is why `ProcSource` is an interface rather than a configurable root path:
parser and collector work needs no VM, and only the live-capture path does.

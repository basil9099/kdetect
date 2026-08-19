# Detection methods

One entry per technique. Each states what it observes, why it works, what
defeats it, and the evidence it rests on.

Entries marked **[implemented]** exist in the code today. Entries marked
**[planned]** are recorded here because the reasoning was worked out while
building phase 1, and re-deriving it later would be waste.

Raw observations are in [`step0/`](step0/README.md). Consequences and known
gaps are in [`limitations.md`](limitations.md).

---

## The organising principle: cross-view comparison

There is no channel a sufficiently privileged rootkit cannot lie on. A kernel
module runs at the same privilege as the code asking the questions, so any
single answer can be forged.

kdetect therefore does not look for a trustworthy channel. It asks **the same
question through several channels of differing trustworthiness and compares the
answers**. A rootkit must lie *consistently across all of them* to stay hidden,
and consistency across channels is much harder than falsifying one.

This has a consequence worth stating plainly: **a single collector proves
nothing.** The phase 1 procfs collector is trust level `LOW` precisely because
it is the easiest surface to forge. Its value is as one term in a comparison.

---

## 1. Process identity triangulation [implemented]

**Observes.** Three independent answers to "what is this process": `comm`
(`/proc/[pid]/stat` field 2), `cmdline` (`/proc/[pid]/cmdline`), and `exe`
(`/proc/[pid]/exe`).

**Why it works.** They are forgeable to very different degrees:

| Source | Held by | Forged how | Difficulty |
|---|---|---|---|
| `cmdline` | process memory | rewrite the `argv` region, or `exec -a` | trivial, unprivileged |
| `comm` | kernel `task_struct` | `prctl(PR_SET_NAME)`, or write `/proc/self/comm` | easy, unprivileged, but truncates at 15 chars |
| `exe` | kernel, points at the real inode | cannot be forged from userspace | requires kernel-level access |

A process claiming to be one thing in `cmdline` while `exe` says otherwise is
not proof of compromise — plenty of legitimate software rewrites `argv[0]` —
but it is a cheap, high-signal discriminator worth recording on every process.

**Defeated by.** A kernel rootkit that patches the proc handlers can make all
three agree. Detecting that needs a higher-trust channel, not a cleverer
reading of `/proc`.

**Evidence.** [`step0/02-comm-vs-cmdline.txt`](step0/02-comm-vs-cmdline.txt) —
one process reporting `comm=sleep` while `cmdline` reads
`evil (hidden) proc`.

---

## 2. `PF_KTHREAD` as kernel-asserted identity [implemented]

**Observes.** Bit `0x00200000` of `/proc/[pid]/stat` field 9 (task flags).

**Why it works.** The obvious way to identify a kernel thread is "empty
`cmdline` and no `exe`". That is a heuristic over two derived facts, and it is
wrong in two ways: an ordinary process can have an empty `cmdline`, and an
unprivileged reader cannot read `exe` **at all** — so the heuristic collapses
entirely without root.

Field 9 is the kernel's own answer, it is world-readable, and it survives at any
privilege level. Measured on the lab host: as uid 1000, all 113 kernel threads
were still correctly identified while every one of their `exe` reads returned
`EACCES`.

**Defeated by.** A rootkit with kernel access can clear the flag. But doing so
makes the process inconsistent with other kernel-side views — which is exactly
what phase 2 compares.

**Design note.** kdetect stores the raw integer, never a derived
`is_kernel_thread` boolean. A collector that records conclusions cannot be
audited, and the derived form would have been unusable unprivileged.

**Evidence.** [`step0/07-pf-kthread-flags.txt`](step0/07-pf-kthread-flags.txt),
[`limitations.md`](limitations.md) L12.

---

## 3. errno discrimination [implemented]

**Observes.** The *reason* a read failed, not merely that it failed.

**Why it works.** Three outcomes look identical if you record only "no value":

| Outcome | errno | Means |
|---|---|---|
| read succeeded | — | the value |
| `ENOENT` | 2 | genuinely has no such attribute — e.g. a kernel thread has no `exe` |
| `EACCES` | 13 | it exists, you are not permitted to see it |

Collapsing the last two into a null destroys the distinction, and the
distinction is where false positives come from. Worse, **`EACCES` while running
as root is itself anomalous** — potentially a rootkit obstructing inspection —
whereas the same errno unprivileged is routine.

kdetect records the errno kind and `capture.euid`, and leaves the judgement to
analysis.

**Defeated by.** Nothing at this level; it is a fidelity property rather than a
detection in itself. Its value is preventing a whole class of false positives
in every technique built on top.

**Evidence.**
[`step0/06-exe-errno-comparison.txt`](step0/06-exe-errno-comparison.txt).

---

## 4. Deleted executables [implemented]

**Observes.** A `" (deleted)"` suffix on the `/proc/[pid]/exe` symlink target.

**Why it works.** The kernel appends it when the inode a running process was
executed from has been unlinked. Legitimate causes exist — a package upgrade
during runtime is the common one — but it is also the normal end state of
"drop a payload, execute it, delete it from disk", which leaves a running
process whose backing file no longer exists for a file-integrity scanner to
find.

Cheap to collect and high signal when correlated with process age and parentage.

**Defeated by.** Anything with kernel access can rewrite the link target.

**Implementation note.** The suffix is preserved verbatim. Stripping it to
"clean up" the path would discard the finding.

---

## 5. Absolute process start time [implemented]

**Observes.** `/proc/[pid]/stat` field 22 (`starttime`), combined with `btime`
from `/proc/stat` and `SC_CLK_TCK`.

**Why it works.** Field 22 is measured in **clock ticks since boot**, not
seconds and not an absolute time. On its own it is an uninterpretable integer.
With `btime` and the tick rate it becomes a wall-clock instant:

```
start = btime + starttime_ticks / clock_ticks_per_sec
```

That matters for correlation: "which processes started within a second of that
module being loaded" is a question you cannot ask without it.

`boot_id` is captured for the same reason at a coarser scale — PIDs and start
times are only comparable within one boot, and comparing captures across a
reboot produces confident nonsense.

**Verified.** The computed value matched `ps -o lstart=` exactly on the lab
host.

**Evidence.** [`step0/01-stat-fields.txt`](step0/01-stat-fields.txt),
[`step0/00-host-facts.txt`](step0/00-host-facts.txt).

---

## 6. Kernel address visibility is gated by two sysctls [implemented as a constraint]

**Observes.** Whether `/proc/kallsyms` and `/proc/modules` return real addresses
or zeros.

**Why it matters.** Every address-based technique — module base addresses,
syscall table integrity, detecting a hooked symbol — depends on being able to
read kernel addresses at all. That access is controlled by **two** sysctls, not
one, which is not obvious and cost an hour to work out:

- `kernel.kptr_restrict` — `0` "always show", `1` require `CAP_SYSLOG`, `2` never
- `kernel.perf_event_paranoid`

`kallsyms_show_value()` only honours `kptr_restrict=0` when
`kallsyms_for_perf()` is true, which requires `perf_event_paranoid <= 1`.
Otherwise it falls through and demands `CAP_SYSLOG` regardless.

Measured on the lab host: `kptr_restrict=0` but `perf_event_paranoid=3`, so
unprivileged reads returned zeros despite the permissive-looking first setting.

**Consequence.** kdetect requires root or `CAP_SYSLOG` for any address-based
detection. Recorded as [`limitations.md`](limitations.md) L4.

**Trap.** The first two symbols in `/proc/kallsyms` are type `A` per-CPU symbols
that are legitimately zero for everyone. Testing visibility with `head -2` gives
a false negative. Use a real text symbol — `commit_creds` is a good choice,
being the classic privilege-escalation target.

**Evidence.**
[`step0/09-kallsyms-user-vs-root.txt`](step0/09-kallsyms-user-vs-root.txt).

---

## 7. Immutable attributes on sensitive files [planned]

**Observes.** Extended file attributes, particularly the immutable bit, on paths
like `/etc/shadow`, `/etc/passwd`, `/etc/ld.so.preload`, and systemd unit files.

**Why it works.** `chattr +i` makes a file resist modification **even by root**,
which is a cheap persistence mechanism: a backdoored file that cannot be
overwritten by cleanup or configuration management. It requires
`CAP_LINUX_IMMUTABLE` to set, so its presence on a file that has no business
being immutable is meaningful.

The reason it is worth collecting is that it is **invisible to normal
inspection**. `ls -l` shows nothing unusual; only `lsattr` reveals it, and the
symptom is a confusing permissions error rather than an obvious denial.

**How we met it.** A `passwd` failure during lab setup produced
`Authentication token manipulation error` — the same signature this technique
would produce, which is what prompted writing it down.

**Defeated by.** A kernel rootkit hooking the attribute read path.

**Status.** Not implemented. Candidate for a filesystem collector: cheap to
capture, hard for a userspace-only rootkit to fake.

---

## 8. Cross-view process enumeration [planned — phase 2]

**Observes.** The set of PIDs reported by channels of differing trust:

| Channel | Trust | Method |
|---|---|---|
| `/proc` directory listing | `LOW` | `os.listdir("/proc")` |
| direct `getdents` on `/proc` | `MEDIUM` | bypasses libc, catches userspace-only interception |
| PID-space sweep | `MEDIUM` | `kill(pid, 0)` across the whole PID range; `ESRCH` means absent, `EPERM` means present but not ours |
| thread enumeration | `MEDIUM` | `/proc/[pid]/task/` — a hidden process's threads may still be reachable via its parent |

**Why it works.** Hiding a process from `/proc` means intercepting the directory
listing. Hiding it from a `kill(pid, 0)` sweep means intercepting a different
syscall path entirely. Each additional channel is another place the lie must be
maintained perfectly.

The `kill` sweep is particularly awkward to defeat because it does not ask "list
processes" — it asks "does this specific PID exist", 32768 times.

**Defeated by.** A rootkit that hooks both paths consistently. That is exactly
what a well-written LKM rootkit does, which is why phase 5 adds eBPF at `HIGH`
trust.

**Schema support.** This is why an `Observation` carries `entity_ids` separately
from `entities`: the `kill` sweep proves a PID exists without learning anything
else about it, so `entity_ids` is a superset of `entities`.

---

## 9. Hidden kernel module detection [planned — phase 2]

**Observes.** `/proc/modules` compared against `/sys/module/` and, later,
against the kernel's own module list.

**Why it works.** The standard LKM self-hiding technique removes the module's
entry from the kernel's module list (`list_del`), which takes it out of
`/proc/modules` and `lsmod` while leaving it loaded and running. But
`/sys/module/<name>/` is populated through a different mechanism, and a module
that removes itself from one may remain visible in the other.

Comparing the two enumerations is the same cross-view idea applied to modules
rather than processes.

**Defeated by.** A rootkit that removes itself from both. Diamorphine, the test
subject for phase 2, hides itself deliberately and exposes a magic-signal
control channel — see its repository for the current mechanism.

**Also worth collecting.** Module base addresses (requires `CAP_SYSLOG`, see
method 6), load order, and whether the module is signed. Debian's stock kernel
ships with module signature checking available; an unsigned out-of-tree module
is not proof of anything by itself, but it is a strong prior.

**Evidence for the reading.**
[`step0/08-modules-user-vs-root.txt`](step0/08-modules-user-vs-root.txt) —
70 modules, addresses masked unprivileged.

---

## 10. Symbol and syscall table integrity [planned — phase 3]

**Observes.** Hashes of critical kernel text regions and the addresses stored in
the syscall table, compared against a stored baseline.

**Why it works.** Function hooking has to change something: either a pointer in
a dispatch table, or the first bytes of a function (a trampoline). Both are
detectable by comparison against a known-good record — provided the baseline was
taken while the system was genuinely clean, which is the whole reason
[`lab-setup.md`](lab-setup.md) insists on a verified installer.

Since kernel 5.7, `kallsyms_lookup_name` is no longer exported, so modern
rootkits resolve symbols via kprobes instead. That changes how a rootkit finds
its target, not whether the modification is visible afterwards.

**Defeated by.** A rootkit that hooks the comparison itself. Detection from
inside a compromised kernel is fundamentally limited — the honest mitigation is
out-of-band memory analysis (phase 5, Volatility against a VM memory image),
where the observer is not running on the observed kernel.

---

## References

- `man 5 proc` — field definitions for everything under `/proc/[pid]/`
- [m0nad/Diamorphine](https://github.com/m0nad/Diamorphine) — LKM rootkit used
  as phase 2 ground truth
- [Linux Rootkits: New Methods for Kernel 5.7+](https://xcellerator.github.io/posts/linux_rootkits_11/)
  — kprobe-based symbol resolution after the `kallsyms_lookup_name` unexport
- [ossec/ossec-hids](https://github.com/ossec/ossec-hids) — mature host IDS,
  useful for comparing rootcheck's approach to cross-view detection

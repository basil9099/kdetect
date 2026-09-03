# Threat model

What kdetect can detect, what it cannot, and why. Where
[`detection-methods.md`](detection-methods.md) says *"here is what each
technique sees"*, this document says *"here is what an attacker can do about
it"*.

It exists to stop the tool overclaiming. A detector that cannot say what it
misses is not a security tool, it is a source of false confidence.

---

## 1. What a finding actually claims

kdetect does not detect rootkits. It detects **disagreement between views of
the same system**, and disagreement is evidence, not proof.

A finding says: *"channel A and channel B gave different answers to the same
question, and here are both answers."* Turning that into "this host is
compromised" is a human judgement, and there are legitimate causes of
disagreement — a process exiting between two reads, a container's PID namespace,
a package upgrade mid-scan.

Consequently:

- **A positive finding is a prompt to investigate, not a verdict.**
- **A clean result is not evidence of cleanliness.** It means no channel
  disagreed with any other, which is exactly what a competent rootkit produces.

---

## 2. Assumptions

Everything below rests on these. Where one fails, the corresponding detections
fail silently rather than loudly, which is the dangerous direction.

**A1 — The baseline was taken on a clean system.** Every integrity check
compares against a stored record. If the host was already compromised when that
record was made, kdetect faithfully certifies the compromise as normal. This is
why [`lab-setup.md`](lab-setup.md) insists on a signature-verified installer,
and why the phase 1 lab image is recorded as unfit for the purpose
([`limitations.md`](limitations.md) L1).

**A2 — kdetect's own code is intact.** The tool is a Python package on the host
it inspects. An attacker at root can edit it. Nothing in the design prevents
this; it is mitigated only by running from read-only or external media, which
kdetect does not currently support.

**A3 — Stored snapshots and baselines have not been tampered with.** They are
plain JSON on the same filesystem being inspected. Phase 3's baseline store
should address this — signing, or storage off-host — and until then a baseline
is only as trustworthy as the host holding it.

**A4 — The kernel is telling the truth about itself, or is at least
inconsistent when lying.** The entire cross-view approach depends on a rootkit
failing to forge every channel identically. Against one that succeeds, kdetect
returns clean.

---

## 3. Attacker capability tiers

| Tier | Capability | kdetect's position |
|---|---|---|
| **T0** | Unprivileged local user | Strong |
| **T1** | Root, userspace only | Good |
| **T2** | Loaded kernel module, not kdetect-aware | Fair — the design target |
| **T3** | Kernel-level and kdetect-aware | Weak |
| **T4** | Below the kernel: hypervisor, firmware, SMM | None |

### T0 — Unprivileged local user

**Can:** run processes; rewrite its own `argv` so `cmdline` lies; set `comm` via
`prctl(PR_SET_NAME)` or by writing `/proc/self/comm`; unlink its own binary
while running; spawn and exit fast enough to slip between a listing and a read.

**Cannot:** load kernel modules; alter another user's `/proc` entries; hide from
the kernel's own accounting.

**Detection.** Strong. `exe` is kernel-maintained and cannot be forged at this
tier, so identity triangulation (method 1) catches `cmdline` and `comm` lies
directly. `PF_KTHREAD` cannot be faked. A deleted executable is visible.

**Caveat.** kdetect running unprivileged is much weaker than kdetect running as
root — every `exe` read returns `EACCES`, so the strongest signal at this tier
is unavailable exactly when it would be cheapest to collect (L12).

### T1 — Root, userspace only

**Can:** replace `ps`, `ls`, `netstat` with lying versions; use
`/etc/ld.so.preload` to hook libc in every dynamically linked process; set
immutable attributes on files to resist cleanup; edit any configuration;
read and modify kdetect itself and its stored snapshots.

**Cannot:** intercept a syscall made directly, without libc.

**Detection.** Good, and this is where cross-view first earns its keep. A
`LD_PRELOAD` hook on `readdir` fools anything using libc but not a direct
`getdents` call — so the phase 2 `MEDIUM`-trust collector sees processes the
`LOW` one does not. Immutable attributes are visible to `lsattr` (method 7).
File integrity against a baseline catches replaced binaries.

**Caveat.** Assumption A2 already fails here. A root attacker can simply patch
kdetect. Detection at this tier assumes the attacker did not bother — a
reasonable assumption for commodity malware, a poor one for a targeted
intrusion.

### T2 — Loaded kernel module, not kdetect-aware

**Can:** hook syscalls or patch their handlers; remove itself from the kernel's
module list so it vanishes from `/proc/modules` and `lsmod`; hide chosen PIDs
from `/proc`; grant privilege on demand through a magic signal or similar
channel; hide files by intercepting filesystem calls.

**Detection.** Fair, and probabilistic. It rests entirely on the rootkit hiding
*inconsistently*:

- A PID hidden from the `/proc` listing but still answering `kill(pid, 0)`
- A PID hidden from both, but whose threads appear under a parent's
  `/proc/[pid]/task/`
- A module removed from `/proc/modules` but still present in `/sys/module/`
- A syscall table entry that no longer matches the baseline

Every one of these is a bet that the rootkit's author missed a path. Against
Diamorphine — the phase 2 test subject — several of these bets are expected to
pay off, which is what makes it a useful teaching target rather than a realistic
worst case.

**Caveat.** "kdetect found it" and "this class of rootkit is detectable" are
different claims. Finding a rootkit that does not try to hide from you
establishes very little about one that does.

### T3 — Kernel-level and kdetect-aware

**Can:** everything at T2, plus hook the specific paths kdetect uses; return
consistent lies across every channel; detect kdetect running and suspend hostile
behaviour for the duration; rewrite snapshots and baselines on disk; modify
kdetect's own code between runs.

**Detection.** Weak to none from on-host. This is the fundamental limit:
**kdetect runs on the kernel it is trying to assess, at lower privilege than the
attacker it is looking for.** No amount of cleverness inside that boundary
resolves it — the attacker can always see and alter the observer.

**The only real answers are out-of-band:**

- Analyse a memory image from outside the guest — phase 5's Volatility work
  against a VMware `.vmem`, where the analysis does not execute on the
  compromised kernel
- Store baselines off-host so they cannot be rewritten to match
- Compare against a network view taken from another machine, rather than the
  host's own socket tables

### T4 — Below the kernel

Hypervisor-level, firmware, SMM, or malicious hardware. kdetect has no
visibility whatsoever and makes no claim to. Listed only so the boundary is
explicit.

---

## 4. Detection coverage summary

| Technique | T0 | T1 | T2 | T3 |
|---|---|---|---|---|
| Identity triangulation (`comm`/`cmdline`/`exe`) | ✅ | ✅ | ⚠️ | ❌ |
| `PF_KTHREAD` kernel flag | ✅ | ✅ | ⚠️ | ❌ |
| Deleted executable | ✅ | ✅ | ⚠️ | ❌ |
| Cross-view PID enumeration | n/a | ✅ | ⚠️ | ❌ |
| Hidden module (`/proc/modules` vs `/sys/module`) | n/a | n/a | ⚠️ | ❌ |
| Syscall table / symbol integrity | n/a | n/a | ⚠️ | ❌ |
| Immutable attributes | n/a | ✅ | ⚠️ | ❌ |
| Out-of-band memory analysis | ✅ | ✅ | ✅ | ⚠️ |

✅ reliable · ⚠️ depends on the attacker's thoroughness · ❌ no coverage

The pattern is the point: **on-host techniques degrade to nothing by T3, and
only out-of-band analysis holds any value there.**

---

## 5. Limits that apply at every tier

**A capture is a sweep, not an instant.** Walking `/proc` takes tens of
milliseconds. A process that starts and exits inside that window is invisible,
and two collectors run in sequence observe slightly different systems — so some
disagreement is timing, not deception (L8). This is a permanent source of noise
that scoring must account for rather than eliminate.

**The observer is in the observation.** kdetect's own process, its threads, and
the VS Code Remote-SSH server are in every capture taken on the lab host (L6).
Useful as an invariant — a snapshot lacking its own author is untrustworthy —
but it also means the tool perturbs what it measures.

**Privilege is required for the strongest signals.** Address-based detection
needs root or `CAP_SYSLOG` (L4), and `exe` needs root to be meaningful (L12).
This makes kdetect a program that routinely runs as root while parsing
attacker-influenced input — see §6.

**A process sets its own `comm`, and the kernel keeps only 15 characters of it**
(L5), so process names are not reliable identifiers and are trivially collided.

---

## 6. Risks the tool itself introduces

A detector is not free. kdetect adds three risks to the host it protects.

**It runs as root and parses hostile input.** Every byte it reads from `/proc`
can be influenced by a process on the box — `cmdline` is entirely
attacker-controlled. A parser bug is therefore a privilege-escalation
opportunity, which is why parsing is confined to pure functions with no I/O and
no `eval`-style behaviour, and why malformed input raises `ParseError` rather
than being coerced.

**Snapshots are sensitive artefacts.** They contain the full command line of
every process, which routinely includes credentials passed as arguments. The
phase 1 fixture required a VS Code session token to be redacted before it could
be committed (L13). **A snapshot should be treated as at least as sensitive as
the host it came from**, and phase 4's reporting will need a redaction pass
before anything is shareable.

**Baselines are a target.** Once integrity checking exists, the fastest way to
defeat it is to rewrite the baseline rather than hide from it. A baseline stored
on the host it describes provides much weaker assurance than one stored
elsewhere.

---

## 7. Out of scope

- Prevention, containment, or remediation. kdetect observes; it does not act.
- Non-Linux hosts.
- Containers and namespaces as first-class concepts. A container's PID namespace
  will produce disagreement that looks like hiding, and phase 1 has no model for
  this. Recorded as a known gap rather than a solved problem.
- Malicious hardware, firmware, or hypervisor (T4).
- Network-based detection from off-host. Valuable, complementary, not this tool.

---

## 8. Confidence discipline

Directly downstream of §1, and binding on phase 3's scoring and phase 4's
reporting:

1. **Report the observation, then the interpretation, and keep them separate.**
   "procfs listed 152 PIDs; the kill sweep found 153; PID 31337 appears only in
   the sweep" is a fact. "A process is hidden" is an inference.
2. **Never emit a finding without its evidence**, including which collectors
   disagreed and at what trust levels.
3. **State the euid the capture ran at** on every report. A capture taken
   unprivileged is missing whole categories of signal, and a reader who does not
   know that will over-read a clean result.
4. **Do not aggregate a confidence score into a single verdict.** Combine
   signals, show the components.
5. **A clean result must be phrased as "no disagreement detected"**, never as
   "no rootkit present".

---

## 9. What would change this document

- Phase 2's Diamorphine results: which of the T2 bets actually pay off
- Container support, which changes what disagreement means
- Off-host baseline storage, which would strengthen assumption A3
- Phase 5's out-of-band memory analysis, the only thing that moves the T3 column

# kdetect v2 — red vs blue

Date: 2026-11-09. Status: design approved, spec under review.

## 1. Purpose

v2 exists to make kdetect a stronger portfolio piece for a first
penetration-testing role. It does that by showing adversarial thinking end to
end: write a lab-only evasion that beats kdetect through one of its documented
blind spots, then extend kdetect until it catches the evasion, and publish both.

v2 is open-ended. It is a series of **rounds**, each one shippable on its own.
Phase 4d (parser hardening) is no longer a separate v1.1: it becomes Round 1.

## 2. Rounds

Rounds escalate deliberately, so the series reads as one story.

| Round | Red: the evasion | Blue: the fix | Closes |
|---|---|---|---|
| R1 | Module named `evil][ext4`, read as `ext4` by all three naming channels | Delimiter-based parsing, `hostile_module_name`, malformed-channel findings | planned 4d |
| R2 | Kprobe or core-kernel ftrace hook that names no unlisted module | Function-keyed hook baseline drift | L22 |
| R3 | Process hiding that works on 6.1 (ftrace hook on `getdents64`) | First live validation of `hidden_process`, plus whatever it breaks | L16, L24 |
| R4 | Hook the `/proc` readers, so every in-guest channel lies in agreement | In-guest detection fails, and the write-up says so; Volatility 3 out-of-guest cross-view catches it | T3 column |
| R5+ | eBPF rootkit | BPF program and map cross-view | new class |

Only R1 is specified in full here (section 6). Each later round gets its own
short spec when it starts, and may be reordered or dropped then. R3 depends on
a `getdents64` hook actually working on 6.1; R5 is the most optional.

## 3. Anatomy of a round

Every round follows the same six steps:

1. **Recon.** A VM experiment that answers what the kernel actually permits.
   Evidence goes in `docs/step0-rN/`. Nothing after this step is final until
   recon has run.
2. **Red.** Add the technique to `kmod/kdetect_evade.c` behind a build flag.
   Load it on the VM and capture kdetect missing it (`findings: none`, a wrong
   name, or a lower confidence). Redact the capture with
   `tools/redact_snapshot.py` and commit it as
   `tests/fixtures/snapshots/evaded-rN.json`.
3. **Blue.** Short spec, then plan, then build. The regression test runs
   against the miss fixture: it must fail before the fix and pass after. Every
   guarded line gets a break/fail/restore/pass cycle (the 4c lesson).
4. **Live check.** On the VM: load the evasion again and confirm kdetect now
   catches it, then confirm a clean capture still reads `findings: none`.
5. **Docs.** Close or amend the limitation entry, and update
   `detection-methods.md`, the README ATT&CK table and `threat-model.md`.
6. **Write-up.** One post (section 5).

**An honest loss is a valid outcome.** If blue cannot fix a round from inside
the guest, the round still ships: the write-up says so and a new limitation
entry records it. R4 is built on this.

**Done** means the miss fixture exists, the test failed before the fix and
passes after, both live checks are green, the docs are updated and the post is
published.

## 4. The evasion LKM: `kmod/kdetect_evade.c`

It must be useful for testing kdetect and useless as a real rootkit.

- **One file, one flag per technique** (`make R1=1`, `make R3=1`, ...). Each
  build carries exactly one technique, so every fixture traces to a single
  cause. Combining techniques is out of scope until a round needs it.
- **Harmless payload.** It hides only itself, or processes whose `comm` is the
  hardcoded marker `kdetect-victim`. There is no parameter for picking other
  targets, and no persistence, networking, backdoor or privilege escalation.
- **Lab guard.** `init` returns an error unless the hostname matches the lab
  VM's. This is a guard against an accidental `insmod`, not a security
  control.
- **Narrow evasion.** Each technique beats only what its round targets; R1
  does not also suppress taint.
- **Unloading.** Visible builds can be removed with `rmmod`. Hidden builds
  cannot: revert the VM snapshot, as with Diamorphine and `kdetect_hooktest`.
  The existing lab rules apply: snapshot before loading, and never `git push`
  while it is loaded.
- **Publishing.** GPL, with a header comment stating its purpose and a section
  in `kmod/README`. Only techniques that are already public (Diamorphine,
  Reptile, the ftrace-hook write-ups); each post cites its source.

## 5. Releases and write-ups

- **Git.** One branch per round (`round-1-name-spoof`), merged to protected
  `main` by PR.
- **Versions.** Each merged round is a GitHub pre-release (`v2.0.0-r1`,
  `v2.0.0-r2`). `v2.0.0` is tagged when R3 lands; R4 becomes `v2.1.0`, R5
  `v2.2.0`.
- **Schema.** A round that needs new snapshot fields bumps the schema version
  additively (1.1 to 1.2). Old fixtures must keep loading, and the existing
  ground-truth tests prove it.
- **Write-ups.** A series on basil9099.github.io, *Breaking my own rootkit
  detector*. Part 0, published before R1: what kdetect is, what v1 admits it
  cannot do, and the plan. Then one post per round, structured as: the miss,
  why it happened, the fix, what is still open.
- **README.** A "Red vs blue" table with one row per round: technique, v1
  result, fix, status, post link.

## 6. Round 1: the name spoof

### 6.1 The defect

All three naming channels take the **last** `[` on a line as the start of the
module tag:

- `parsers/modules.py:73` (`parse_ftrace_modules`, `available_filter_functions`)
- `parsers/kernel_hooks.py:37` (`_callback_and_module`, `enabled_functions`)
- `parsers/kernel_hooks.py:125` (`reduce_kallsyms`, `/proc/kallsyms`)

A record `sym [evil][ext4]` therefore reads as module `ext4` on all three at
once, and cross-view corroboration cannot recover the real name.

Related hardening, carried over from the 4d plan:

- `parse_net_tcp` catches `(ValueError, IndexError)`, but the `struct.pack`
  call in its address decoder can raise `struct.error`, which is not a
  `ValueError` subclass, into a sockets collector that catches nothing.
- `parse_kprobes` raises for the whole file on any line with fewer than three
  tokens, into a hooks collector that hardcodes `errors=[]` and `status=OK`.
- `collectors/kernel_hooks.py:58` sets `kallsyms_available` with
  `is not None`, while line 29 builds the module map with a truthiness test.
  An empty but readable `/proc/kallsyms` therefore reports available with no
  names (the open 4c decision).

### 6.2 Recon (`docs/step0-r1/`)

Build `kdetect_evade` with `R1=1` and patch the `name` field of
`.gnu.linkonce.this_module` with `objcopy`. Try these names:

- `evil][ext4`
- a name containing a space
- a name containing a newline
- a 55-character name (the `MODULE_NAME_LEN` maximum)

For each, record whether `insmod` accepts it, and how it appears in
`/proc/modules`, `/proc/kallsyms`, `available_filter_functions`,
`enabled_functions` and `/sys/module`.

**Gate:** sections 6.3 and 6.4 are designed against the names that load. If
the kernel rejects `]` and `[`, R1 shrinks to the hardening items (6.4 items 3
and 4) plus `hostile_module_name` for whatever does load, and the write-up
reports that the attack fails.

### 6.3 Red

The R1 build combines three parts:

- the `kdetect_hooktest` ftrace hook on `__x64_sys_newuname`
- `list_del` self-hiding
- the hostile name

What we expect v1 to do: the callback is attributed to `ext4`, which is
listed, so the orphan-hook signal stays quiet. Only the anonymous taint and
vmalloc channels remain, so the verdict drops from HIGH `hidden_module` to
`suspected_hidden_module` or lower. The capture made in step 2 records what v1
actually does, and the write-up reports that, not this prediction.

### 6.4 Blue

1. **Parse from the delimiter, not the last bracket.**
   - `kallsyms`: the module tag is everything after the tab, minus its outer
     brackets.
   - `available_filter_functions` and `enabled_functions`: the tag starts at
     the first ` [` after the symbol and runs to the final `]`.

   The result is module `evil][ext4`, intact. The exact grammar is fixed
   against the recon captures.
2. **New signal `hostile_module_name`.** A module name outside
   `[A-Za-z0-9_]` fires it. Real module names are C identifiers, because
   `KBUILD_MODNAME` turns `-` into `_`. It counts as its own channel in the
   per-suspect corroboration count, so the trick is caught even if a parser
   regresses later.
3. **An unparseable channel is a finding.**
   - The `kernel.hooks` and `procfs.sockets` collectors record
     `ErrorKind.MALFORMED` the way `collectors/procfs.py` already does,
     instead of hardcoding `errors=[]`.
   - `parse_kprobes` reports each bad line separately instead of raising for
     the whole file.
   - The sockets parser catches `struct.error`.
   - Analysis turns `MALFORMED` on a naming channel (kallsyms, ftrace,
     `enabled_functions`) into a LOW finding of a new kind,
     `malformed_channel`, that names the channel and carries the bad lines
     as evidence (escaped by `printable()` on human output paths).
4. **`kallsyms_available = bool(kallsyms_text)`** at
   `collectors/kernel_hooks.py:58`, matching line 29.

### 6.5 Tests

- **Regression.** On `evaded-r1.json`: one HIGH `hidden_module` naming
  `evil][ext4`, with `hostile_module_name` among its channels. It must fail on
  `main` before the fix.
- **Parsers.** Unit tests for every name that loaded during recon, on all
  three naming parsers.
- **Hardening.** Unit tests for a short kprobes line, a `struct.error` address
  and an empty `/proc/kallsyms`, each asserting a `MALFORMED` error or
  unavailable flag rather than an exception or a silent OK.
- **No regressions.** The existing ground truth stays unchanged: Diamorphine
  and `kdetect_hooktest` are each one HIGH `hidden_module`, and the clean
  fixtures read zero findings.
- **Proof the tests guard.** Every test above goes through the
  break/fail/restore/pass cycle on the line it guards.
- **Environments.** The full suite passes on both Windows and the 3.11 VM.

### 6.6 Docs

- **Limitations.** A new entry recording the name-spoof defect and its fix, and
  any recon surprises.
- **Detection methods.** `detection-methods.md` gains `hostile_module_name`.
- **README.** The "Red vs blue" table gets its first row.

## 7. Out of scope for v2

- A monitoring mode or daemon.
- Off-host baseline signing (L18).
- Packaging for real hosts.
- A YAML rule engine.

These can return if v2's goal changes from portfolio to usability.

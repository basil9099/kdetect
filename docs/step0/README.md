# Step 0 — raw `/proc` observations

Captured by hand before any code was written, on the clean lab VM.
These files are evidence: every field in the snapshot schema should trace
back to something observed here.

| File | What it establishes |
|---|---|
| `00-host-facts.txt` | `btime`, `CLK_TCK`, `boot_id`, `kptr_restrict` — without these, `stat` field 22 is uninterpretable |
| `01-stat-fields.txt` | Full field-by-field map of `/proc/[pid]/stat`, plus `starttime` → wall-clock verified against `ps lstart` |
| `02-comm-vs-cmdline.txt` | `argv[0]` is freely forgeable; `comm` and `exe` are not. Three identities, three difficulties |
| `03-comm-paren-trap.txt` | A `comm` containing spaces and parens silently misaligns every field after it under naive `split()` |
| `04-identity-sources-pid1.txt` | `cmdline` / `comm` / `exe` on PID 1. **`exe` must be `readlink`'d, never `cat`'d** |
| `05-kernel-thread-pid2.txt` | `kthreadd`: empty `cmdline`, no `exe`, ppid 0. False-positive class #1 |
| `06-exe-errno-comparison.txt` | `ENOENT(2)` "has no exe" vs `EACCES(13)` "not allowed to look" — same null, different meaning |
| `07-pf-kthread-flags.txt` | `PF_KTHREAD` (`0x00200000`) in `stat` field 9 — kernel ground truth, beats every heuristic |
| `08-modules-user-vs-root.txt` | Module base addresses masked to zero for non-root |
| `09-kallsyms-user-vs-root.txt` | Address visibility is gated by **two** sysctls: `kptr_restrict` *and* `perf_event_paranoid` |

## Findings that changed the design

1. **`flags` (stat field 9) must be in the process entity schema.** `PF_KTHREAD`
   is kernel-provided ground truth for "is this a kernel thread". Inferring it
   from an empty `cmdline` would have been false-positive class #1.

2. **`exe` needs a three-state representation**, not a nullable string:
   a path, `null` because there is none, or `null` because access was denied.
   Collapsing the last two loses the distinction that matters.

3. **Parse `stat` by locating the last `)`**, never by splitting on whitespace.

4. **kdetect requires root (or `CAP_SYSLOG`)** for any address-based detection.
   On this host `kptr_restrict=0` but `perf_event_paranoid=3`, so unprivileged
   reads of `/proc/kallsyms` and `/proc/modules` return zeroed addresses.

## Reproducing

Each file carries the exact command and capture timestamp in its header.
Captured on `6.1.0-10-amd64`, Debian 12, as uid 1000 with passwordless sudo.

# Step 0 — phase 2 evidence (cross-view channels)

Phase 1's schema traces to `docs/step0/`. Phase 2's **differ** traces to here.

Phase 2 asks the same question through channels of differing trust and treats
disagreement as signal. Before designing the differ, this pass measures how far
those channels disagree **on a clean machine** — because every clean-machine
disagreement is a false positive the differ must explain away — and checks
whether a hidden module leaves a trace on any channel that does not share a
source with `/proc/modules`.

Collected by `tools/step0_phase2.py`, which only reads (its one write is forking
short-lived children of its own to make mid-capture races visible). It loads no
modules and changes no settings.

## The files

| File | Question it answers |
|---|---|
| `00-host-facts.txt` | Kernel, `pid_max`, and the taint word — the baseline the infected run is compared against |
| `01-listing-vs-tasks.txt` | **FP class #1:** `/proc` lists ~136 leaders; the sweep finds ~226 tasks. A naive diff reports ~90 hidden processes on a clean box |
| `02-sweep-vs-listing.txt` | The `kill(id,0)` sweep in full, every unlisted id classified as thread / vanished / unexplained |
| `03-sandwich-race.txt` | Why capture runs procfs → sweep → procfs: under churn the channels disagree from timing alone |
| `04-direct-access-channel.txt` | **Channel 3:** `/proc/<pid>` answers even when readdir won't list it — and yields identity, not just existence |
| `05-module-three-lists.txt` | `/proc/modules`, `/sys/module`, kallsyms tags — and **FP classes #2 (built-ins in sysfs) and #3 (`[bpf]` tags)** |
| `06-ftrace-module-tags.txt` | **Candidate independent channel:** do ftrace function records outlive list-unlinking? *(root)* |
| `07-vmallocinfo-modules.txt` | **Candidate independent channel:** does a hidden module keep its vmalloc region? *(root)* |
| `08-taint-accounting.txt` | **Candidate independent channel:** taint bits 12/13 set, but no listed module wears the marker *(root)* |

Files 06–08 need root; run the whole pass under `sudo`.

## What the clean run already established (uid 1000, `6.1.0-52`)

- **~90 phantom hidden processes** from threads alone. The differ must fold a
  task into its leader via `Tgid` before comparing, or it cries wolf 90 times.
- The **sandwich** cleanly separates timing from hiding: idle, the sweep and
  both walks agree on the 90 thread-ids and nothing else; under churn, only the
  churn processes differ, and they resolve to listed leaders.
- **`/sys/module` (136) ≫ `/proc/modules` (72):** built-in code registers a
  sysfs directory without being a loadable module. `initstate` present ⇒ truly
  loaded. This is the module view's FP class #2.
- **kallsyms tags aren't all modules:** `[bpf]` appears with no module behind
  it. FP class #3.

## Running the clean pass

On the lab VM, from the repo root, on the `clean-baseline` snapshot:

```bash
sudo python3 tools/step0_phase2.py --label clean
```

Review the files, then copy them to the Windows host and commit them (they
contain hostnames and process command lines — the same sensitivity as any
capture; review before committing, per L13).

## Running the infected pass — SAFETY

This runs live rootkit code. Follow the lab procedure exactly
([[kdetect-lab-env]]):

1. From `clean-baseline`, **commit and push** everything you want to keep. Never
   push again until you are back on a clean snapshot — the deploy key lives on
   this machine.
2. Snapshot the VM as `infected-diamorphine`.
3. **Switch the network adapter to Host-only.**
4. Build and load Diamorphine (source stays under `lab/targets/`, which is
   gitignored — it is never committed):
   ```bash
   # in lab/targets/diamorphine, per its README
   make
   sudo insmod diamorphine.ko
   ```
5. Hide a process you control, and note its PID. Classic Diamorphine
   (`m0nad/Diamorphine`) toggles PID hiding on signal 31 (`SIGINVIS`) — but the
   number is a `#define` in the source, so confirm it in the version you built:
   ```bash
   grep SIGINVIS lab/targets/diamorphine/diamorphine.h   # confirm the number
   sleep 6000 &          # note the PID it prints
   kill -31 <PID>        # now hidden from ps/top/readdir
   ```
6. Run the evidence pass, telling it which PID you hid:
   ```bash
   sudo python3 tools/step0_phase2.py --label infected-diamorphine --hidden-pid <PID>
   ```
   Diamorphine also hides its own module on load (it unlinks from the module
   list); file 05 should show it gone from `/proc/modules` while files 06–08
   test whether any channel still sees it.
7. Copy **only the evidence text files** off the VM (scp to the Windows host).
   Do not `git push` from the infected snapshot.
8. **Revert the VM to `clean-baseline`.** Commit the infected evidence from the
   reverted, clean tree.

The paired `clean/` and `infected-diamorphine/` directories are what the phase 2
design reasons over, and their captured snapshots become the regression
fixtures — clean and infected, same boot shape.

# Validation

What kdetect has been shown to do, against what, and how to check it yourself.

Every claim here sits in one of three tiers:

- **Live.** Run on the lab VM (Debian 12, kernel 6.1.0-52, built per
  [`lab-setup.md`](lab-setup.md)) as root, with the rootkit or test module
  actually loaded. The capture was then redacted and committed.
- **Replayed.** That committed capture is re-analysed on every CI run by
  [`tests/unit/test_ground_truth.py`](../tests/unit/test_ground_truth.py), so a
  live result cannot quietly regress. Replay checks the analysis layer against
  real kernel output; it does not re-run the collectors.
- **Synthetic.** Hand-built proc trees, signal sets or snapshots only. The logic
  is tested, but no real rootkit has produced the evidence.

## Summary

| Claim | Tier | Capture | Asserted by |
|---|---|---|---|
| A clean host produces zero findings | Live, replayed | `clean-phase2.json`, `clean-phase3a.json` | `test_clean_phase2_has_zero_findings`, `test_clean_phase3a_has_zero_findings`, `test_clean_fixtures_have_no_socket_findings` |
| `hidden_module`: Diamorphine, `HIGH` | Live, replayed | `infected-diamorphine.json` | `test_infected_diamorphine_is_one_high_hidden_module` |
| `hidden_module`: `kdetect_hooktest`, `HIGH` | Live, replayed | `infected-hooktest.json` | `test_infected_hooktest_is_one_high_hidden_module` |
| No false `hidden_process` on an infected host | Live, replayed | both infected captures | `test_infected_*_no_false_hidden_process` |
| `hidden_process` | Synthetic | none (L16, L24) | `test_scoring.py`: `test_process_two_channels_is_medium`, `test_socket_visible_lifts_hidden_process_to_high`; `test_collector_sweep.py` |
| `suspected_hidden_module` | Synthetic | none | `test_scoring.py`: `test_two_hidden_modules_do_not_absorb_anonymous` |
| `over_listed_module` | Synthetic, on a real capture | `infected-hooktest.json` with one phantom row injected | `test_a_phantom_modules_row_reaches_analyze_as_an_over_listed_finding` |
| `baseline_drift` | Synthetic | none | `test_scoring.py`: `test_baseline_only_module_is_low_drift_not_hidden`; `test_signals.py`: `test_baseline_drift_emits_added_modules_only` |

Captures are under [`tests/fixtures/snapshots/`](../tests/fixtures/snapshots/).

The CI integration tier (`tests/integration/`, marked `needs_procfs`) also runs
the collectors against the real `/proc` of a GitHub Ubuntu runner. That shows
capture works on a live kernel other than the lab's, unprivileged and with
nothing hidden. It is not detection evidence.

## Live runs

Each infected capture was taken in the same boot as a clean one: the pairs share
a `boot_id`. So the only difference between them is the module that was loaded,
not a reboot or a different kernel.

### Phase 2: Diamorphine (2026-08-20)

- **Host:** `kdetect-lab`, kernel `6.1.0-52-amd64`, boot `8098f952…`
- **Clean half:** `clean-phase2.json`, captured 2026-08-19 23:58 UTC. Zero findings.
- **Loaded:** [m0nad/Diamorphine](https://github.com/m0nad/Diamorphine), built
  from source on the VM. It unlinks itself from the module list in its own
  `init`.
- **Infected half:** `infected-diamorphine.json`, captured 2026-08-20 05:19 UTC.
- **Result:** one `HIGH` `hidden_module` for `diamorphine`, seen by
  `ftrace_orphan`, `taint` and `vmalloc_region` and denied by `/proc/modules`.
  Taint went from `0` to `12288` (bits 12 and 13), `load_module` regions rose to
  73 against 72 listed, and ftrace still tagged a module named `diamorphine`.
  Full write-up in [`detection-methods.md`](detection-methods.md), method 9.
- **What did not engage:** Diamorphine's syscall-table hooks for process hiding
  never took effect on 6.1. Signal 31 killed the target with `SIGSYS` instead of
  hiding it ([L16](limitations.md)). So this run tested module hiding only.
- **Procedure:** [`step0-phase2/README.md`](step0-phase2/README.md).

### Phase 3a: `kdetect_hooktest` (2026-08-27)

- **Host:** `kdetect-lab`, kernel `6.1.0-52-amd64`, boot `56524d35…`
- **Clean half:** `clean-phase3a.json`, captured 08:45 UTC. Zero findings.
- **Loaded:** [`kmod/kdetect_hooktest.c`](../kmod/kdetect_hooktest.c), built
  hidden (`make hidden`). It registers a no-op ftrace hook on
  `__x64_sys_newuname` and unlinks itself. It is benign, and it is committed so
  that anyone can reproduce the run.
- **Infected half:** `infected-hooktest.json`, captured 08:55 UTC.
- **Result:** one `HIGH` `hidden_module` for `kdetect_hooktest`, seen by
  `taint`, `unexpected_hook` and `vmalloc_region`, with the hook named as an IOC.
  [`detection-methods.md`](detection-methods.md), method 10, has the details.
  This is the same scenario as the README's demo GIF and "Try it" section.

## Not demonstrated live

- **Process hiding.** No rootkit available on kernel 6.1 hid a process, so the
  `hidden_process` path rests on synthetic tests plus the clean-host guard (L16).
- **Socket corroboration.** The `socket_visible` → `HIGH` `hidden_process` path is
  validated only by hand-built snapshots (L24).
- **Anonymous, over-listed and drift findings.** `suspected_hidden_module`,
  `over_listed_module` and `baseline_drift` have never fired on a capture taken
  with a real threat present.
- **Kernels other than 6.1.0-52.** Every live run was on one kernel. The phase 1
  fixture `clean-vm.json` (kernel 6.1.0-10) predates detection and only exercises
  process capture.

[`limitations.md`](limitations.md) covers what kdetect cannot see in principle.
This section covers only what is untested.

## Reproducing

### 1. Run the replay (any OS, no root)

```bash
pip install -e .
pip install pytest
pytest tests/unit/test_ground_truth.py
```

### 2. Analyse the captures yourself

```bash
kdetect analyze tests/fixtures/snapshots/clean-phase2.json
kdetect analyze tests/fixtures/snapshots/infected-diamorphine.json
kdetect analyze tests/fixtures/snapshots/infected-hooktest.json
```

Expected: `findings:  none` and exit 0 for each clean capture. For each infected
capture, the `HIGH` `hidden_module` above and exit 3. The Diamorphine result
looks like this:

```
findings:
  [HIGH]   hidden_module   module diamorphine
           seen by: ftrace_orphan, taint, vmalloc_region
           denied by: procfs.modules listing
```

### 3. Re-run it live

You need a disposable VM: a hidden module cannot be unloaded, so you revert a
snapshot afterwards.

1. Build the VM from [`lab-setup.md`](lab-setup.md) and take a
   `clean-baseline` snapshot. Follow §8 for working with rootkits, including the
   host-only network adapter.
2. **Test module:** build it with `(cd kmod && make clean && make hidden)`, then
   run [`tools/demo.sh`](../tools/demo.sh) as root. It captures, loads the
   module and captures again.
3. **Diamorphine:** follow [`step0-phase2/README.md`](step0-phase2/README.md).
   Rootkit source is deliberately not in this repository. Clone it into
   `lab/targets/` on the VM, which `.gitignore` excludes.
4. Revert to `clean-baseline`, and never push from an infected snapshot.

Expect small numeric differences, such as module counts, on a different kernel
or package set. The finding kind, the subject and the corroborating channels
should match.

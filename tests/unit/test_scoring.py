from kdetect.analysis.models import Signal, Suspect, FindingKind, Confidence
from kdetect.analysis.scoring import score

def _mod(channel, name, **ev):
    return Signal(channel, Suspect("module", name), "procfs.modules listing", ev or {})

def test_empty_signals_no_findings():
    assert score([]) == []

def test_one_hidden_module_folds_anonymous_to_high():
    sigs = [
        _mod("unexpected_hook", "kdetect_hooktest", function="__x64_sys_newuname"),
        _mod("taint", None, bits=[12, 13]),
        _mod("vmalloc_region", None, unaccounted=1),
    ]
    findings = score(sigs)
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.HIDDEN_MODULE
    assert f.subject == "module kdetect_hooktest"
    assert f.confidence is Confidence.HIGH          # 3 distinct channels
    assert set(f.channels_agree) == {"unexpected_hook", "taint", "vmalloc_region"}

def test_two_hidden_modules_do_not_absorb_anonymous():
    sigs = [
        _mod("ftrace_orphan", "modA"),
        _mod("unexpected_hook", "modB", function="x"),
        _mod("taint", None, bits=[12]),
    ]
    findings = score(sigs)
    kinds = {f.subject: f for f in findings}
    # each named module scores on its own channel only (LOW), and the anonymous
    # taint becomes a separate SUSPECTED_HIDDEN_MODULE rather than being guessed
    assert kinds["module modA"].confidence is Confidence.LOW
    assert kinds["module modB"].confidence is Confidence.LOW
    susp = [f for f in findings if f.kind is FindingKind.SUSPECTED_HIDDEN_MODULE]
    assert len(susp) == 1 and susp[0].subject == "unattributed hidden module"

def test_baseline_only_module_is_low_drift_not_hidden():
    findings = score([_mod("baseline_drift", "cfg80211", direction="added")])
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.BASELINE_DRIFT
    assert findings[0].confidence is Confidence.LOW

def test_process_two_channels_is_medium():
    p = Suspect("process", "1234")
    sigs = [Signal("syscall_kill", p, "procfs readdir (all passes)", {"tgid": 1234}),
            Signal("direct_status", p, "procfs readdir (all passes)", {"tgid": 1234})]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_PROCESS
    assert findings[0].confidence is Confidence.MEDIUM
    assert findings[0].subject == "pid 1234"

def test_socket_visible_lifts_hidden_process_to_high():
    p = Suspect("process", "1234")
    sigs = [
        Signal("syscall_kill", p, "procfs readdir (all passes)", {"tgid": 1234}),
        Signal("direct_status", p, "procfs readdir (all passes)", {"tgid": 1234}),
        Signal("socket_visible", p, "procfs readdir (all passes)", {"inode": 999}),
    ]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_PROCESS
    assert findings[0].confidence is Confidence.HIGH        # 3 channels

def test_over_listed_module_gets_its_own_kind_and_is_not_hidden():
    findings = score([_mod("over_listed", "phantom_mod")])
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.OVER_LISTED_MODULE
    assert f.confidence is Confidence.LOW
    # The inverse-classification trap from spec section 7.1.
    assert f.kind is not FindingKind.HIDDEN_MODULE
    assert f.kind is not FindingKind.BASELINE_DRIFT

def test_over_listed_does_not_absorb_anonymous_hidden_evidence():
    sigs = [_mod("over_listed", "phantom_mod"), _mod("taint", None, bits=[12])]
    findings = score(sigs)
    over = [f for f in findings if f.kind is FindingKind.OVER_LISTED_MODULE]
    assert len(over) == 1
    assert over[0].channels_agree == ["over_listed"]

def test_over_listed_plus_other_evidence_never_reads_as_pure_concealment():
    # A single-channel over_listed-only suspect can pass this mandate by luck
    # of check ordering even when over_listed is wrongly added to _HIDING (the
    # exact-match branch still catches it first) or when the branch is moved
    # after the _HIDING test (_HIDING correctly excludes it either way). A
    # composite suspect -- over_listed riding alongside a channel that is
    # neither over_listed nor hiding -- is the case that actually exercises
    # whether _HIDING excludes over_listed: it never matches the exact-match
    # branch, so it always falls through to the _HIDING test.
    findings = score([_mod("over_listed", "m"), _mod("baseline_drift", "m")])
    assert len(findings) == 1
    assert findings[0].kind is not FindingKind.HIDDEN_MODULE

def test_over_listed_is_not_masked_as_baseline_drift():
    # The exact-match branch (channels == ["over_listed"]) was inert in exactly
    # the posture the project recommends. A phantom row an attacker inserts is
    # by construction absent from any baseline predating it, so baseline_drift
    # fires on the same suspect, the exact match misses, and the finding
    # classified as baseline_drift: the weaker of the two facts stated in the
    # summary, and the kind an operator greps for never emitted at all.
    findings = score([_mod("over_listed", "phantom_mod"),
                      _mod("baseline_drift", "phantom_mod", direction="added")])
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.OVER_LISTED_MODULE
    assert f.kind is not FindingKind.BASELINE_DRIFT
    assert set(f.channels_agree) == {"over_listed", "baseline_drift"}
    # The over-listed fact is stated, and the channel riding alongside it is
    # named rather than dropped -- both facts, not the weaker one.
    assert "named by no other channel" in f.summary
    assert "baseline_drift" in f.summary


def test_a_hiding_channel_still_outranks_over_listed_after_the_presence_check():
    # The presence check must not overtake _HIDING: over_listed riding with a
    # genuine hiding channel is still concealment, not an over-listed row.
    findings = score([_mod("over_listed", "m"),
                      _mod("ftrace_orphan", "m"),
                      _mod("baseline_drift", "m", direction="added")])
    assert len(findings) == 1
    assert findings[0].kind is FindingKind.HIDDEN_MODULE


def test_over_listed_is_not_named_among_channels_that_corroborate_concealment():
    # unexpected_hook IS in _HIDING, unlike baseline_drift above -- this is the
    # composite that actually reaches the HIDDEN_MODULE summary-join line and
    # can catch a regression of the over_listed exclusion there.
    findings = score([_mod("over_listed", "m"),
                      _mod("unexpected_hook", "m", function="x")])
    assert len(findings) == 1
    f = findings[0]
    assert f.kind is FindingKind.HIDDEN_MODULE      # a hiding channel is present
    assert "unexpected_hook" in f.summary
    # over_listed means "nothing corroborates this module" -- listing it among
    # the channels that named a concealment is self-contradictory.
    assert "over_listed" not in f.summary
    # It is still a real channel that fired and must still count toward
    # confidence -- only the summary's "named by" clause excludes it.
    assert "over_listed" in f.channels_agree

def test_a_second_name_does_not_strip_the_real_suspects_evidence():
    """One appended module name must not demote a real finding (spec section 6)."""
    real = [
        _mod("unexpected_hook", "kdetect_hooktest", function="__x64_sys_newuname"),
        _mod("taint", None, bits=[12, 13]),
        _mod("vmalloc_region", None, unaccounted=1),
    ]
    alone = score(real)
    assert alone[0].confidence is Confidence.HIGH

    # The attack: manufacture one extra hidden name to force a tie.
    with_decoy = score(real + [_mod("ftrace_orphan", "e1000_dbg")])
    unattributed = [f for f in with_decoy
                    if f.kind is FindingKind.SUSPECTED_HIDDEN_MODULE]
    assert len(unattributed) == 1

    # The anonymous evidence is still reachable: it names BOTH candidates
    # instead of silently discarding the attribution.
    assert unattributed[0].evidence["candidates"] == ["e1000_dbg", "kdetect_hooktest"]
    assert "e1000_dbg" in unattributed[0].summary
    assert "kdetect_hooktest" in unattributed[0].summary

def test_single_candidate_still_attributes_and_carries_no_candidate_list():
    sigs = [_mod("unexpected_hook", "solo", function="x"), _mod("taint", None, bits=[12])]
    findings = score(sigs)
    assert len(findings) == 1
    assert findings[0].subject == "module solo"
    assert "candidates" not in findings[0].evidence


from kdetect.analysis.taint import TAINT_BIT_LETTER, reconcile


def test_table_carries_only_the_evidenced_letters():
    # docs/step0-phase2/clean/08-taint-accounting.txt evidences bit 12 = (O)
    # out-of-tree and bit 13 = (E) unsigned, and nothing else. Widening the
    # table without capturing evidence first is the phase 3a format-guess
    # mistake (spec section 4.3).
    assert TAINT_BIT_LETTER == {12: "O", 13: "E"}


def test_no_listed_marker_leaves_every_set_bit_unexplained():
    rec = reconcile((1 << 12) | (1 << 13), {"ext4": None, "xfs": None})
    assert rec.unexplained == [12, 13]
    assert rec.explained_by == {}
    assert rec.saturated is False


def test_marker_explains_only_its_own_bit():
    # The whole point: a (P) proprietary marker has nothing to do with bits
    # 12 and 13, and must not silence them.
    rec = reconcile((1 << 12) | (1 << 13), {"nv": "P"})
    assert rec.unexplained == [12, 13]

    # (O) explains out-of-tree but leaves unsigned unexplained.
    rec = reconcile((1 << 12) | (1 << 13), {"dkms_mod": "O"})
    assert rec.unexplained == [13]
    assert rec.explained_by == {12: ["dkms_mod"]}


def test_oe_module_explains_both_bits_and_saturates_the_channel():
    # This is a LIMIT, not a bug: (OE) honestly explains both bits, so the
    # channel cannot speak about a hidden module (spec section 1.2).
    rec = reconcile((1 << 12) | (1 << 13), {"vboxdrv": "OE", "ext4": None})
    assert rec.unexplained == []
    assert rec.explained_by == {12: ["vboxdrv"], 13: ["vboxdrv"]}
    assert rec.saturated is True


def test_non_reconcilable_bits_are_ignored():
    # Bit 9 is TAINT_WARN; no module can account for it and it must never
    # produce an unexplained bit.
    rec = reconcile(1 << 9, {"ext4": None})
    assert rec.unexplained == []
    assert rec.saturated is False


def test_clean_taint_word_is_not_saturated():
    rec = reconcile(0, {"ext4": "OE"})
    assert rec.unexplained == []
    assert rec.explained_by == {}
    assert rec.saturated is False


def test_owners_are_sorted():
    rec = reconcile(1 << 12, {"zz": "O", "aa": "OE", "ext4": None})
    assert rec.explained_by == {12: ["aa", "zz"]}

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ядро проверки целостности (решение 28.10-273; чистая граница 286 п. 6): цепочка журнала и отпечатки строк без базы."""

from __future__ import annotations

import pytest

from homensai_security import public_api as security


def _chain(n: int) -> list[security.JournalEntry]:
    entries: list[security.JournalEntry] = []
    prev = security.JOURNAL_ZERO
    for seq in range(1, n + 1):
        payload = {"kind": "tx", "tables": [f"t{seq}"], "audit": None}
        digest = security.journal_link(prev, payload)
        entries.append(security.JournalEntry(seq, prev, payload, digest))
        prev = digest
    return entries


def test_clean_chain_has_no_problems() -> None:
    assert security.verify_chain(_chain(5)) == []
    assert security.verify_chain([]) == []


def test_rewritten_entry_breaks_its_hash() -> None:
    entries = _chain(4)
    bad = entries[1]
    entries[1] = security.JournalEntry(bad.seq, bad.prev, {**bad.payload, "tables": []}, bad.hash)
    assert [(p.code, p.seq) for p in security.verify_chain(entries)] == [("journal_hash", 2)]


def test_removed_entry_is_a_gap_and_broken_link() -> None:
    entries = _chain(4)
    del entries[1]
    codes = {(p.code, p.seq) for p in security.verify_chain(entries)}
    assert ("journal_gap", 3) in codes
    assert ("journal_link", 3) in codes


def test_recomputed_tail_still_differs_from_anchor() -> None:
    """Переписанный «хвост» с пересчётом хэшей проходит цепочку, но хэш записи уже не тот, что в якоре копии."""
    entries = _chain(3)
    anchored = entries[1].hash
    payload: dict[str, object] = {"kind": "tx", "tables": [], "audit": None}
    forged = security.journal_link(entries[0].hash, payload)
    rewritten = [entries[0], security.JournalEntry(2, entries[0].hash, payload, forged)]
    assert security.verify_chain(rewritten) == []
    assert forged != anchored


def test_row_hash_names_changed_columns_without_values() -> None:
    before_hash, before_cols = security.row_hash(("unit-1", "Квартира А", 700000, None, b"\x01"))
    after_hash, after_cols = security.row_hash(("unit-1", "Квартира Б", 700000, None, b"\x01"))
    assert before_hash != after_hash
    assert len(before_hash) == 32
    assert len(before_cols) == 5 * 8
    assert "Квартира" not in before_cols
    found = security.diff_rows({"k1": (before_hash, before_cols), "k2": ("0" * 32, "0" * 40)},
                               iter([("k1", after_hash, after_cols), ("k3", after_hash, after_cols)]),
                               ["id", "name", "amount", "note", "blob"])
    assert {(f.kind, f.key, f.columns) for f in found} == {("changed", "k1", ("name",)), ("added", "k3", ()), ("removed", "k2", ())}


def test_row_hash_distinguishes_types() -> None:
    assert security.row_hash((1,))[0] != security.row_hash(("1",))[0]
    assert security.row_hash((1.0,))[0] != security.row_hash((1,))[0]
    assert security.row_hash((None,))[0] != security.row_hash(("",))[0]


def test_table_digest_and_root() -> None:
    a, b = security.TableDigest(), security.TableDigest()
    a.add("k1", "1" * 32)
    a.add("k2", "2" * 32)
    b.add("k1", "1" * 32)
    b.add("k2", "3" * 32)
    assert a.hexdigest() != b.hexdigest()
    assert a.rows == 2
    assert security.root({"t": a.hexdigest()}, "s1") != security.root({"t": a.hexdigest()}, "s2")
    assert security.root({"a": "x", "b": "y"}, "s") == security.root({"b": "y", "a": "x"}, "s")


def test_audit_digest_order_matters() -> None:
    assert security.audit_digest([(1, "a"), (2, "b")]) != security.audit_digest([(2, "b"), (1, "a")])


@pytest.mark.parametrize("code", ["integrity_change", "integrity_schema", "journal_gap", "journal_link", "journal_hash",
                                  "anchor_mismatch", "audit_changed", "index_changed", "integrity_reason"])
def test_integrity_error_codes_are_data_in_two_languages(code: str) -> None:
    entry = security.ERRORS[code]
    assert entry["ru"]
    assert entry["uk"]
    assert entry["what_to_do_ru"]
    assert entry["what_to_do_uk"]

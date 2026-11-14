# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Откат цепочки по журналу, тишина после восстановления, неизменяемость в облаке (решение 333 пп. 4, 5, 7)."""

from __future__ import annotations

from datetime import datetime
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from homensai_security import backup_chain as chain
from homensai_security import restore_policy as policy

VEC = json.loads((Path(__file__).resolve().parents[1] / "spec" / "vectors" / "chain.json").read_text(encoding="utf-8"))
KNOWN = {VEC["signer"]: chain.public_raw(Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VEC["signing_seed_hex"])))}


def test_last_trusted() -> None:
    texts = [m["text"] for m in VEC["manifests"]]
    assert chain.last_trusted(texts, KNOWN) == 2
    assert chain.last_trusted([texts[0], VEC["tampered"]["text"]], KNOWN) == 1
    assert chain.last_trusted([VEC["tampered"]["text"]], KNOWN) == 0
    assert chain.last_trusted([], KNOWN) == 0


def test_stale_after_restore() -> None:
    restored = datetime(2026, 11, 14, 10, 0)
    pending = [("old-invoice", datetime(2026, 10, 31)), ("between", datetime(2026, 11, 5)), ("new", datetime(2026, 11, 14, 11, 0))]
    assert policy.stale_after_restore(pending, restored) == ["old-invoice", "between"]


def test_object_lock() -> None:
    assert policy.object_lock_problem(400, 365) is None
    assert "короче" in (policy.object_lock_problem(30, 365) or "")
    assert policy.object_lock_problem(0, 14) is not None
    assert policy.object_lock_problem(2000, 365) is not None

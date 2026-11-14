# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ключ хозяйства для копий (перенос Rent app/archive/keys.py): вектора identity.json и envelope.json, новая пара, конверт."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homensai_security import backup_keys as keys
from homensai_security.errors import SecurityError

VEC = Path(__file__).resolve().parents[1] / "spec" / "vectors"
IDENTITY = json.loads((VEC / "identity.json").read_text(encoding="utf-8"))
ENVELOPE = json.loads((VEC / "envelope.json").read_text(encoding="utf-8"))


@pytest.mark.parametrize("case", IDENTITY["cases"], ids=lambda c: c["name"])
def test_identity_vectors(case: dict) -> None:
    raw = keys.unwrap_identity(case["wrapped"], case["password"], public=case["public"])
    assert raw.hex() == case["private_hex"]
    assert keys.public_of_raw(raw) == case["public"]
    assert keys.fingerprint_of(case["public"]) == case["fingerprint"]
    for bad in case["errors"]:
        with pytest.raises((keys.BackupKeyError, SecurityError)) as info:
            keys.unwrap_identity(case["wrapped"], bad["password"], public=case["public"])
        assert info.value.code == bad["code"]


def test_envelope_vectors_open_by_password_recovery_and_shares() -> None:
    keyed = ENVELOPE["keyed"]
    envelope = keys.envelope_from_comment(keyed["comment"].encode())
    assert envelope is not None
    for case in keyed["open"]:
        assert keys.open_password(envelope, case["input"].encode()) == case["secret"].encode()  # секрет — пароль ZIP (base64-текст)
    for bad in keyed["errors"]:
        with pytest.raises((keys.BackupKeyError, SecurityError)) as info:
            keys.open_password(envelope, bad["input"].encode())
        assert info.value.code == bad["code"]
    assert keys.envelope_from_comment(ENVELOPE["none"]["comment"].encode()) == {"v": 1, "mode": "none"}


def test_new_identity_round_trip_and_seal() -> None:
    public, fingerprint, wrapped = keys.new_identity("Новый-пароль-копий-2026!")
    assert fingerprint.startswith("HR1-")
    raw = keys.unwrap_identity(wrapped, "Новый-пароль-копий-2026!", public=public)
    assert keys.public_of_raw(raw) == public
    secret, comment = keys.seal("custom", public, wrapped)
    envelope = keys.envelope_from_comment(comment)
    assert envelope is not None
    assert keys.open_password(envelope, "Новый-пароль-копий-2026!".encode()) == secret
    with pytest.raises(keys.BackupKeyError) as info:
        keys.unwrap_identity(wrapped, "другой", public=public)
    assert info.value.code == "bad_password"

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Шифрование полей `v1gcm`, слепой индекс `bi2`, KCV и прежний `v0stub` — по векторам spec/vectors/field-aead.json."""

from __future__ import annotations

import json
from pathlib import Path

import pytest

from homensai_security import fields

VECTORS = json.loads((Path(__file__).resolve().parents[1] / "spec" / "vectors" / "field-aead.json").read_text(encoding="utf-8"))
KEYS = fields.FieldKeys(VECTORS["base_key_text"].encode())


def _ctx(data: dict[str, str] | None) -> fields.FieldContext | None:
    if data is None:
        return None
    return fields.FieldContext(data.get("account_id", ""), data.get("table", ""), data.get("column", ""), data.get("row_id", ""))


def test_gcm_key_and_salt_match_vectors() -> None:
    assert VECTORS["hkdf_salt"].encode() == KEYS.salt
    assert KEYS.derive(b"gcm").hex() == VECTORS["gcm_key_hex"]


@pytest.mark.parametrize("case", VECTORS["cases"], ids=lambda c: c["name"])
def test_seal_matches_vector_byte_for_byte_and_opens(case: dict[str, object]) -> None:
    ctx = _ctx(case["context"])  # type: ignore[arg-type]
    blob = bytes.fromhex(str(case["blob_hex"]))
    assert fields.aad(KEYS, ctx).hex() == case["aad_hex"]
    nonce = blob[len(fields.PREFIX):len(fields.PREFIX) + fields.NONCE_BYTES]
    assert fields.seal(KEYS, str(case["plaintext"]), ctx, nonce=nonce) == blob
    assert fields.unseal(KEYS, blob, ctx) == case["plaintext"]


@pytest.mark.parametrize("bad", VECTORS["errors"], ids=lambda e: e["case"])
def test_moved_ciphertext_does_not_open(bad: dict[str, object]) -> None:
    case = next(c for c in VECTORS["cases"] if c["name"] == bad["case"])
    with pytest.raises(fields.FieldCryptoError):
        fields.unseal(KEYS, bytes.fromhex(case["blob_hex"]), _ctx(bad["context"]))  # type: ignore[arg-type]


def test_other_key_truncated_and_unknown_format_fail() -> None:
    case = VECTORS["cases"][0]
    blob = bytes.fromhex(case["blob_hex"])
    other = fields.FieldKeys(b"another-fictional-key-for-tests-0123456789-ABCDEFG")
    with pytest.raises(fields.FieldCryptoError):
        fields.unseal(other, blob, _ctx(case["context"]))
    with pytest.raises(fields.FieldCryptoError, match="обрезан"):
        fields.unseal(KEYS, fields.PREFIX + b"\x00" * 10)
    with pytest.raises(fields.FieldCryptoError, match="формат"):
        fields.unseal(KEYS, b"hfc1:xyz")


def test_random_nonce_round_trip_and_differs() -> None:
    ctx = fields.FieldContext("acc", "persons", "phone_enc", "1")
    a, b = fields.seal(KEYS, "+380 00 000-00-01", ctx), fields.seal(KEYS, "+380 00 000-00-01", ctx)
    assert a != b
    assert fields.unseal(KEYS, a, ctx) == fields.unseal(KEYS, b, ctx) == "+380 00 000-00-01"


def test_blind_index_and_kcv_match_vectors() -> None:
    for item in VECTORS["blind_index"]:
        assert fields.blind_index(KEYS, item["normalized"], _ctx(item["context"])) == item["index"]
    assert fields.key_check_value(KEYS) == VECTORS["key_check"]["kcv_hex"]
    assert fields.key_fingerprint(KEYS) == VECTORS["key_check"]["fingerprint"]
    assert fields.same_key(KEYS, VECTORS["key_check"]["kcv_hex"])
    assert not fields.same_key(KEYS, "0" * 64)


def test_legacy_v0stub_reads_only() -> None:
    legacy = VECTORS["legacy_v0stub"]
    assert fields.unseal(KEYS, bytes.fromhex(legacy["blob_hex"])) == legacy["plaintext"]
    broken = bytearray(bytes.fromhex(legacy["blob_hex"]))
    broken[-1] ^= 1
    with pytest.raises(fields.FieldCryptoError):
        fields.unseal(KEYS, bytes(broken))


def test_other_domain_is_incompatible() -> None:
    jobpilot = fields.FieldKeys(KEYS.base, domain="homensai-jobpilot")
    ctx = fields.FieldContext("acc", "t", "c", "1")
    blob = fields.seal(jobpilot, "x", ctx)
    assert fields.unseal(jobpilot, blob, ctx) == "x"
    with pytest.raises(fields.FieldCryptoError):
        fields.unseal(KEYS, blob, ctx)
    assert fields.key_check_value(jobpilot) != fields.key_check_value(KEYS)


@pytest.mark.parametrize(("key", "problem"), [("", "пустой"), ("change-me" + "x" * 40, "шаблон"), ("ab" * 30, "повторяющихся"), ("aB3dE5gH7jK9", "короче")])
def test_weak_keys_refused(key: str, problem: str) -> None:
    assert problem in (fields.weak_key_problem(key) or "")
    with pytest.raises(ValueError, match=problem):
        fields.keys_from_text(key)


def test_strong_key_accepted() -> None:
    key = "Xk3_9fQ2mZ7pL0vN4rT8yB1cD6hJ5sW-aE2gU9iO3kM"
    assert fields.weak_key_problem(key) is None
    assert fields.keys_from_text(key).base == key.encode()

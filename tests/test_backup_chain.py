# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Цепочка копий: вектора spec/vectors/chain.json (подпись, prev, отпечаток), подмена, разрыв, имена файлов, файлы ОС."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
import pytest

from homensai_security import backup_chain as chain

VEC = json.loads((Path(__file__).resolve().parents[1] / "spec" / "vectors" / "chain.json").read_text(encoding="utf-8"))
PRIVATE = Ed25519PrivateKey.from_private_bytes(bytes.fromhex(VEC["signing_seed_hex"]))
PUBLIC = chain.public_raw(PRIVATE)
KNOWN = {VEC["signer"]: PUBLIC}


def test_key_fingerprint_and_public_match_vectors() -> None:
    assert chain._b64(PUBLIC) == VEC["public_b64url"]
    assert chain.fingerprint_of(PUBLIC) == VEC["signer"]


def test_manifests_resign_byte_for_byte_and_chain_is_intact() -> None:
    texts = [m["text"] for m in VEC["manifests"]]
    for m in VEC["manifests"]:
        body, _sig = chain.parse_manifest(m["text"]) or ({}, b"")
        signed = chain.sign_manifest(PRIVATE, body)  # Ed25519 детерминирован: та же подпись
        assert signed.text == m["text"]
        assert signed.manifest_sha256 == m["manifest_sha256"]
        assert chain.manifest_name(signed.seq) == m["file"]
    assert chain.verify_sequence(texts, KNOWN) == []


def test_tampered_gap_and_broken_link_are_found() -> None:
    texts = [m["text"] for m in VEC["manifests"]]
    assert chain.signature_ok(VEC["tampered"]["text"], KNOWN) is VEC["tampered"]["signature_valid"]
    assert [p.code for p in chain.verify_sequence([VEC["tampered"]["text"]], KNOWN)] == ["chain_signature"]  # изменённый манифест №1
    assert [p.code for p in chain.verify_sequence(texts[1:], KNOWN)] == ["chain_gap", "chain_link"]
    body, _ = chain.parse_manifest(texts[1]) or ({}, b"")
    forged = chain.sign_manifest(PRIVATE, {**body, "prev": chain.ZERO})
    assert [p.code for p in chain.verify_sequence([texts[0], forged.text], KNOWN)] == ["chain_link"]
    assert not chain.signature_ok(texts[0], {})  # неизвестный ключ


def test_sign_requires_matching_signer_and_parse_rejects_garbage() -> None:
    body, _ = chain.parse_manifest(VEC["manifests"][0]["text"]) or ({}, b"")
    with pytest.raises(ValueError, match="signer"):
        chain.sign_manifest(Ed25519PrivateKey.generate(), body)
    for bad in ("", "{}", "[" * 100000, '{"manifest":[],"signature":"AA=="}', "x" * (chain.MANIFEST_LIMIT + 1)):
        assert chain.parse_manifest(bad) is None


@pytest.mark.parametrize(("name", "seq"), [("000001.json", 1), ("1234567.json", 1234567), ("2.json", None), ("0000002.json", None),
                                           ("².json", None), ("000000.json", None), ("000001.json.part", None)])
def test_manifest_names_are_strict(name: str, seq: int | None) -> None:
    assert chain.manifest_seq(name) == seq


def test_os_files() -> None:
    assert all(chain.os_file(n) for n in ("desktop.ini", "Thumbs.db", ".DS_Store", "._000001.json", ".directory", "000001.json:Zone.Identifier"))
    assert not any(chain.os_file(n) for n in ("notes.txt", "desktop.ini.json", "Thumbs.db.exe"))

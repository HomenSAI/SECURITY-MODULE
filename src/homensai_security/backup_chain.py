# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Цепочка копий «как у биткоина» без базы и файлов (MOD.extract-backups; решение 276, формат — spec/chain.md).

Источник — Rent `app/archive/chain.py`: канонический JSON, подпись Ed25519 манифеста, `prev` = SHA-256 предыдущего
манифеста, отпечаток ключа подписи `HS1-…`, строгие имена файлов `NNNNNN.json`, служебные файлы ОС (решение 294),
проверка последовательности. Где лежат манифесты, ключ подписи (DPAPI/0600) и копии — дело адаптера продукта.
Вектора — `spec/vectors/chain.json` (тест сверяет байт в байт).
"""

from __future__ import annotations

import base64
from collections.abc import Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json
import re
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat

FORMAT = "homensai-rent-chain/1"
ZERO = "0" * 64
MANIFEST_LIMIT = 64 * 1024
MANIFEST_NAME_RE = re.compile(r"[0-9]{6,}\.json")
OS_FILES = frozenset({"desktop.ini", "thumbs.db", "ehthumbs.db", "ehthumbs_vista.db", ".ds_store", ".localized", "icon\r", ".directory"})
OS_PREFIXES = ("._",)
OS_SUFFIXES = (":zone.identifier",)


def canonical(value: object) -> str:
    """Канонический JSON: ключи по алфавиту, без пробелов, UTF-8 как есть."""
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def sha256_text(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8")).hexdigest()


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: object) -> bytes:
    if not isinstance(text, str) or len(text) > 200:
        raise ValueError("bad base64")
    return base64.urlsafe_b64decode(text.encode("ascii"))


def public_raw(private: Ed25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(Encoding.Raw, PublicFormat.Raw)


def fingerprint_of(public: bytes) -> str:
    """Отпечаток ключа подписи для бумаги: «HS1-» и 16 знаков SHA-256 группами по 4."""
    digest = hashlib.sha256(b"homensai-rent/chain-key\x00" + public).hexdigest()[:16].upper()
    return "HS1-" + "-".join(digest[i:i + 4] for i in range(0, 16, 4))


def manifest_name(seq: int) -> str:
    return f"{seq:06d}.json"


def manifest_seq(name: str) -> int | None:
    """Номер копии из имени файла, только если имя ровно такое, какое пишет `manifest_name` (синонимы — посторонние)."""
    if not (name.isascii() and MANIFEST_NAME_RE.fullmatch(name)):
        return None
    seq = int(name[: -len(".json")])
    return seq if seq > 0 and manifest_name(seq) == name else None


def os_file(name: str) -> bool:
    """Служебный файл ОС (desktop.ini, Thumbs.db, .DS_Store, ._*, .directory, *:Zone.Identifier) — тихая строка, не тревога."""
    folded = name.casefold()
    return folded in OS_FILES or folded.startswith(OS_PREFIXES) or folded.endswith(OS_SUFFIXES)


@dataclass(frozen=True)
class Signed:
    seq: int
    body: dict[str, Any]
    text: str  # пишется как есть в chain/NNNNNN.json
    manifest_sha256: str  # prev следующего манифеста


def sign_manifest(private: Ed25519PrivateKey, body: Mapping[str, Any]) -> Signed:
    """Подписывает тело манифеста (поля — spec/chain.md §2; `signer` должен совпадать с ключом)."""
    data = dict(body)
    if data.get("signer") != fingerprint_of(public_raw(private)):
        raise ValueError("signer не совпадает с ключом подписи")
    signature = private.sign(canonical(data).encode("utf-8"))
    text = canonical({"manifest": data, "signature": _b64(signature)})
    return Signed(int(data["seq"]), data, text, sha256_text(text))


def parse_manifest(text: str) -> tuple[dict[str, Any], bytes] | None:
    """Тело и подпись; мусор, превышение предела, глубокая вложенность — None (не исключение)."""
    if len(text) > MANIFEST_LIMIT or len(text.encode("utf-8")) > MANIFEST_LIMIT:
        return None
    try:
        value = json.loads(text)
        body, signature = value["manifest"], _unb64(value["signature"])
    except (ValueError, KeyError, TypeError, RecursionError):
        return None
    return (body, signature) if isinstance(body, dict) else None


def signature_ok(text: str, known: Mapping[str, bytes]) -> bool:
    """Подпись верна ключом из `known` (отпечаток → открытый ключ) по полю `signer`."""
    parsed = parse_manifest(text)
    if parsed is None:
        return False
    body, signature = parsed
    public = known.get(str(body.get("signer")))
    if public is None:
        return False
    try:
        Ed25519PublicKey.from_public_bytes(public).verify(signature, canonical(body).encode("utf-8"))
    except (InvalidSignature, ValueError):
        return False
    return True


@dataclass(frozen=True)
class ChainProblem:
    code: str  # chain_gap | chain_link | chain_signature (коды spec/error-codes.json)
    seq: int


def verify_sequence(texts: Sequence[str], known: Mapping[str, bytes]) -> list[ChainProblem]:
    """Проверка цепочки по порядку: номера подряд с 1, подпись, `prev` = SHA-256 предыдущего текста. Пусто — цепочка цела."""
    problems: list[ChainProblem] = []
    prev, expected = ZERO, 1
    for text in texts:
        parsed = parse_manifest(text)
        seq = int(parsed[0].get("seq", 0)) if parsed and isinstance(parsed[0].get("seq"), int) else expected
        if seq != expected:
            problems.append(ChainProblem("chain_gap", expected))
        if not signature_ok(text, known):
            problems.append(ChainProblem("chain_signature", seq))
        elif parsed and parsed[0].get("prev") != prev:
            problems.append(ChainProblem("chain_link", seq))
        prev, expected = sha256_text(text), seq + 1
    return problems

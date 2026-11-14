# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Запись ключа восстановления и частей ключа для бумаги (28.10-279 п. 2, 28.10-284 п. 2).

- Ключ восстановления: 128 случайных бит (`secrets`) + 16 бит контрольной суммы SHA-256 → Crockford Base32, 6 групп по 5
  знаков: `RK1-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX-XXXXX`. Алфавит без I, L, O, U: при вводе O читается как 0, I и L — как 1;
  регистр, пробелы и дефисы не важны. Контрольная сумма ловит опечатку до попытки расшифровки (как коды Auto VPN).
- Часть ключа (Шамир «2 из 3»): номер части 1–3, метка набора (16 бит), 16 байт части, 16 бит контрольной суммы →
  `RS1-N-XXXXX-…` (7 групп). Метка новых наборов — случайная (`new_set_label`, ревью DR-recovery №1); у наборов, выданных
  раньше, метка — 16 бит SHA-256 от ключа (`set_tag`), такие части читаются и собираются как прежде.
"""

from __future__ import annotations

import hashlib
import re
import secrets

from homensai_security.errors import SecurityError

ALPHABET = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"  # Crockford Base32
_VALUE = {ch: i for i, ch in enumerate(ALPHABET)}
_CONFUSABLE = str.maketrans({"O": "0", "I": "1", "L": "1"})
KEY_PREFIX = "RK1"
SHARE_PREFIX = "RS1"
KEY_BYTES = 16
KEY_GROUPS = 6
SHARE_GROUPS = 7
GROUP = 5
_KEY_SUM = b"homensai-security/rk/1"
_SHARE_SUM = b"homensai-security/rs/1"
_SHARE_TAG = b"homensai-security/rs-tag/1"


def _encode(data: bytes, chars: int) -> str:
    bits = int.from_bytes(data, "big") << (chars * 5 - len(data) * 8)
    return "".join(ALPHABET[(bits >> (5 * (chars - 1 - i))) & 31] for i in range(chars))


def _decode(text: str, size: int) -> bytes:
    bits = 0
    for ch in text:
        if ch not in _VALUE:
            raise SecurityError("recovery_format")
        bits = (bits << 5) | _VALUE[ch]
    spare = len(text) * 5 - size * 8
    if spare < 0 or bits & ((1 << spare) - 1):
        raise SecurityError("recovery_format")
    return (bits >> spare).to_bytes(size, "big")


def _groups(body: str) -> str:
    return "-".join(body[i : i + GROUP] for i in range(0, len(body), GROUP))


def normalize(text: str) -> str:
    """Верхний регистр, без пробелов и дефисов, O→0, I/L→1."""
    return re.sub(r"[\s\-_.,;:]+", "", text.upper()).translate(_CONFUSABLE)


def key_checksum(key: bytes) -> bytes:
    return hashlib.sha256(_KEY_SUM + key).digest()[:2]


def format_key(key: bytes) -> str:
    if len(key) != KEY_BYTES:
        raise SecurityError("recovery_format")
    return KEY_PREFIX + "-" + _groups(_encode(key + key_checksum(key), KEY_GROUPS * GROUP))


def new_key() -> bytes:
    return secrets.token_bytes(KEY_BYTES)


def parse_key(text: str) -> bytes:
    """Ключ (16 байт) из записи; неверный вид — recovery_format, опечатка — recovery_checksum."""
    flat = normalize(text)
    if not flat.startswith(KEY_PREFIX) or len(flat) != len(KEY_PREFIX) + KEY_GROUPS * GROUP:
        raise SecurityError("recovery_format")
    raw = _decode(flat[len(KEY_PREFIX) :], KEY_BYTES + 2)
    key, checksum = raw[:KEY_BYTES], raw[KEY_BYTES:]
    if key_checksum(key) != checksum:
        raise SecurityError("recovery_checksum")
    return key


SET_LABEL_BYTES = 2


def set_tag(key: bytes) -> bytes:
    """Метка наборов, выданных до ревью DR-recovery №1: 16 бит SHA-256 от ключа с доменным разделителем.

    Новые наборы её не получают: любая метка, вычисленная из ключа, сообщает держателю одной части 16 бит о ключе (стойкость
    128 → 112 бит), а 28.10-284 обещает, что одна часть не даёт ничего. Функция остаётся только для описания старого формата
    и для тестов совместимости; при сборке частей метку не проверяют (см. `shamir.combine`)."""
    return hashlib.sha256(_SHARE_TAG + key).digest()[:SET_LABEL_BYTES]


def new_set_label() -> bytes:
    """Метка нового набора частей (ревью DR-recovery №1): 16 случайных бит из `secrets`, своя у каждого выпуска набора.

    Почему не из ключа. Детерминированная функция ключа на бумаге рядом с частью — это всегда сведения о ключе: держатель
    одной части сужает перебор на 2^16, как бы ни была устроена функция (усечённый хэш, HKDF, HMAC). Метка, независимая
    от ключа и от многочлена Шамира, не сообщает ничего, а смешение частей ловит лучше: два выпуска одного ключа получают
    разные метки, тогда как метка из ключа у них совпадала бы. Проверку собранного ключа делает не метка, а расшифровка
    (ChaCha20-Poly1305 с AAD) — чужой ключ молча не принимается. На ПК метка не хранится: формат части и базы прежний."""
    return secrets.token_bytes(SET_LABEL_BYTES)


def format_share(index: int, tag: bytes, share: bytes) -> str:
    if not 1 <= index <= 3 or len(tag) != SET_LABEL_BYTES or len(share) != KEY_BYTES:
        raise SecurityError("recovery_format")
    payload = bytes([index]) + tag + share
    body = _encode(payload + hashlib.sha256(_SHARE_SUM + payload).digest()[:2], SHARE_GROUPS * GROUP)
    return f"{SHARE_PREFIX}-{index}-" + _groups(body)


SHARE_RE = re.compile(rf"{SHARE_PREFIX}([1-3])([{ALPHABET}]{{{SHARE_GROUPS * GROUP}}})")


def parse_share(index_text: str, body: str) -> tuple[int, bytes, bytes]:
    """(номер, метка набора, 16 байт части); опечатка — recovery_checksum."""
    raw = _decode(body, 1 + 2 + KEY_BYTES + 2)
    payload, checksum = raw[:-2], raw[-2:]
    if hashlib.sha256(_SHARE_SUM + payload).digest()[:2] != checksum:
        raise SecurityError("recovery_checksum")
    index = payload[0]
    if str(index) != index_text:
        raise SecurityError("recovery_checksum")
    return index, payload[1:3], payload[3:]


def find_shares(text: str) -> list[tuple[int, bytes, bytes]]:
    """Все части ключа в тексте (через пробел, перенос строки и т. п.)."""
    return [parse_share(index, body) for index, body in SHARE_RE.findall(normalize(text))]


def looks_like_recovery(text: str) -> bool:
    flat = normalize(text)
    return flat.startswith((KEY_PREFIX, SHARE_PREFIX))

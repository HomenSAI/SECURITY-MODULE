# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Шифрование полей базы `v1gcm`, слепой индекс `bi2`, контрольное значение ключа (MOD.extract-fields, решения 286, 332).

Формат — `spec/field-encryption.md` (источник: Rent `app/platform/sealing.py`, `key_check.py`); проверка — вектора
`spec/vectors/field-aead.json`. Модуль не читает окружение и не знает таблиц продукта: базовый ключ, домен и контекст поля
передаёт вызывающий (`FieldKeys`, `FieldContext`). Значения по умолчанию домена — как в Rent, поэтому шифротексты Rent
открываются этим кодом байт в байт. Другой продукт задаёт свой домен — его шифротексты с Rent несовместимы (так и нужно).

Криптопримитивы — pyca/cryptography: HKDF-SHA256 (RFC 5869), AES-256-GCM, HMAC-SHA256.
"""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import hmac
import secrets

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

PREFIX = b"v1gcm|"
LEGACY_PREFIX = b"v0stub|"  # прежний формат Rent, только чтение
INDEX_PREFIX = "bi2:"
NONCE_BYTES = 12
TAG_BYTES = 16
LEGACY_NONCE_BYTES = 16
LEGACY_TAG_BYTES = 32
MIN_KEY_CHARS = 43  # base64-запись 256-битного ключа
MIN_KEY_DISTINCT_CHARS = 10
_PLACEHOLDERS = (  # как в Rent `sealing._PLACEHOLDER_KEY_PARTS`
    "change-me", "changeme", "change_me", "password", "passw0rd", "placeholder", "example",
    "your-key", "your_key", "yourkey", "secret", "fictional", "demo-only",
)


class FieldCryptoError(ValueError):
    """Шифротекст повреждён, перенесён в другой контекст или открыт другим ключом."""


@dataclass(frozen=True)
class FieldContext:
    """Где лежит значение: перенос шифротекста в другое хозяйство, таблицу, колонку или строку ломает тег GCM."""

    account_id: str = ""
    table: str = ""
    column: str = ""
    row_id: str = ""


@dataclass(frozen=True)
class FieldKeys:
    """Базовый ключ (байты строки ключа как есть) и домен продукта. Rent: домен `homensai-rent`."""

    base: bytes
    domain: str = "homensai-rent"

    @property
    def salt(self) -> bytes:
        return f"{self.domain}/v1".encode()

    def derive(self, info: bytes) -> bytes:
        """HKDF-SHA256(ikm=base, salt=«домен/v1», info, 32 байта)."""
        return HKDF(algorithm=hashes.SHA256(), length=32, salt=self.salt, info=info).derive(self.base)


def keys_from_text(key_text: str, domain: str = "homensai-rent") -> FieldKeys:
    """Ключ из строки настройки (переменная окружения и т. п.): UTF-8 байты строки как есть; слабый ключ — ValueError."""
    problem = weak_key_problem(key_text)
    if problem is not None:
        raise ValueError(problem)
    return FieldKeys(key_text.encode(), domain)


def weak_key_problem(key_text: str) -> str | None:
    """Почему ключ полей не подходит для рабочей базы (None — подходит); сам ключ в текст не попадает. Правила — как в Rent."""
    value = key_text.strip()
    if not value:
        return "ключ пустой"
    lowered = value.lower()
    if any(part in lowered for part in _PLACEHOLDERS):
        return "ключ похож на шаблон или пример (change-me, password и т. п.)"
    if len(set(value)) < MIN_KEY_DISTINCT_CHARS:
        return "ключ состоит из повторяющихся знаков"
    if len(value) < MIN_KEY_CHARS:
        return f"ключ короче {MIN_KEY_CHARS} знаков (нужно не менее 256 бит случайных данных)"
    return None


def aad(keys: FieldKeys, field: FieldContext | None) -> bytes:
    """Связанные данные GCM: «домен/v1\\0» ‖ account\\0table\\0column\\0row (без контекста — пустые части)."""
    f = field or FieldContext()
    return keys.salt + b"\x00" + "\x00".join((f.account_id, f.table, f.column, str(f.row_id))).encode()


def seal(keys: FieldKeys, plaintext: str, field: FieldContext | None = None, *, nonce: bytes | None = None) -> bytes:
    """Шифрует значение в конверт `v1gcm|nonce‖AES-256-GCM`. `nonce` — только для тест-векторов (иначе случайный)."""
    nonce = secrets.token_bytes(NONCE_BYTES) if nonce is None else nonce
    if len(nonce) != NONCE_BYTES:
        raise ValueError("nonce — 12 байт")
    return PREFIX + nonce + AESGCM(keys.derive(b"gcm")).encrypt(nonce, plaintext.encode(), aad(keys, field))


def unseal(keys: FieldKeys, blob: bytes, field: FieldContext | None = None) -> str:
    """Открывает `v1gcm` (и прежний `v0stub` Rent, только чтение). Неверный тег, ключ или контекст — FieldCryptoError."""
    if blob.startswith(LEGACY_PREFIX):
        return unseal_legacy(keys.base, blob)
    if not blob.startswith(PREFIX):
        raise FieldCryptoError("неизвестный формат шифротекста")
    body = blob[len(PREFIX):]
    if len(body) < NONCE_BYTES + TAG_BYTES:
        raise FieldCryptoError("шифротекст обрезан")
    try:
        return AESGCM(keys.derive(b"gcm")).decrypt(body[:NONCE_BYTES], body[NONCE_BYTES:], aad(keys, field)).decode()
    except InvalidTag as exc:
        raise FieldCryptoError("шифротекст не открывается этим ключом в этом месте") from exc


def blind_index(keys: FieldKeys, normalized: str, field: FieldContext | None = None) -> str:
    """Слепой индекс `bi2:` для поиска совпадений внутри колонки хозяйства (строка в ключ не входит).

    Нормализацию значения (телефон, номер авто и т. п.) делает продукт до вызова."""
    f = field or FieldContext()
    key = keys.derive(b"bidx2\x00" + "\x00".join((f.account_id, f.table, f.column)).encode())
    return INDEX_PREFIX + hmac.new(key, normalized.encode(), hashlib.sha256).hexdigest()


def key_check_value(keys: FieldKeys) -> str:
    """Контрольное значение ключа (hex): хранится в базе, другой ключ — отказ запуска (Rent 28.10-230)."""
    return hmac.new(keys.derive(b"kcv"), f"{keys.domain}/kcv/v1".encode(), hashlib.sha256).hexdigest()


def key_fingerprint(keys: FieldKeys) -> str:
    """Короткий отпечаток ключа для экрана и журнала — первые 8 знаков KCV (сам ключ не показывается)."""
    return key_check_value(keys)[:8]


def same_key(keys: FieldKeys, stored_kcv: str) -> bool:
    """Совпадает ли ключ с сохранённым KCV (сравнение постоянного времени)."""
    return hmac.compare_digest(key_check_value(keys), stored_kcv)


def unseal_legacy(base: bytes, blob: bytes) -> str:
    """Прежний формат Rent `v0stub` (HMAC-поток, без контекста) — только чтение для перешифровки в `v1gcm`."""
    if not blob.startswith(LEGACY_PREFIX):
        raise FieldCryptoError("не v0stub")
    body = blob[len(LEGACY_PREFIX):]
    if len(body) < LEGACY_NONCE_BYTES + LEGACY_TAG_BYTES:
        raise FieldCryptoError("шифротекст обрезан")
    nonce, ct, tag = body[:LEGACY_NONCE_BYTES], body[LEGACY_NONCE_BYTES:-LEGACY_TAG_BYTES], body[-LEGACY_TAG_BYTES:]
    k_enc = hmac.new(base, b"homensai-rent/enc", hashlib.sha256).digest()
    k_mac = hmac.new(base, b"homensai-rent/mac", hashlib.sha256).digest()
    if not hmac.compare_digest(hmac.new(k_mac, nonce + ct, hashlib.sha256).digest(), tag):
        raise FieldCryptoError("шифротекст v0stub повреждён или ключ другой")
    stream = b""
    counter = 0
    while len(stream) < len(ct):
        stream += hmac.new(k_enc, nonce + counter.to_bytes(8, "big"), hashlib.sha256).digest()
        counter += 1
    return bytes(a ^ b for a, b in zip(ct, stream, strict=False)).decode()

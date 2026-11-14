# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Google Authenticator: одноразовые коды TOTP (RFC 6238 поверх HOTP RFC 4226) — решение владельца 28.10-282 п. 4.

Что выбрано: TOTP SHA-1, 6 цифр, шаг 30 секунд — именно эти параметры понимают все приложения (Google Authenticator,
Microsoft Authenticator, Aegis, NordPass); другие значения часть приложений молча игнорирует и показывает неверные коды.
Секрет — 20 случайных байт (160 бит, как рекомендует RFC 4226 §4), показывается один раз QR-кодом `otpauth://` и текстом.
HMAC считает pyca/cryptography; сам алгоритм — 10 строк из RFC и проверяется тест-векторами RFC 4226 (приложение D) и
RFC 6238 (приложение B).

Проверка допускает сдвиг часов на один шаг в обе стороны (±30 с, RFC 6238 §5.2) и не принимает уже использованный шаг
повторно: вызывающий хранит последний принятый шаг (`last_step`). Для копий код не используется (269/282): он не может
ничего расшифровать."""

from __future__ import annotations

import base64
import secrets
import struct
from urllib.parse import quote, urlencode

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives import hmac as crypto_hmac

from homensai_security.errors import SecurityError

DIGITS = 6
PERIOD = 30
WINDOW = 1
SECRET_BYTES = 20
_HASHES: dict[str, type[hashes.SHA1 | hashes.SHA256 | hashes.SHA512]] = {"sha1": hashes.SHA1, "sha256": hashes.SHA256, "sha512": hashes.SHA512}


def new_secret() -> bytes:
    return secrets.token_bytes(SECRET_BYTES)


def secret_text(secret: bytes) -> str:
    """Base32 без «=», группами по 4 — для ручного ввода в приложение."""
    raw = base64.b32encode(secret).decode("ascii").rstrip("=")
    return " ".join(raw[i : i + 4] for i in range(0, len(raw), 4))


def parse_secret(text: str) -> bytes:
    flat = "".join(text.split()).upper()
    try:
        secret = base64.b32decode(flat + "=" * (-len(flat) % 8))
    except ValueError as exc:
        raise SecurityError("totp_format") from exc
    if len(secret) < 16:
        raise SecurityError("totp_format")
    return secret


def hotp(secret: bytes, counter: int, *, digits: int = DIGITS, algorithm: str = "sha1") -> str:
    """HOTP (RFC 4226 §5.3): HMAC от 8-байтового счётчика, динамическое усечение, остаток от 10^digits."""
    mac = crypto_hmac.HMAC(secret, _HASHES[algorithm]())
    mac.update(struct.pack(">Q", counter))
    digest = mac.finalize()
    offset = digest[-1] & 0x0F
    code = int.from_bytes(digest[offset : offset + 4], "big") & 0x7FFFFFFF
    return str(code % 10**digits).zfill(digits)


def step(now: int, period: int = PERIOD) -> int:
    return now // period


def totp(secret: bytes, now: int, *, digits: int = DIGITS, period: int = PERIOD, algorithm: str = "sha1") -> str:
    return hotp(secret, step(now, period), digits=digits, algorithm=algorithm)


def check_code(code: str) -> str:
    flat = "".join(code.split())
    if len(flat) != DIGITS or not flat.isascii() or not flat.isdigit():
        raise SecurityError("totp_format")
    return flat


def verify(secret: bytes, code: str, now: int, *, last_step: int = -1) -> int | None:
    """Шаг, которому соответствует код (в окне ±1 шаг и строго после `last_step`), или None. Сравнение — постоянное время."""
    try:
        flat = check_code(code)
    except SecurityError:
        return None
    current = step(now)
    found: int | None = None
    for candidate in range(current - WINDOW, current + WINDOW + 1):
        if candidate > last_step and secrets.compare_digest(hotp(secret, candidate), flat):
            found = candidate
    return found


def otpauth_uri(secret: bytes, *, account: str, issuer: str) -> str:
    """Ссылка для QR (формат Key Uri Format Google Authenticator): в ней секрет — QR показывается один раз."""
    label = quote(f"{issuer}:{account}", safe="")
    raw = base64.b32encode(secret).decode("ascii").rstrip("=")
    query = urlencode({"secret": raw, "issuer": issuer, "algorithm": "SHA1", "digits": DIGITS, "period": PERIOD})
    return f"otpauth://totp/{label}?{query}"

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Argon2id для паролей и PIN (28.10-279 п. 3).

Что выбрано: Argon2id (RFC 9106), реализация pyca/cryptography (OpenSSL 3.2+). Параметры по умолчанию m = 64 МиБ, t = 3,
p = 4 — сильнее минимума OWASP Password Storage Cheat Sheet (m = 19 МиБ, t = 2, p = 1). Запись — строка PHC
`$argon2id$v=19$m=…,t=…,p=…$соль$хэш` (как у argon2-cffi и libsodium): параметры лежат рядом с хэшем, поэтому их можно
усилить позже, а прежние записи перешифровать при следующем успешном вводе (`needs_rehash`).

Параметры из чужой записи ограничены сверху: подложенная запись не заставит выделить гигабайты памяти.
"""

from __future__ import annotations

import base64
import hmac
import re
import secrets
import unicodedata

from cryptography.hazmat.primitives.kdf.argon2 import Argon2id

from homensai_security.errors import SecurityError

DEFAULT = {"m": 65536, "t": 3, "p": 4}
OWASP_MIN = {"m": 19456, "t": 2, "p": 1}
LIMITS = {"m": (OWASP_MIN["m"], 1024 * 1024), "t": (1, 32), "p": (1, 16)}
SALT_BYTES = 16
HASH_BYTES = 32
_PHC = re.compile(r"^\$argon2id\$v=19\$m=(\d{1,8}),t=(\d{1,3}),p=(\d{1,3})\$([A-Za-z0-9+/]{22,88})\$([A-Za-z0-9+/]{43,88})$")


def _b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii").rstrip("=")


def _unb64(text: str) -> bytes:
    return base64.b64decode(text + "=" * (-len(text) % 4))


def check_params(m: int, t: int, p: int) -> None:
    for name, value in (("m", m), ("t", t), ("p", p)):
        low, high = LIMITS[name]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise SecurityError("kdf_params")
    if m < 8 * p:
        raise SecurityError("kdf_params")


def derive(secret: bytes, salt: bytes, m: int, t: int, p: int, length: int = HASH_BYTES) -> bytes:
    """Производный ключ Argon2id с проверкой границ параметров."""
    check_params(m, t, p)
    return Argon2id(salt=salt, length=length, iterations=t, lanes=p, memory_cost=m).derive(secret)


def _text(password: str) -> bytes:
    return unicodedata.normalize("NFKC", password).encode("utf-8")


def hash_secret(password: str, *, m: int = DEFAULT["m"], t: int = DEFAULT["t"], p: int = DEFAULT["p"]) -> str:
    """Запись PHC для пароля или PIN с новой случайной солью; сам пароль не сохраняется."""
    salt = secrets.token_bytes(SALT_BYTES)
    return f"$argon2id$v=19$m={m},t={t},p={p}${_b64(salt)}${_b64(derive(_text(password), salt, m, t, p))}"


def params(stored: str) -> dict[str, int]:
    match = _PHC.match(stored)
    if not match:
        raise SecurityError("kdf_params")
    return {"m": int(match.group(1)), "t": int(match.group(2)), "p": int(match.group(3))}


def verify_secret(password: str, stored: str) -> bool:
    """Пароль подходит к записи PHC; сравнение за постоянное время. Повреждённая запись — False (и kdf_params в логах вызывающего)."""
    match = _PHC.match(stored)
    if not match or len(password) > 1024:
        return False
    m, t, p = int(match.group(1)), int(match.group(2)), int(match.group(3))
    try:
        expected = _unb64(match.group(5))
        derived = derive(_text(password), _unb64(match.group(4)), m, t, p, len(expected))
    except (SecurityError, ValueError):
        return False
    return hmac.compare_digest(derived, expected)


def needs_rehash(stored: str) -> bool:
    """Запись слабее текущих параметров по умолчанию — перешифровать при следующем успешном вводе."""
    try:
        current = params(stored)
    except SecurityError:
        return True
    return any(current[name] < DEFAULT[name] for name in ("m", "t"))

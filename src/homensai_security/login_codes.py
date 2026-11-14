# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Коды восстановления входа — 10 одноразовых кодов, как у GitHub (решение владельца 28.10-284 п. 1).

Каждый код заменяет второй фактор (ключ или Google Authenticator) один раз. Новый набор отменяет прежний. Коды
показываются один раз (и печатаются на аварийном листе, если лист выдают вместе с новым набором); на ПК хранятся только
отпечатки.

Почему так: код — 125 случайных бит (`secrets`), 25 знаков Crockford Base32 группами по 5, как ключ восстановления копий
(`codes`): без I, L, O, U, регистр, пробелы и дефисы не важны. При энтропии от 112 бит NIST SP 800-63B §5.1.2.2 разрешает
хранить секрет обычной односторонней функцией: перебор 2^125 невозможен, поэтому отпечаток — SHA-256 с разделителем домена
и номером набора, а не медленный Argon2id (10 проверок Argon2id на каждый ввод только замедлили бы вход без выигрыша)."""

from __future__ import annotations

import hashlib
import re
import secrets

from homensai_security.codes import ALPHABET, normalize
from homensai_security.errors import SecurityError

COUNT = 10
GROUPS = 5
GROUP = 5
CHARS = GROUPS * GROUP  # 25 знаков × 5 бит = 125 бит
_DOMAIN = b"homensai-security/login-code/1\x00"
_FLAT = re.compile(rf"^[{ALPHABET}]{{{CHARS}}}$")


def _format(flat: str) -> str:
    return "-".join(flat[i : i + GROUP] for i in range(0, CHARS, GROUP))


def new_codes(count: int = COUNT) -> list[str]:
    """Новый набор кодов (только для показа один раз); повторов внутри набора нет."""
    found: list[str] = []
    while len(found) < count:
        code = _format("".join(secrets.choice(ALPHABET) for _ in range(CHARS)))
        if code not in found:
            found.append(code)
    return found


def flat(text: str) -> str:
    """Код без дефисов и пробелов; не похоже на код — SecurityError('login_code_format')."""
    value = normalize(text)
    if not _FLAT.match(value):
        raise SecurityError("login_code_format")
    return value


def looks_like_code(text: str) -> bool:
    return bool(_FLAT.match(normalize(text)))


def code_hash(text: str, set_id: str) -> str:
    """Отпечаток кода для хранения и поиска: SHA-256(домен ‖ набор ‖ код), 64 hex-знака."""
    return hashlib.sha256(_DOMAIN + set_id.encode("utf-8") + b"\x00" + flat(text).encode("ascii")).hexdigest()


def new_set_id() -> str:
    return secrets.token_hex(8)

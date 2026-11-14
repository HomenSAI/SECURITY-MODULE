# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Публичный интерфейс модуля безопасности (28.10-286 п. 6): чистые функции без базы и контекста.

Ключ восстановления (28.10-279 п. 2), его части «2 из 3» (28.10-284 п. 2), запечатывание на ключ восстановления,
Argon2id для паролей и PIN (28.10-279 п. 3), аварийный лист (28.10-279 п. 1), коды ошибок как данные; PIN важных действий,
режимы «Офис»/«Дом», срок и блокировка экрана (28.10-272), уровни 0–5 (28.10-278), рекомендации NordVPN/ESET (28.10-285)."""

from __future__ import annotations

from dataclasses import dataclass
from pathlib import Path

from homensai_security import access, codes, fields, help, kdf, levels, licensing, recommendations, recovery, shamir, sheet, training, web, wizard
from homensai_security.actions import (
    ACTION_TITLES,
    ACTIONS,
    MODE_TITLES,
    MODES,
    PIN_LOCK_AFTER,
    PIN_PAUSE_SECONDS,
    TTL_CHOICES,
    TTL_TITLES,
    Policy,
    action_title,
    check_pin,
    deadline,
    expired,
    hash_pin,
    lowering,
    needs_risk_ack,
    pin_failure,
    validate_policy,
    verify_pin,
)
from homensai_security.errors import ERRORS, SecurityError
from homensai_security.fields import FieldContext, FieldCryptoError, FieldKeys
from homensai_security.integrity import ZERO as JOURNAL_ZERO
from homensai_security.integrity import Entry as JournalEntry
from homensai_security.integrity import Finding as IntegrityFinding
from homensai_security.integrity import Problem as JournalProblem
from homensai_security.integrity import TableDigest, audit_digest, diff_rows, root, row_hash, row_key, schema_digest, verify_chain
from homensai_security.integrity import canonical as journal_canonical
from homensai_security.integrity import link as journal_link
from homensai_security.levels import LEVEL_TITLES, RECOMMENDED_LEVEL, LevelFacts, Measure, level, level_measures
from homensai_security.product import RENT as RENT_PRODUCT
from homensai_security.product import Product, configure
from homensai_security.recommendations import (
    CODES as RECOMMENDATION_CODES,
)
from homensai_security.recommendations import (
    DEFER_DAYS,
    Recommendation,
    recommendation,
    recommendation_state,
    visible_recommendations,
)
from homensai_security.sheet import SheetData, sheet_lines

__all__ = [
    "ACTIONS",
    "ACTION_TITLES",
    "DEFER_DAYS",
    "ERRORS",
    "JOURNAL_ZERO",
    "LEVEL_TITLES",
    "MODES",
    "MODE_TITLES",
    "PIN_LOCK_AFTER",
    "PIN_PAUSE_SECONDS",
    "RECOMMENDATION_CODES",
    "RECOMMENDED_LEVEL",
    "RENT_PRODUCT",
    "TTL_CHOICES",
    "TTL_TITLES",
    "FieldContext",
    "FieldCryptoError",
    "FieldKeys",
    "IntegrityFinding",
    "JournalEntry",
    "JournalProblem",
    "LevelFacts",
    "Measure",
    "Policy",
    "Product",
    "Recommendation",
    "RecoveryKey",
    "SecurityError",
    "SheetData",
    "TableDigest",
    "access",
    "action_title",
    "argon2_params",
    "audit_digest",
    "check_pin",
    "combine_shares",
    "configure",
    "deadline",
    "derive_argon2id",
    "diff_rows",
    "emergency_sheet_pdf",
    "expired",
    "fields",
    "hash_pin",
    "hash_secret",
    "journal_canonical",
    "journal_link",
    "legacy_share_set",
    "level",
    "level_measures",
    "licensing",
    "looks_like_recovery",
    "lowering",
    "needs_rehash",
    "needs_risk_ack",
    "new_recovery_key",
    "open_with",
    "parse_recovery_key",
    "pin_failure",
    "recommendation",
    "recommendation_state",
    "recovery_from_input",
    "recovery_id",
    "recovery_public",
    "root",
    "row_hash",
    "row_key",
    "schema_digest",
    "seal_to",
    "shamir_combine_raw",
    "sheet_lines",
    "split_key",
    "validate_policy",
    "verify_chain",
    "verify_pin",
    "verify_secret",
    "visible_recommendations",
    "web",
]

ARGON2_DEFAULT = dict(kdf.DEFAULT)
ARGON2_OWASP_MIN = dict(kdf.OWASP_MIN)


@dataclass(frozen=True)
class RecoveryKey:
    secret: bytes  # 16 байт; только в памяти — для запечатывания и показа один раз
    text: str  # «RK1-XXXXX-…» для бумаги


def new_recovery_key() -> RecoveryKey:
    secret = codes.new_key()
    return RecoveryKey(secret, codes.format_key(secret))


def parse_recovery_key(text: str) -> bytes:
    return codes.parse_key(text)


def recovery_public(secret: bytes) -> str:
    return recovery.public_of(secret)


def recovery_id(public: str) -> str:
    return recovery.recovery_id(public)


def seal_to(public: str, payload: bytes, *, aad: bytes) -> dict[str, object]:
    return recovery.seal_to(public, payload, aad=aad)


def open_with(secret: bytes, sealed: object, *, aad: bytes) -> bytes:
    return recovery.open_with(secret, sealed, aad=aad)


def split_key(secret: bytes) -> tuple[str, str, str]:
    return shamir.split(secret)


def combine_shares(texts: list[str] | str) -> bytes:
    return shamir.combine(texts)


def legacy_share_set(text: str) -> bool:
    """В вводе части «2 из 3» прежнего образца (метка из ключа) и они собираются — повод посоветовать перевыпуск частей."""
    try:
        return bool(codes.SHARE_RE.search(codes.normalize(text))) and shamir.legacy_set(text)
    except SecurityError:
        return False


def shamir_combine_raw(parts: list[tuple[int, bytes]]) -> bytes:
    return shamir.combine_raw(parts)


def looks_like_recovery(text: str) -> bool:
    return codes.looks_like_recovery(text)


def recovery_from_input(text: str) -> bytes | None:
    """Ключ восстановления из ввода: запись RK1-… или две (три) части RS1-…; обычный пароль — None. Опечатка — SecurityError."""
    if not codes.looks_like_recovery(text) and not codes.SHARE_RE.search(codes.normalize(text)):
        return None
    if codes.SHARE_RE.search(codes.normalize(text)):
        return shamir.combine(text)
    return codes.parse_key(text)


def hash_secret(password: str, *, m: int = kdf.DEFAULT["m"], t: int = kdf.DEFAULT["t"], p: int = kdf.DEFAULT["p"]) -> str:
    return kdf.hash_secret(password, m=m, t=t, p=p)


def verify_secret(password: str, stored: str) -> bool:
    return kdf.verify_secret(password, stored)


def needs_rehash(stored: str) -> bool:
    return kdf.needs_rehash(stored)


def argon2_params(stored: str) -> dict[str, int]:
    return kdf.params(stored)


def derive_argon2id(secret: bytes, salt: bytes, m: int, t: int, p: int, length: int = 32) -> bytes:
    return kdf.derive(secret, salt, m, t, p, length)


def emergency_sheet_pdf(data: SheetData, lang: str = "ru", font_dir: Path | None = None) -> bytes:
    return sheet.emergency_sheet_pdf(data, lang, font_dir)


# --- мастер безопасности, тренировка, помощь (28.10-277, 278, 283, 287, 289, 290) ------------------------------------
# Правила — пространствами имён: `wizard` (шаги, решения, уровень 0–5, принудительный показ), `training` (28 дней, умные
# интервалы 3→7→14→30, обзор, учение, проверка кода без гашения), `help` (тексты RU/UK: «Если случилось», страницы мер,
# уровни, «Как защитить компьютер и аккаунты»).

PC_ITEMS = recommendations.PC_ITEMS
item_status = recommendations.item_status
pc_remaining = recommendations.pc_remaining
level_measures_for = levels.level_measures_for
missing_for = levels.missing_for

__all__ += ["PC_ITEMS", "help", "item_status", "level_measures_for", "missing_for", "pc_remaining", "training", "wizard"]


# --- вход и восстановление (часть C: 28.10-282, 284, 289) ----------------------------------------------------------
# WebAuthn (аппаратные ключи и passkey, PRF для копий), TOTP (Google Authenticator), коды восстановления входа, правила
# сброса по почте / с ожиданием 72 ч / подтверждения в Telegram. Модули целиком: снаружи — `security.webauthn.…` и т. п.
from homensai_security import auth_texts, login_codes, reset, totp, webauthn  # noqa: E402

__all__ += ["auth_texts", "login_codes", "reset", "totp", "webauthn"]


def recovery_text_of(secret: bytes) -> str:
    """Запись «RK1-…» для 16-байтового ключа восстановления — например, посчитанного ключом через PRF (282 п. 1)."""
    return codes.format_key(secret)


__all__ += ["recovery_text_of"]

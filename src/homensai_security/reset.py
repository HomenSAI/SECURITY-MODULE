# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Восстановление входа: ссылка сброса по почте, сброс с ожиданием 72 часа, подтверждение в Telegram, правила второго фактора
(решения владельца 28.10-282 п. 3, 28.10-284 п. 1). Чистые правила без базы и часов: время (секунды Unix) передаёт вызывающий.

- Ссылка сброса: 256 случайных бит (`secrets.token_urlsafe(32)`), на ПК — только SHA-256; действует 15 минут и один раз.
  Новая ссылка отменяет прежние. Сбрасывается только пароль входа: пароль копий программа не хранит (270), для него —
  ключ восстановления (279).
- Если включён второй фактор (ключ, passkey, Google Authenticator), он нужен и при сбросе. Вместо него годится код
  восстановления (284) или подтверждение в Telegram (284: привязанный чат владельца с ботом «Система» — второй фактор для
  восстановления).
- Факторов не осталось — сброс с ожиданием: запрос по ссылке из письма, срабатывает через 72 часа; всё это время
  уведомления во все каналы, запрос отменяется из любого действующего входа. После ожидания пароль задаётся заново, а
  потерянные факторы отключаются (иначе войти всё равно нельзя) — коды, ключи и Google Authenticator настраиваются снова."""

from __future__ import annotations

from dataclasses import dataclass
import hashlib
import secrets

EMAIL_TTL = 15 * 60
DELAY = 72 * 3600
DELAYED_USE_WINDOW = 7 * 24 * 3600  # после 72 часов ссылка завершения действует неделю
TELEGRAM_TTL = 15 * 60
MAX_LINKS_PER_HOUR = 3
SECOND_FACTORS = ("webauthn", "totp", "code", "telegram")


def new_token() -> tuple[str, str]:
    """(токен для ссылки, его SHA-256 для базы)."""
    token = secrets.token_urlsafe(32)
    return token, digest(token)


def digest(token: str) -> str:
    return hashlib.sha256(token.encode("utf-8")).hexdigest()


def token_shape_ok(token: str) -> bool:
    return 20 <= len(token) <= 100 and all(ch.isascii() and (ch.isalnum() or ch in "-_") for ch in token)


def email_expired(created_at: int, now: int) -> bool:
    return now - created_at > EMAIL_TTL or now < created_at


def delayed_ready_at(requested_at: int) -> int:
    return requested_at + DELAY


def delayed_state(requested_at: int, now: int) -> str:
    """waiting — 72 часа ещё идут; ready — можно завершить; expired — окно завершения прошло."""
    ready = delayed_ready_at(requested_at)
    if now < ready:
        return "waiting"
    return "ready" if now <= ready + DELAYED_USE_WINDOW else "expired"


@dataclass(frozen=True)
class Factors:
    """Что включено у входа: число действующих ключей/passkey, Google Authenticator, неиспользованных кодов, чат Telegram."""

    keys: int = 0
    totp: bool = False
    codes_left: int = 0
    telegram: bool = False

    @property
    def second_factor(self) -> bool:
        """Второй фактор входа включён: ключ или Google Authenticator (коды и Telegram — запасные способы, не отдельный фактор)."""
        return self.keys > 0 or self.totp


def reset_allowed(factors: Factors, *, link_ok: bool, proof: str | None) -> bool:
    """Сброс по ссылке разрешён: ссылка действительна и, если включён второй фактор, предъявлено одно из доказательств."""
    if not link_ok:
        return False
    if not factors.second_factor:
        return True
    return proof in SECOND_FACTORS


def proofs_available(factors: Factors) -> tuple[str, ...]:
    """Чем можно подтвердить сброс при включённом втором факторе (по порядку показа)."""
    found: list[str] = []
    if factors.keys:
        found.append("webauthn")
    if factors.totp:
        found.append("totp")
    if factors.codes_left:
        found.append("code")
    if factors.telegram:
        found.append("telegram")
    return tuple(found)


def mask_email(address: str) -> str:
    """«s***@gmail.com» — для экрана «ссылка отправлена» (адрес целиком до входа не показывается)."""
    name, _, domain = address.partition("@")
    if not name or not domain:
        return "***"
    return f"{name[0]}***@{domain}"

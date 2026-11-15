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


# --- вход по одноразовому коду из почты (решение владельца 28.10-344) ---------------------------------------------------
# Код заменяет только пароль: при включённом втором факторе (ключ, passkey, Google Authenticator) после кода нужен и он.
# По умолчанию выключено; включается только при настроенной и проверенной почте. Письмо — 8 цифр и ссылка: ссылка лишь
# показывает код крупно и сама вход не выполняет; ввод — в том же окне браузера, где код запрошен (привязка к запросу
# через cookie). 10 минут, один раз, новый код отменяет прежний, 5 неверных вводов — код сгорает, не больше 3 писем в час.
# Хранение: продукт кладёт в базу только HMAC кода с секретом из своего хранилища ключей (`login_code_message` — что
# подписывать) и SHA-256 токенов ссылки и окна браузера (`digest`). Время (секунды Unix) передаёт вызывающий.

LOGIN_CODE_TTL = 10 * 60
LOGIN_CODE_DIGITS = 8
LOGIN_CODE_ATTEMPTS = 5
LOGIN_CODES_PER_HOUR = 3


@dataclass(frozen=True)
class LoginCodeIssue:
    """Новый код входа: код для письма, токен ссылки (показывает код) и токен окна браузера (cookie) — только в памяти."""

    code: str
    link_token: str
    browser_token: str


def email_login_allowed(*, enabled: bool, mail_verified: bool) -> bool:
    """Вход по коду из почты доступен: включён владельцем и почта настроена и проверена (иначе его нет на экране входа)."""
    return enabled and mail_verified


def email_login_can_enable(*, mail_verified: bool) -> bool:
    """Включить можно только при проверенной почте (решение 344: «по умолчанию выключено»)."""
    return mail_verified


def email_login_weakens(factors: Factors, *, enabled: bool) -> bool:
    """Почта — единственный способ входа без второго фактора: уровень защиты понижается, мастер объясняет почему."""
    return enabled and not factors.second_factor


def new_login_code() -> LoginCodeIssue:
    return LoginCodeIssue(f"{secrets.randbelow(10 ** LOGIN_CODE_DIGITS):0{LOGIN_CODE_DIGITS}d}", secrets.token_urlsafe(32),
                          secrets.token_urlsafe(32))


def normalize_login_code(text: str) -> str | None:
    """8 цифр без пробелов и дефисов; иначе None (не код — неверный ввод)."""
    digits = "".join(ch for ch in text if not ch.isspace() and ch != "-")
    return digits if len(digits) == LOGIN_CODE_DIGITS and digits.isascii() and digits.isdigit() else None


def login_code_message(request_id: str, code: str) -> str:
    """Что подписывает HMAC продукта: код привязан к своему запросу (одинаковый код другого запроса не подходит)."""
    return f"homensai-login-code/1:{request_id}:{code}"


def login_codes_rate_ok(sent_at: list[int] | tuple[int, ...], now: int) -> bool:
    """Не больше 3 писем с кодом за последний час."""
    return sum(1 for moment in sent_at if 0 <= now - moment < 3600) < LOGIN_CODES_PER_HOUR


def login_code_state(*, created_at: int, now: int, attempts: int, used: bool, superseded: bool) -> str:
    """active — код можно вводить; used — уже вошли; superseded — запрошен новый; burned — 5 неверных вводов;
    expired — прошло 10 минут (или часы ушли назад)."""
    if used:
        return "used"
    if superseded:
        return "superseded"
    if attempts >= LOGIN_CODE_ATTEMPTS:
        return "burned"
    if now < created_at or now - created_at > LOGIN_CODE_TTL:
        return "expired"
    return "active"


def login_code_verdict(*, state: str, browser_ok: bool, mac_ok: bool) -> str:
    """Итог ввода: ok; email_login_expired — код не действует; email_login_browser — другое окно браузера (не считается
    попыткой: подбор так не идёт); email_login_code_wrong — неверный код (считается попыткой)."""
    if state != "active":
        return "email_login_expired"
    if not browser_ok:
        return "email_login_browser"
    return "ok" if mac_ok else "email_login_code_wrong"


def mac_equal(stored: str, computed: str) -> bool:
    """Сравнение HMAC без утечки по времени."""
    import hmac

    return hmac.compare_digest(stored.encode("ascii", "replace"), computed.encode("ascii", "replace"))

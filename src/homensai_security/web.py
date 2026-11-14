# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Защита веба без привязки к фреймворку (MOD.extract-web, решения 286, 332): заголовки и CSP, проверка чужого сайта
(Origin / Sec-Fetch-Site / Referer, OWASP CSRF Cheat Sheet), CSRF «двойная отправка», пределы тела, очистка управляющих
символов, одноразовые ключи форм (повтор формы), предел попыток входа с растущей паузой.

Источник — Rent `app/web/core.py`, `app/web/auth.py` (аудит SEC2-WEB-01, SEC2-MONEY-02). Модуль решает и отвечает
кодом отказа (`WebRefusal.code` — как в справочнике ошибок Rent: web_foreign_origin, web_csrf, upload_too_big…); как
показать отказ, где хранить ключи форм и счётчик попыток — дело адаптера (WSGI Rent, FastAPI/Starlette JobPilot Pro).
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass
import hashlib
import hmac
import re
import secrets
from typing import Protocol
from urllib.parse import urlsplit

CSP = (
    "default-src 'none'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; connect-src 'self'; "
    "base-uri 'none'; form-action 'self'; frame-ancestors 'none'"
)
CSP_UNTRUSTED_FILE = "sandbox"  # отдаваемый файл мог прислать посторонний (жилец, кандидат): без скриптов и доступа к сайту
SECURITY_HEADERS: tuple[tuple[str, str], ...] = (
    ("X-Content-Type-Options", "nosniff"),
    ("X-Frame-Options", "DENY"),
    # no-referrer превращает Origin обычной POST-формы в null (Fetch 3.2); same-origin сохраняет проверку своих форм.
    ("Referrer-Policy", "same-origin"),
    ("Cross-Origin-Opener-Policy", "same-origin"),
    ("Cross-Origin-Resource-Policy", "same-origin"),
    ("Permissions-Policy", "camera=(), microphone=(), geolocation=(), payment=()"),
)
MAX_UPLOAD_BODY = 30 * 1024 * 1024  # формы с файлами (multipart/form-data)
MAX_FORM_BODY = 1024 * 1024  # обычные формы: 1 МБ, иначе 413 без чтения тела
CSRF_FIELD = "csrf_token"
FORM_KEY_FIELD = "_form_key"
FORM_KEY_TTL = 24 * 3600
LOCK_AFTER = 5  # неудачных входов подряд — пауза
LOCK_BASE_SECONDS = 15 * 60
LOCK_MAX_SECONDS = 6 * 3600

_CONTROL = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")  # в полях форм: кроме табуляции и переводов строки
_CONTROL_ANY = re.compile(r"[\x00-\x1f\x7f]")  # в заголовках ответа: и CR/LF/табуляция


@dataclass(frozen=True)
class WebRefusal:
    """Отказ: HTTP-статус и код ошибки (текст — из справочника продукта по коду)."""

    status: int
    code: str


def security_headers(*, untrusted_file: bool = False) -> list[tuple[str, str]]:
    """Заголовки каждого ответа: защитные + CSP (для файла от постороннего — `sandbox`)."""
    return [*SECURITY_HEADERS, ("Content-Security-Policy", CSP_UNTRUSTED_FILE if untrusted_file else CSP)]


def check_host(host: str, allowed_hosts: Iterable[str]) -> WebRefusal | None:
    """Host не из списка (подмена DNS rebinding) — 400 `web_bad_host`."""
    return None if host in set(allowed_hosts) else WebRefusal(400, "web_bad_host")


def check_same_site(headers: Mapping[str, str], allowed_hosts: Iterable[str]) -> WebRefusal | None:
    """Запрос, меняющий данные, — только со своего сайта (до чтения тела).

    Origin не свой — отказ; Sec-Fetch-Site не `same-origin`/`none` — отказ; нет ни Origin, ни Sec-Fetch-Site (старый клиент) —
    Referer, если есть, должен быть свой. `headers` — имена в нижнем регистре."""
    allowed = set(allowed_hosts)
    origin = headers.get("origin")
    if origin and urlsplit(origin).netloc not in allowed:
        return WebRefusal(403, "web_foreign_origin")
    fetch_site = headers.get("sec-fetch-site", "").lower()
    if fetch_site and fetch_site not in ("same-origin", "none"):
        return WebRefusal(403, "web_foreign_origin")
    referer = headers.get("referer")
    if not origin and not fetch_site and referer and urlsplit(referer).netloc not in allowed:
        return WebRefusal(403, "web_foreign_origin")
    return None


def new_csrf_token() -> str:
    """Значение cookie CSRF (HttpOnly; SameSite=Strict) и скрытого поля формы."""
    return secrets.token_urlsafe(24)


def check_csrf(cookie_token: str, form_token: str) -> WebRefusal | None:
    """Двойная отправка: поле формы равно cookie (сравнение постоянного времени); иначе 403 `web_csrf`."""
    if not cookie_token or not form_token or not hmac.compare_digest(cookie_token, form_token):
        return WebRefusal(403, "web_csrf")
    return None


def body_limit(content_type: str) -> int:
    """Предел тела: большой — только для форм с файлами."""
    return MAX_UPLOAD_BODY if content_type.lower().startswith("multipart/form-data") else MAX_FORM_BODY


def check_body_length(content_type: str, length: int) -> WebRefusal | None:
    """Тело больше предела — 413 `upload_too_big` (проверять до чтения тела)."""
    return WebRefusal(413, "upload_too_big") if length > body_limit(content_type) else None


def clean_field(value: str) -> str:
    """Убирает управляющие символы из поля формы или адреса (ломают выгрузки и архив); табуляция и переводы строк остаются."""
    return _CONTROL.sub("", value)


def clean_header(value: str) -> str:
    """Управляющие символы в значении заголовка ответа — percent-кодом (CR/LF не попадут в ответ)."""
    return _CONTROL_ANY.sub(lambda found: f"%{ord(found.group()):02X}", value)


def new_form_key() -> str:
    """Одноразовый ключ формы для скрытого поля `_form_key` (повтор формы не выполняется второй раз)."""
    return secrets.token_urlsafe(18)


def stored_form_key(raw: str) -> str:
    """Как хранить ключ формы: SHA-256 (64 hex) — любой текст поля одинаковой длины и без исходного значения."""
    return hashlib.sha256(raw.encode("utf-8")).hexdigest()


class FormKeyStore(Protocol):
    """Хранилище ключей форм продукта (в Rent — таблица `web_form_keys`): атомарные операции над хэшем ключа."""

    def purge_before(self, moment: int) -> None: ...
    def insert_busy(self, key_hash: str, now: int) -> bool: ...  # True — вставлено (ключ новый)
    def mark_done(self, key_hash: str, now: int) -> None: ...
    def delete_busy(self, key_hash: str) -> None: ...


def form_begin(store: FormKeyStore, raw: str, now: int) -> bool:
    """Начало обработки формы: True — ключ новый; False — эта форма уже выполняется или выполнена (повтор)."""
    store.purge_before(now - FORM_KEY_TTL)
    return store.insert_busy(stored_form_key(raw), now)


def form_done(store: FormKeyStore, raw: str, now: int) -> None:
    """Действие выполнено: повтор той же формы будет отклонён."""
    store.mark_done(stored_form_key(raw), now)


def form_release(store: FormKeyStore, raw: str) -> None:
    """Действие не выполнено (ошибка ввода): форму можно исправить и отправить снова."""
    store.delete_busy(stored_form_key(raw))


def request_key(raw: str) -> str | None:
    """Ключ повтора для денежной операции сервиса (пишется в одной транзакции с операцией): SHA-256 hex, 64 знака."""
    raw = raw.strip()
    return stored_form_key(raw)[:64] if raw else None


def lock_seconds(failures: int) -> int:
    """Пауза после каждых LOCK_AFTER неудач: 15 мин, затем вдвое больше, не больше 6 ч."""
    episode = max(failures // LOCK_AFTER, 1)
    return int(min(LOCK_BASE_SECONDS * 2 ** (episode - 1), LOCK_MAX_SECONDS))


def after_failed_login(failures: int, now: int) -> int | None:
    """Счётчик неудач уже увеличен до `failures`: момент окончания паузы или None, если пауза ещё не нужна."""
    return now + lock_seconds(failures) if failures > 0 and failures % LOCK_AFTER == 0 else None


def login_locked(locked_until: int | None, now: int) -> bool:
    """Идёт ли пауза входа."""
    return locked_until is not None and now < locked_until

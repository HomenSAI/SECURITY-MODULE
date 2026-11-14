# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""PIN для важных действий, режимы «Офис»/«Дом» и блокировка экрана (решение владельца 28.10-272; Argon2id — 28.10-279 п. 3).

Чистые правила без базы и часов: время (секунды Unix) и конец дня передаёт вызывающий.
- PIN — ровно 4 цифры ASCII, отдельный от пароля входа и PIN копий; хранится только записью Argon2id (`kdf.hash_secret`);
- срок действия после ввода — 5, 10, 30 минут, 1 час, 2 часа или весь день (0 — до конца местного дня); пока срок не истёк,
  PIN не спрашивается. Тот же срок — порог бездействия для блокировки экрана;
- «Офис» — PIN и блокировка всегда включены; «Дом» — их можно выключить с галочкой «на свой страх и риск»;
- 5 неверных PIN подряд — пауза 10 минут (как пароль копий, 28.10-270);
- любое понижение защиты (выключить меру, длиннее срок, «Офис» → «Дом», меньше действий под PIN) требует подтверждения."""

from __future__ import annotations

from dataclasses import dataclass, field
import re

from homensai_security import kdf
from homensai_security.errors import SecurityError

PIN_RE = re.compile(r"^[0-9]{4}$", re.ASCII)
PIN_LOCK_AFTER = 5
PIN_PAUSE_SECONDS = 600
MODES = ("home", "office")
TTL_CHOICES = (300, 600, 1800, 3600, 7200, 0)  # 0 — весь день: до конца местного дня
DEFAULT_TTL = 1800
# 28.10-272: правка или отмена оплаты, корректировка истории, удаление; смена реквизитов; настройки копий, безопасности и
# пользователей (пользователи и роли — в Core: в автономном Rent этих действий нет, код оставлен для модуля и Core).
ACTIONS = ("payment_change", "history_correction", "delete", "bank_details", "backup_settings", "security_settings", "users")

ACTION_TITLES: dict[str, dict[str, str]] = {
    "ru": {
        "payment_change": "правка или отмена оплаты",
        "history_correction": "корректировка истории",
        "delete": "удаление",
        "bank_details": "смена реквизитов",
        "backup_settings": "настройки копий",
        "security_settings": "настройки безопасности",
        "users": "пользователи и роли",
    },
    "uk": {
        "payment_change": "правка або скасування оплати",
        "history_correction": "коригування історії",
        "delete": "видалення",
        "bank_details": "зміна реквізитів",
        "backup_settings": "налаштування копій",
        "security_settings": "налаштування безпеки",
        "users": "користувачі та ролі",
    },
}
MODE_TITLES: dict[str, dict[str, str]] = {
    "ru": {"home": "Дом", "office": "Офис"},
    "uk": {"home": "Дім", "office": "Офіс"},
}
TTL_TITLES: dict[str, dict[int, str]] = {
    "ru": {300: "5 минут", 600: "10 минут", 1800: "30 минут", 3600: "1 час", 7200: "2 часа", 0: "весь день"},
    "uk": {300: "5 хвилин", 600: "10 хвилин", 1800: "30 хвилин", 3600: "1 година", 7200: "2 години", 0: "весь день"},
}
LOWERING = ("pin_off", "lock_off", "ttl_longer", "office_to_home", "actions_fewer")


def check_pin(pin: str) -> str:
    """PIN из 4 цифр 0–9 (без пробелов и «широких» цифр); иначе SecurityError('pin_format')."""
    if not isinstance(pin, str) or not PIN_RE.fullmatch(pin):
        raise SecurityError("pin_format")
    return pin


def hash_pin(pin: str) -> str:
    return kdf.hash_secret(check_pin(pin))


def verify_pin(pin: str, stored: str) -> bool:
    """Верный PIN к записи Argon2id. Неверный формат ввода — просто False (попытка всё равно считается вызывающим)."""
    if not isinstance(pin, str) or not PIN_RE.fullmatch(pin):
        return False
    return kdf.verify_secret(pin, stored)


def _ttl_rank(ttl: int) -> int:
    return 10**9 if ttl == 0 else ttl  # «весь день» длиннее любого срока в минутах


@dataclass(frozen=True)
class Policy:
    """Выбор владельца. По умолчанию все меры выключены (28.10-277: необязательны), режим «Дом», срок 30 минут."""

    mode: str = "home"
    pin: bool = False
    lock: bool = False
    ttl: int = DEFAULT_TTL
    actions: tuple[str, ...] = field(default=ACTIONS)

    def normalized(self) -> Policy:
        if self.mode == "office":
            return Policy("office", True, True, self.ttl, self.actions)
        return self

    def to_dict(self) -> dict[str, object]:
        return {"mode": self.mode, "pin": self.pin, "lock": self.lock, "ttl": self.ttl, "actions": list(self.actions)}

    @classmethod
    def from_dict(cls, value: object) -> Policy:
        """Сохранённая настройка; нет — значения по умолчанию; неверная — SecurityError('policy_invalid')."""
        if value is None:
            return cls()
        if not isinstance(value, dict):
            raise SecurityError("policy_invalid")
        mode = value.get("mode", "home")
        pin = value.get("pin", False)
        lock = value.get("lock", False)
        ttl = value.get("ttl", DEFAULT_TTL)
        actions = value.get("actions", list(ACTIONS))
        if (mode not in MODES or not isinstance(pin, bool) or not isinstance(lock, bool) or isinstance(ttl, bool)
                or ttl not in TTL_CHOICES or not isinstance(actions, list | tuple) or not all(a in ACTIONS for a in actions)):
            raise SecurityError("policy_invalid")
        ordered = tuple(a for a in ACTIONS if a in actions)
        return cls(str(mode), pin, lock, int(ttl), ordered).normalized()


def lowering(old: Policy, new: Policy) -> tuple[str, ...]:
    """Чем новая настройка слабее прежней; пусто — не слабее (подтверждение не нужно)."""
    before, after = old.normalized(), new.normalized()
    found: list[str] = []
    if before.pin and not after.pin:
        found.append("pin_off")
    if before.lock and not after.lock:
        found.append("lock_off")
    if (before.pin or before.lock) and _ttl_rank(after.ttl) > _ttl_rank(before.ttl):
        found.append("ttl_longer")
    if before.mode == "office" and after.mode == "home":
        found.append("office_to_home")
    if before.pin and after.pin and set(after.actions) < set(before.actions):
        found.append("actions_fewer")
    return tuple(found)


def needs_risk_ack(old: Policy, new: Policy) -> bool:
    """В режиме «Дом» выключение PIN или блокировки — только с галочкой «на свой страх и риск» (как 271)."""
    reasons = lowering(old, new)
    return "pin_off" in reasons or "lock_off" in reasons


def validate_policy(policy: Policy, *, has_pin: bool) -> Policy:
    """PIN и блокировка (а значит и «Офис») возможны только при заданном PIN: разблокировка — PIN или пароль входа."""
    normal = policy.normalized()
    if (normal.pin or normal.lock) and not has_pin:
        raise SecurityError("pin_not_set")
    return normal


def pin_failure(failed_count: int, *, now: int) -> tuple[int, int]:
    """Ещё одна ошибка PIN: (новый счётчик, пауза до — секунды Unix или 0). Каждая пятая ошибка подряд — пауза 10 минут."""
    count = failed_count + 1
    return count, (now + PIN_PAUSE_SECONDS if count % PIN_LOCK_AFTER == 0 else 0)


def deadline(start: int, ttl: int, *, day_end: int) -> int:
    """Когда истекает срок, начатый в `start`: через ttl секунд или (весь день) в конце местного дня `day_end`."""
    return day_end if ttl == 0 else start + ttl


def expired(start: int, now: int, ttl: int, *, day_end: int) -> bool:
    return now > deadline(start, ttl, day_end=day_end)


def action_title(code: str, lang: str = "ru") -> str:
    return ACTION_TITLES.get(lang, ACTION_TITLES["ru"])[code]

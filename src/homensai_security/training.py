# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Тренировка безопасности (решение владельца 28.10-287), чтобы не забывать пароли и порядок восстановления.

Чистые правила без базы и часов: факты (когда включён каждый способ, удачные и неудачные вводы, прошлые обзоры и учения)
собирает вызывающий, «сегодня» — тоже он. Образцы — GitHub (проверка 2FA через 28 дней, периодический обзор способов
восстановления) и Signal (напоминание PIN: верно — реже, ошибка — чаще).

1. **Проверка через 28 дней** после включения каждого способа (TOTP, аппаратный ключ, passkey (289), PIN, пароль копий,
   ключ восстановления): нужен удачный ввод в срок или позже; иначе — «Перенастроить».
2. **Умные интервалы** для пароля копий и PIN: 3 → 7 → 14 → 30 дней. Верный ввод — ступень вверх, ошибка — ступень вниз
   (не ниже 3 дней). Интервал не длиннее выбранного срока проверки 270 (14 или 30 дней) — «не реже» его.
3. **Обзор восстановления** раз в полгода — страница из пяти галочек (`REVIEW_ITEMS`).
4. **Учебное восстановление** с пользователем раз в квартал — в песочнице, рабочая база не трогается (делает привязка).
5. **Проверка кода без гашения**: случайный номер кода восстановления (`pick_code`); ключ восстановления сверяется целиком
   (на ПК хранится только его открытый ключ, поэтому «первые группы» отдельно сверить нельзя).
6. Всё приходит в «Важное» ненавязчиво; мигает только просрочка — `OVERDUE_GRACE` дней после срока.
"""

from __future__ import annotations

from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from datetime import date, timedelta
import secrets

from homensai_security.errors import SecurityError

LADDER = (3, 7, 14, 30)  # дни — свои числа (287 п. 2, уточнение 333); от Signal взят только принцип «верно — реже, ошибка — чаще»
CHECKUP_DAYS = 28  # GitHub: через 28 дней после включения 2FA (287 п. 1)
REVIEW_DAYS = 182  # обзор восстановления раз в полгода (287 п. 3)
DRILL_DAYS = 91  # учебное восстановление раз в квартал (287 п. 4)
OVERDUE_GRACE = 7  # просрочка (мигает) — через неделю после срока; до того строка спокойная
METHODS = ("totp", "hardware_key", "passkey", "pin", "backup_password", "recovery_key")
SMART = ("backup_password", "pin")
REVIEW_ITEMS = ("email", "keys", "codes", "sheet", "trustees")
KINDS = ("checkup", "smart", "review", "drill")


def stage(results: Sequence[bool]) -> int:
    """Ступень лестницы 3/7/14/30 по вводам по порядку: верный — вверх, ошибка — вниз; старт — 0 (3 дня)."""
    current = 0
    for ok in results:
        current = min(current + 1, len(LADDER) - 1) if ok else max(current - 1, 0)
    return current


def interval(results: Sequence[bool], cap_days: int) -> int:
    """Дней до следующего ввода: ступень лестницы, но не больше выбранного срока проверки (270: 14 или 30)."""
    if isinstance(cap_days, bool) or not isinstance(cap_days, int) or cap_days < LADDER[0]:
        raise SecurityError("training_unknown")
    return min(LADDER[stage(results)], cap_days)


def smart_due(start: date, events: Sequence[tuple[date, bool]], cap_days: int) -> date:
    """Срок следующего ввода: от последнего ввода (или от включения `start`) через `interval` дней."""
    ordered = sorted((e for e in events if e[0] >= start), key=lambda e: e[0])
    base = ordered[-1][0] if ordered else start
    return base + timedelta(days=interval([ok for _d, ok in ordered], cap_days))


def checkup_due(enabled_on: date) -> date:
    return enabled_on + timedelta(days=CHECKUP_DAYS)


def checkup_done(enabled_on: date, proofs: Sequence[date]) -> bool:
    """Проверка 28 дней пройдена: есть удачный ввод в срок или позже (раньше срока — ещё не та проверка)."""
    due = checkup_due(enabled_on)
    return any(day >= due for day in proofs)


def periodic_due(last: date | None, start: date | None, days: int) -> date | None:
    """Срок периодического дела: от прошлого раза, иначе от начала тренировки; без начала — не назначено."""
    base = last or start
    return None if base is None else base + timedelta(days=days)


def state_of(due: date, today: date) -> str:
    """later — ещё рано (в «Важное» не идёт); due — пора (спокойная строка); overdue — просрочено (мигает)."""
    if due > today:
        return "later"
    return "overdue" if (today - due).days >= OVERDUE_GRACE else "due"


@dataclass(frozen=True)
class Smart:
    start: date  # когда задан пароль/PIN (смена — начало заново)
    events: tuple[tuple[date, bool], ...]  # вводы по порядку: (день, верно)
    cap_days: int  # выбранный срок проверки 270 (для PIN — 30)


@dataclass(frozen=True)
class Facts:
    enabled: bool  # тренировка включена (по умолчанию с уровня 2)
    start: date | None  # начало тренировки — от него первые обзор и учение
    methods: Mapping[str, date] = field(default_factory=dict)  # способ → когда включён
    proofs: Mapping[str, tuple[date, ...]] = field(default_factory=dict)  # способ → дни удачных вводов
    smart: Mapping[str, Smart] = field(default_factory=dict)
    last_review: date | None = None
    last_drill: date | None = None
    drill_possible: bool = False  # есть копии на ключе хозяйства — есть что восстанавливать
    review_possible: bool = False  # есть что пересматривать: пароль копий, ключи восстановления или способы входа


@dataclass(frozen=True)
class Item:
    key: str  # постоянный ключ для «Важного»: train:<вид>:<способ>
    kind: str
    method: str | None
    due: date
    state: str  # later | due | overdue

    @property
    def overdue(self) -> bool:
        return self.state == "overdue"


def plan(facts: Facts, today: date) -> list[Item]:
    """Все дела тренировки со сроками (и будущие), по сроку. Выключенная тренировка — пусто."""
    if not facts.enabled:
        return []
    items: list[Item] = []
    for method in METHODS:
        enabled_on = facts.methods.get(method)
        if enabled_on is None or checkup_done(enabled_on, facts.proofs.get(method, ())):
            continue
        due = checkup_due(enabled_on)
        items.append(Item(f"train:checkup:{method}", "checkup", method, due, state_of(due, today)))
    pending_checkup = {i.method for i in items if i.state != "later"}
    for method in SMART:
        info = facts.smart.get(method)
        if info is None or method in pending_checkup:
            continue  # пора проверка 28 дней — тот же ввод засчитается и в умный интервал; одна строка вместо двух
        due = smart_due(info.start, info.events, info.cap_days)
        items.append(Item(f"train:smart:{method}", "smart", method, due, state_of(due, today)))
    if facts.review_possible:
        due_review = periodic_due(facts.last_review, facts.start, REVIEW_DAYS)
        if due_review is not None:
            items.append(Item("train:review", "review", None, due_review, state_of(due_review, today)))
    if facts.drill_possible:
        due_drill = periodic_due(facts.last_drill, facts.start, DRILL_DAYS)
        if due_drill is not None:
            items.append(Item("train:drill", "drill", None, due_drill, state_of(due_drill, today)))
    return sorted(items, key=lambda i: (i.due, i.key))


def due_items(facts: Facts, today: date) -> list[Item]:
    """Дела, которым пора (в «Важное»): срок настал; просроченные — мигают."""
    return [item for item in plan(facts, today) if item.state != "later"]


def review_complete(checked: Sequence[str], applicable: Sequence[str]) -> bool:
    """Обзор засчитан, когда отмечен каждый применимый пункт (неприменимые — например, нет частей «2 из 3» — не нужны)."""
    unknown = set(checked) - set(REVIEW_ITEMS)
    if unknown:
        raise SecurityError("review_incomplete")
    return set(applicable) <= set(checked)


def pick_code(count: int) -> int:
    """Номер случайного кода восстановления для проверки без гашения (1…count). Нет кодов — SecurityError."""
    if isinstance(count, bool) or not isinstance(count, int) or count < 1:
        raise SecurityError("training_unknown")
    return secrets.randbelow(count) + 1

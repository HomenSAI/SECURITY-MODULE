# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Мастер безопасности (решения владельца 28.10-277, 278, 290): шаги, решения «выбрать / пропустить / отложить», уровень 0–5.

Чистые правила без базы и часов: состояние — словарь (его хранит вызывающий), «сегодня» передаёт вызывающий.
- Все меры необязательны. На каждом шаге одно из трёх решений: «Выбрать» (`chosen`), «Пропустить» (`skipped`) — только с
  галочкой «понимаю риск», «Отложить» (`deferred`) — на неделю, 2 недели, месяц, 3 месяца или полгода. Решение можно изменить
  в любой момент: новое заменяет прежнее.
- Мастер пройден, когда по каждому шагу есть решение (отложенный шаг тоже решён: он вернётся напоминанием в свой срок).
- Принудительный показ (`required`) ставит вызывающий после мастера первого запуска; пройденный мастер его снимает.
- Пока мастер не пройден, в «Важном» — ненавязчивое немигающее напоминание; «Напомнить позже» прячет его до даты.
- Уровень 0–5 (278): по умолчанию 2; уровни 0 и 1 — только с галочкой риска. Выбор уровня — это и решение шага `level`.
- Первый шаг — «Как защитить компьютер и аккаунты» (290); рекомендации NordVPN/ESET/NordPass (285/289) — шаг `recommendations`.
Адреса экранов здесь не хранятся: шаг знает только свой код, уровень и вид; куда вести — решает привязка к продукту."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field, replace
from datetime import date, timedelta

from homensai_security.errors import SecurityError
from homensai_security.levels import RECOMMENDED_LEVEL

DEFER_DAYS = (7, 14, 30, 90, 180)  # неделя, 2 недели, месяц, 3 месяца, полгода (277)
CHOICES = ("chosen", "skipped", "deferred")
RISKY_LEVELS = (0, 1)


@dataclass(frozen=True)
class Step:
    code: str
    level: int | None  # уровень ползунка, в который входит мера; None — вне уровней (рекомендации, вход)
    kind: str  # level — ползунок; checklist — список рекомендаций; toggle — включается прямо в мастере; setup — свой экран


# Порядок шагов. Шаг `protect_pc` первый (290), `level` второй: выбранный уровень подсвечивает шаги, которые в него входят.
STEPS: tuple[Step, ...] = (
    Step("protect_pc", None, "checklist"),
    Step("level", None, "level"),
    Step("backup_password", 1, "setup"),
    Step("places", 1, "setup"),
    Step("after_events", 2, "toggle"),
    Step("password_check", 2, "setup"),
    Step("recovery", 2, "setup"),
    Step("training", 2, "toggle"),
    Step("pin_lock", 3, "setup"),
    Step("login", None, "setup"),
    Step("integrity", 4, "setup"),
    Step("chain", 4, "setup"),
    Step("notify", 5, "setup"),
    Step("recommendations", None, "checklist"),
)
STEP_CODES = tuple(s.code for s in STEPS)
_BY_CODE = {s.code: s for s in STEPS}


@dataclass(frozen=True)
class Decision:
    choice: str
    on: date
    until: date | None = None  # для «Отложить»: когда напомнить


@dataclass(frozen=True)
class WizardState:
    required: bool = False
    target: int | None = None  # выбранный уровень 0–5; None — ещё не выбирали (показывается рекомендуемый 2)
    steps: Mapping[str, Decision] = field(default_factory=dict)
    finished_on: date | None = None
    snoozed_until: date | None = None  # «Напомнить позже» для всего мастера

    # --- хранение ------------------------------------------------------------------------------------------------

    def to_dict(self) -> dict[str, object]:
        return {
            "v": 1,
            "required": self.required,
            "target": self.target,
            "steps": {code: {"choice": d.choice, "on": d.on.isoformat(), **({"until": d.until.isoformat()} if d.until else {})}
                      for code, d in self.steps.items()},
            "finished_on": self.finished_on.isoformat() if self.finished_on else None,
            "snoozed_until": self.snoozed_until.isoformat() if self.snoozed_until else None,
        }

    @classmethod
    def from_dict(cls, value: object) -> WizardState:
        """Сохранённое состояние; нет или испорчено — чистый мастер (испорченное состояние не прячет напоминание)."""
        if not isinstance(value, Mapping):
            return cls()
        steps: dict[str, Decision] = {}
        raw_steps = value.get("steps")
        for code, raw in (raw_steps.items() if isinstance(raw_steps, Mapping) else ()):
            if code not in _BY_CODE or not isinstance(raw, Mapping) or raw.get("choice") not in CHOICES:
                continue
            on = _day(raw.get("on"))
            until = _day(raw.get("until"))
            if on is None or (raw.get("choice") == "deferred" and until is None):
                continue
            steps[code] = Decision(str(raw["choice"]), on, until if raw.get("choice") == "deferred" else None)
        target = value.get("target")
        if isinstance(target, bool) or not isinstance(target, int) or not 0 <= target <= 5:
            target = None
        state = cls(bool(value.get("required") is True), target, steps, _day(value.get("finished_on")), _day(value.get("snoozed_until")))
        if state.finished_on is not None and not finished(state):
            state = replace(state, finished_on=None)  # шаги добавились в новой версии — мастер снова не пройден
        return state


def _day(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def step(code: str) -> Step:
    if code not in _BY_CODE:
        raise SecurityError("wizard_step")
    return _BY_CODE[code]


def finished(state: WizardState) -> bool:
    return all(code in state.steps for code in STEP_CODES)


def _settle(state: WizardState, today: date) -> WizardState:
    if finished(state):
        return replace(state, required=False, finished_on=state.finished_on or today, snoozed_until=None)
    return replace(state, finished_on=None)


def decide(state: WizardState, code: str, choice: str, *, today: date, days: int = 0, risk_ack: bool = False) -> WizardState:
    """Решение по шагу. «Пропустить» без галочки риска — SecurityError('wizard_risk'); неверный срок — 'defer_period'."""
    step(code)
    if choice not in CHOICES:
        raise SecurityError("wizard_choice")
    if choice == "skipped" and not risk_ack:
        raise SecurityError("wizard_risk")
    until = None
    if choice == "deferred":
        if isinstance(days, bool) or days not in DEFER_DAYS:
            raise SecurityError("defer_period")
        until = today + timedelta(days=days)
    steps = dict(state.steps)
    steps[code] = Decision(choice, today, until)
    return _settle(replace(state, steps=steps), today)


def set_target(state: WizardState, level: int, *, today: date, risk_ack: bool = False) -> WizardState:
    """Выбрать уровень 0–5 (278): уровни 0–1 — только с галочкой риска. Это и решение шага `level`."""
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= 5:
        raise SecurityError("wizard_level")
    if level in RISKY_LEVELS and not risk_ack:
        raise SecurityError("wizard_risk")
    steps = dict(state.steps)
    steps["level"] = Decision("chosen", today)
    return _settle(replace(state, target=level, steps=steps), today)


def shown_level(state: WizardState) -> int:
    """Где стоит ползунок: выбранный уровень, иначе рекомендуемый 2."""
    return RECOMMENDED_LEVEL if state.target is None else state.target


def require(state: WizardState) -> WizardState:
    """Мастер первого запуска пройден — показать мастер безопасности принудительно (если он ещё не пройден)."""
    return state if finished(state) else replace(state, required=True)


def snooze(state: WizardState, *, today: date, days: int) -> WizardState:
    """«Напомнить позже» для всего мастера: напоминание и принудительный показ уходят до даты."""
    if isinstance(days, bool) or days not in DEFER_DAYS:
        raise SecurityError("defer_period")
    return replace(state, snoozed_until=today + timedelta(days=days))


def _snoozed(state: WizardState, today: date) -> bool:
    return state.snoozed_until is not None and state.snoozed_until > today


def forced(state: WizardState, today: date) -> bool:
    """Открывать ли мастер вместо главной: после мастера первого запуска, пока не пройден и не отложен."""
    return state.required and not finished(state) and not _snoozed(state, today)


def reminder_due(state: WizardState, today: date) -> bool:
    """Ненавязчивое напоминание «Настройте безопасность» (277): мастер не пройден и не отложен «на потом»."""
    return not finished(state) and not _snoozed(state, today)


def next_step(state: WizardState, after: str | None = None) -> str | None:
    """Следующий шаг без решения после `after` (по кругу); все решены — None."""
    start = STEP_CODES.index(after) + 1 if after in _BY_CODE else 0
    order = STEP_CODES[start:] + STEP_CODES[:start]
    return next((code for code in order if code not in state.steps), None)


def following(code: str) -> str | None:
    """Шаг по порядку после `code` (для кнопки «Дальше»), последний — None."""
    index = STEP_CODES.index(step(code).code)
    return STEP_CODES[index + 1] if index + 1 < len(STEP_CODES) else None


def deferred(state: WizardState) -> list[tuple[str, date]]:
    """Отложенные шаги со сроком напоминания, ближайшие первыми (блок «Тревоги и отложенное»)."""
    found = [(code, d.until) for code, d in state.steps.items() if d.choice == "deferred" and d.until is not None]
    return sorted(found, key=lambda item: (item[1], STEP_CODES.index(item[0])))


def due_deferred(state: WizardState, today: date) -> list[tuple[str, date]]:
    """Отложенные шаги, срок которых настал: вернуть напоминанием в «Важное» (не мигает)."""
    return [(code, until) for code, until in deferred(state) if until <= today]


def skipped(state: WizardState) -> list[str]:
    return [code for code in STEP_CODES if code in state.steps and state.steps[code].choice == "skipped"]


def in_level(code: str, level: int) -> bool:
    """Входит ли мера шага в выбранный уровень (уровни накопительные)."""
    lvl = step(code).level
    return lvl is not None and lvl <= level


def progress(state: WizardState) -> tuple[int, int]:
    """(решено шагов, всего шагов) — «Шаг N из M»."""
    return sum(1 for code in STEP_CODES if code in state.steps), len(STEP_CODES)

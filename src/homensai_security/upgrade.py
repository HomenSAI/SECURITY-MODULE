# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Периодическое предложение повысить уровень защиты (решение Rent 28.10-375): чистая логика без базы и часов.

Раз в период (по умолчанию месяц, меняется в настройках) на компьютере предлагается следующий уровень: что добавится, чем рискует
остающийся на текущем, чем грозит потеря ключей, паролей и PIN на новом. «Повысить» запускает шаги перехода (решение 374),
«Не сейчас» запоминается и откладывает предложение на период. На уровне 6 предложения нет. Время подаёт продукт (`today`)."""

from __future__ import annotations

from dataclasses import dataclass
from datetime import date, timedelta

from homensai_security import levels, upgrade_texts
from homensai_security.errors import SecurityError

PERIODS = (14, 30, 60, 90, 180)  # 2 недели, месяц, 2 месяца, 3 месяца, полгода
DEFAULT_PERIOD = 30
ANSWERS = ("later", "accepted")


@dataclass(frozen=True)
class OfferState:
    period_days: int = DEFAULT_PERIOD
    anchor: date | None = None  # от какого дня считается срок: день первого показа или последнего «Не сейчас»
    answer: str | None = None  # последний ответ: later («Не сейчас») или accepted («Повысить»)
    answered_on: date | None = None
    declines: int = 0  # сколько раз ответили «Не сейчас» (для журнала и справки)

    def to_dict(self) -> dict[str, object]:
        return {"v": 1, "period_days": self.period_days, "anchor": self.anchor.isoformat() if self.anchor else None,
                "answer": self.answer, "answered_on": self.answered_on.isoformat() if self.answered_on else None,
                "declines": self.declines}

    @classmethod
    def from_dict(cls, value: object) -> OfferState:
        """Сохранённое состояние; нет или испорчено — начальное (испорченное не должно ни скрывать, ни частить предложение)."""
        if not isinstance(value, dict):
            return cls()
        period = value.get("period_days")
        if isinstance(period, bool) or period not in PERIODS:
            period = DEFAULT_PERIOD
        answer = value.get("answer")
        declines = value.get("declines")
        return cls(int(period), _day(value.get("anchor")), answer if answer in ANSWERS else None, _day(value.get("answered_on")),
                   declines if isinstance(declines, int) and not isinstance(declines, bool) and declines >= 0 else 0)


@dataclass(frozen=True)
class Offer:
    from_level: int
    to_level: int
    adds: tuple[str, ...]  # что добавится на новом уровне
    stay_risk: str  # риски, если остаться
    loss_risk: str  # риски потери ключей, паролей и PIN на новом уровне, и как восстановить


def _day(value: object) -> date | None:
    if not isinstance(value, str):
        return None
    try:
        return date.fromisoformat(value)
    except ValueError:
        return None


def check_period(days: int) -> int:
    if isinstance(days, bool) or days not in PERIODS:
        raise SecurityError("offer_period")
    return days


def schedule(state: OfferState, today: date) -> OfferState:
    """Первый показ: срок отсчитывается от сегодняшнего дня (мастер только что пройден, не тревожить сразу)."""
    return state if state.anchor is not None else OfferState(state.period_days, today, state.answer, state.answered_on, state.declines)


def next_on(state: OfferState) -> date | None:
    return None if state.anchor is None else state.anchor + timedelta(days=state.period_days)


def due(state: OfferState, level: int, today: date) -> bool:
    """Показывать ли предложение: уровень ниже 6, срок наступил, не запланировано заново. Без отсчёта (`anchor` пуст) — нет."""
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level < levels.MAX_LEVEL:
        return False
    if state.anchor is not None and state.anchor > today:
        return True  # ревью Н2: дата отсчёта в будущем (сбой часов, порча) не должна скрывать предложение
    when = next_on(state)
    return when is not None and today >= when


def decline(state: OfferState, today: date) -> OfferState:
    """«Не сейчас»: ответ запоминается, следующее предложение через период от сегодняшнего дня."""
    return OfferState(state.period_days, today, "later", today, state.declines + 1)


def accept(state: OfferState, today: date) -> OfferState:
    """«Повысить»: ответ запоминается; следующий отсчёт — от дня ответа (если переход прервали, предложение вернётся через период)."""
    return OfferState(state.period_days, today, "accepted", today, state.declines)


def set_period(state: OfferState, days: int, today: date) -> OfferState:
    """Сменить периодичность: срок отсчитывается от последнего ответа или первого показа (не от сегодня), чтобы смена не откладывала."""
    check_period(days)
    return OfferState(days, state.anchor or today, state.answer, state.answered_on, state.declines)


def offer(level: int, lang: str = "ru") -> Offer | None:
    """Содержание предложения для текущего уровня; на уровне 6 — None."""
    if isinstance(level, bool) or not isinstance(level, int) or not 0 <= level <= levels.MAX_LEVEL:
        raise SecurityError("wizard_level")
    if level >= levels.MAX_LEVEL:
        return None
    lang = lang if lang in upgrade_texts.STAY else "ru"
    target = level + 1
    adds = tuple(text for lvl, text in levels.level_measures_for(target, lang) if lvl == target)
    return Offer(level, target, adds, upgrade_texts.STAY[lang][level], upgrade_texts.LOSS[lang][target])

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Строки уровня «Безопасность» для ленты напоминаний продукта («Важное» в Rent) — MOD.important-api (решения 277, 283,
285, 287, 290; 286, 332).

Чистая сборка без базы: продукт передаёт состояния (мастер, рекомендации, тренировка, пауза PIN), свои адреса экранов
(`Hrefs`) и язык; модуль возвращает одинаково устроенные `ImportantItem`. Правила вида (как в Rent):
- настоящая тревога (`alarm=True`) — только нарушение (пароль копий, целостность, цепочка; передаёт продукт);
- «Настройте безопасность», отложенные шаги, рекомендации, «Как защитить компьютер» — серые, не мигают (`blink=False`);
- просроченная тренировка мигает (`blink=True`), но не тревога (без красной точки меню).
"""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import date

from homensai_security import help, recommendations, training, wizard

OVERDUE_PREFIX = "security-train-overdue:"


@dataclass(frozen=True)
class ImportantItem:
    key: str  # устойчивый ключ строки (отметки «отложить», журнал)
    title: str
    note: str
    href: str
    due: date
    alarm: bool = False  # красная тревога: только настоящее нарушение
    blink: bool = False  # мигание (просроченная тренировка); WCAG 2.2.2 — продукт ограничивает число миганий


@dataclass(frozen=True)
class Hrefs:
    """Адреса экранов продукта (модуль адресов не знает). По умолчанию — адреса Rent."""

    wizard: str = "/security/wizard"
    wizard_step: str = "/security/wizard/{code}"
    protect_pc: str = "/help/security/protect-pc"
    level: str = "/security#level"
    journal: str = "/security#journal"
    training: Mapping[str, str] = field(default_factory=lambda: {
        "pin": "/security/training/pin", "backup_password": "/security/training/backup", "totp": "/security/training/login",
        "hardware_key": "/security/training/login", "passkey": "/security/training/login",
        "recovery_key": "/security/training/recovery", "review": "/security/training/review", "drill": "/security/training/drill",
    })
    training_default: str = "/security/training"

    def train(self, item: training.Item) -> str:
        if item.kind in ("review", "drill"):
            return self.training.get(item.kind, self.training_default)
        return self.training.get(item.method or "", self.training_default)


def _t(lang: str, ru: str, uk: str) -> str:
    return uk if lang == "uk" else ru


def guide_items(state: wizard.WizardState, today: date, *, reco_state: Mapping[str, object] | None = None,
                training_facts: training.Facts | None = None, hrefs: Hrefs | None = None, lang: str = "ru") -> list[ImportantItem]:
    """Мастер (напоминание и отложенные шаги), «Как защитить компьютер», тренировка. Не мигают, кроме просрочки тренировки."""
    hrefs = hrefs or Hrefs()
    items: list[ImportantItem] = []
    if wizard.reminder_due(state, today):
        done, total = wizard.progress(state)
        items.append(ImportantItem("security-wizard", _t(lang, "Настройте безопасность", "Налаштуйте безпеку"),
                                   _t(lang, f"Мастер безопасности: решено {done} из {total} шагов",
                                      f"Майстер безпеки: вирішено {done} з {total} кроків"), hrefs.wizard, today))
    for code, until in wizard.due_deferred(state, today):
        title, _lead = help.wizard_text(code, lang)
        items.append(ImportantItem(f"security-wizard-deferred:{code}", _t(lang, "Отложенная мера: ", "Відкладений захід: ") + title,
                                   _t(lang, "Срок отсрочки ", "Строк відкладення ") + f"{until:%d.%m.%Y}",
                                   hrefs.wizard_step.format(code=code), until))
    left = recommendations.pc_remaining(reco_state or {}, today)
    if left:
        items.append(ImportantItem("security-protect-pc", help.ui("protect_pc", lang),
                                   _t(lang, f"Осталось пунктов: {left}", f"Залишилося пунктів: {left}"), hrefs.protect_pc, today))
    if training_facts is not None:
        for item in training.due_items(training_facts, today):
            label = f"{item.kind}:{item.method}" if item.method else item.kind
            key = (OVERDUE_PREFIX if item.overdue else "security-train:") + item.key.removeprefix("train:")
            note = (help.training_text("overdue", lang) + " · " if item.overdue else "") + f"{item.due:%d.%m.%Y}"
            items.append(ImportantItem(key, help.training_text(label, lang), note, hrefs.train(item), item.due, blink=item.overdue))
    return items


def recommendation_items(reco_state: Mapping[str, object] | None, today: date, *, hrefs: Hrefs | None = None,
                         lang: str = "ru") -> list[ImportantItem]:
    """«Рекомендации по настройке работы системы» (285): не мигают; снимаются «Уже установлено» / «Отложить…»."""
    hrefs = hrefs or Hrefs()
    items = []
    for code in recommendations.visible_recommendations(reco_state, today):
        rec = recommendations.recommendation(code, lang)
        note = rec.title + (" (" + rec.partner_note + ")" if rec.partner else "")
        items.append(ImportantItem(f"security-reco:{code}", _t(lang, "Рекомендация по настройке системы · ", "Рекомендація з налаштування системи · ")
                                   + rec.title.split(" — ")[0], note, hrefs.level, today))
    return items


def pin_paused_item(paused_until: int, now: int, today: date, *, hrefs: Hrefs | None = None, lang: str = "ru") -> ImportantItem | None:
    """Пауза PIN после 5 ошибок: строка «проверьте журнал», не тревога."""
    if paused_until <= now:
        return None
    hrefs = hrefs or Hrefs()
    return ImportantItem("security-pin-paused", _t(lang, "PIN важных действий закрыт на 10 минут после 5 ошибок",
                                                   "PIN важливих дій закрито на 10 хвилин після 5 помилок"),
                         _t(lang, "Если PIN вводили не вы — проверьте журнал безопасности и смените PIN",
                            "Якщо PIN вводили не ви — перевірте журнал безпеки та змініть PIN"), hrefs.journal, today)


def alarm_item(key: str, title: str, note: str, href: str, today: date) -> ImportantItem:
    """Настоящая тревога продукта (пароль копий 270, целостность 273, цепочка 276): красная, мигает."""
    return ImportantItem(key, title, note, href, today, alarm=True, blink=True)

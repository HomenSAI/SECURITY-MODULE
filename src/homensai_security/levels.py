# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Уровень защиты 0–5 (решение владельца 28.10-278): уровни накопительные — следующий включает предыдущий.

Здесь только правило «какие меры выполнены → какой уровень»; факты (режим копий, места, PIN…) собирает вызывающий. Тексты
мер — данные на двух языках. Рекомендации NordVPN/ESET (28.10-285) на уровень не влияют."""

from __future__ import annotations

from dataclasses import dataclass

LEVEL_TITLES: dict[str, dict[int, str]] = {
    "ru": {0: "Ненадёжно", 1: "Пароль копий", 2: "Копии вне ПК", 3: "PIN и блокировка", 4: "Контроль целостности",
           5: "Максимальная надёжность"},
    "uk": {0: "Ненадійно", 1: "Пароль копій", 2: "Копії поза ПК", 3: "PIN і блокування", 4: "Контроль цілісності",
           5: "Максимальна надійність"},
}
RECOMMENDED_LEVEL = 2  # 28.10-278: рекомендуемый минимум, ползунок мастера стоит на нём по умолчанию


@dataclass(frozen=True)
class LevelFacts:
    backup_password: bool  # копии на ключ под паролем (сгенерированный или свой)
    backup_pin_only: bool  # копии под PIN — только диски ПК (уровень 1, но не 2)
    places: int  # мест копий всего
    offsite: bool  # есть место вне ПК: флешка/внешний диск, Google Drive, NAS, Telegram
    check_days: int  # проверка пароля копий раз в N дней (0 — нет проверки)
    storage_acks: bool  # галочки хранения пароля (271)
    after_events: bool  # копии после значимых событий (268)
    pin: bool  # PIN важных действий (272)
    lock: bool  # блокировка экрана
    ttl: int  # срок PIN/блокировки в секундах, 0 — весь день
    integrity: bool  # ежедневная проверка целостности (273)
    chain: bool  # цепочка копий (276)
    office: bool  # режим «Офис»
    places_3: bool  # 3 и больше носителей
    check_14: bool  # проверка пароля раз в 2 недели
    sheet_stored: bool  # аварийный лист с отпечатком на бумаге, отметка «в сейфе»
    notify_all: bool  # уведомления безопасности в бот «Система»


@dataclass(frozen=True)
class Measure:
    level: int
    code: str
    title: str
    done: bool


_MEASURES: tuple[tuple[int, str, dict[str, str]], ...] = (
    (1, "backup_password", {"ru": "Копии с паролем или PIN (PIN — только диски ПК)", "uk": "Копії з паролем або PIN (PIN — лише диски ПК)"}),
    (1, "second_place", {"ru": "Копия на второй диск или флешку", "uk": "Копія на другий диск або флешку"}),
    (2, "real_password", {"ru": "Пароль копий, а не PIN", "uk": "Пароль копій, а не PIN"}),
    (2, "offsite", {"ru": "Одно из мест — вне ПК (флешка, Google Drive, NAS, Telegram)", "uk": "Одне з місць — поза ПК (флешка, Google Drive, NAS, Telegram)"}),
    (2, "check_month", {"ru": "Проверка пароля копий не реже раза в месяц", "uk": "Перевірка пароля копій не рідше разу на місяць"}),
    (2, "storage_acks", {"ru": "Отмечено, где хранится пароль копий", "uk": "Позначено, де зберігається пароль копій"}),
    (2, "after_events", {"ru": "Копии после значимых событий", "uk": "Копії після значущих подій"}),
    (3, "pin", {"ru": "PIN для важных действий", "uk": "PIN для важливих дій"}),
    (3, "lock_30", {"ru": "Блокировка экрана не позже 30 минут бездействия", "uk": "Блокування екрана не пізніше 30 хвилин бездіяльності"}),
    (4, "integrity", {"ru": "Ежедневная проверка целостности базы", "uk": "Щоденна перевірка цілісності бази"}),
    (4, "chain", {"ru": "Цепочка копий проверяется", "uk": "Ланцюжок копій перевіряється"}),
    (5, "office_5", {"ru": "Режим «Офис», блокировка через 5 минут", "uk": "Режим «Офіс», блокування через 5 хвилин"}),
    (5, "places_3", {"ru": "3 и больше носителей", "uk": "3 і більше носіїв"}),
    (5, "check_14", {"ru": "Проверка пароля раз в 2 недели", "uk": "Перевірка пароля раз на 2 тижні"}),
    (5, "sheet_stored", {"ru": "Аварийный лист с отпечатком ключа — в сейфе", "uk": "Аварійний аркуш із відбитком ключа — у сейфі"}),
    (5, "notify_all", {"ru": "Уведомления безопасности в бот «Система»", "uk": "Сповіщення безпеки в бот «Система»"}),
)


def _done(code: str, f: LevelFacts) -> bool:
    short = f.ttl != 0 and f.ttl <= 1800
    return {
        "backup_password": f.backup_password or f.backup_pin_only,
        "second_place": f.places >= 2,
        "real_password": f.backup_password,
        "offsite": f.offsite,
        "check_month": 0 < f.check_days <= 31,
        "storage_acks": f.storage_acks,
        "after_events": f.after_events,
        "pin": f.pin,
        "lock_30": f.lock and short,
        "integrity": f.integrity,
        "chain": f.chain,
        "office_5": f.office and f.lock and f.ttl != 0 and f.ttl <= 300,
        "places_3": f.places_3 or f.places >= 3,
        "check_14": f.check_14 or 0 < f.check_days <= 14,
        "sheet_stored": f.sheet_stored,
        "notify_all": f.notify_all,
    }[code]


def level_measures(facts: LevelFacts, lang: str = "ru") -> list[Measure]:
    lang = lang if lang in LEVEL_TITLES else "ru"
    return [Measure(level, code, texts[lang], _done(code, facts)) for level, code, texts in _MEASURES]


def level(facts: LevelFacts) -> int:
    """Наибольший уровень, все меры которого и всех уровней ниже выполнены."""
    reached = 0
    for value in range(1, 6):
        if all(_done(code, facts) for lvl, code, _texts in _MEASURES if lvl == value):
            reached = value
        else:
            break
    return reached


def level_measures_for(target: int, lang: str = "ru") -> list[tuple[int, str]]:
    """Меры выбранного уровня накопительно — для списка под ползунком (мастер, справка): (уровень меры, текст)."""
    lang = lang if lang in LEVEL_TITLES else "ru"
    return [(lvl, texts[lang]) for lvl, _code, texts in _MEASURES if lvl <= target]


def missing_for(facts: LevelFacts, target: int, lang: str = "ru") -> list[Measure]:
    """Отклонения от выбранного уровня: меры уровня `target` и ниже, которые сейчас не выполнены (блок «Уровень защиты»)."""
    return [m for m in level_measures(facts, lang) if m.level <= target and not m.done]

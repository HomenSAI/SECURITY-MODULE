# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Уровень защиты 0–6 (решения владельца 28.10-278, 373, 374): уровни 2–6 накопительные (прежние 1–5), уровень 1 «Только PIN» — отдельная ступень ниже.

Здесь только правило «какие меры выполнены → какой уровень»; факты (режим копий, места, PIN…) собирает вызывающий. Тексты
мер — данные на двух языках. Рекомендации NordVPN/ESET (28.10-285) на уровень не влияют."""

from __future__ import annotations

from dataclasses import dataclass

LEVEL_TITLES: dict[str, dict[int, str]] = {
    "ru": {0: "Без защиты", 1: "Только PIN", 2: "Пароль копий", 3: "Копии вне ПК", 4: "PIN и блокировка", 5: "Контроль целостности",
           6: "Максимальная надёжность"},
    "uk": {0: "Без захисту", 1: "Лише PIN", 2: "Пароль копій", 3: "Копії поза ПК", 4: "PIN і блокування", 5: "Контроль цілісності",
           6: "Максимальна надійність"},
}
MAX_LEVEL = 6
RECOMMENDED_LEVEL = 3  # 28.10-278/373: рекомендуемый минимум (прежний 2), ползунок мастера стоит на нём по умолчанию


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
    pin_login: bool = False  # 28.10-373: вход в программу по PIN (уровень 1)
    email_login_weak: bool = False  # 28.10-344: вход по коду из почты включён без второго фактора — уровень 3 не засчитывается


@dataclass(frozen=True)
class Measure:
    level: int
    code: str
    title: str
    done: bool


_MEASURES: tuple[tuple[int, str, dict[str, str]], ...] = (
    (1, "pin_login", {"ru": "Вход в программу по PIN", "uk": "Вхід у програму за PIN"}),
    (1, "lock_any", {"ru": "Блокировка экрана включена", "uk": "Блокування екрана ввімкнено"}),
    (2, "backup_password", {"ru": "Копии с паролем или PIN (PIN — только диски ПК)", "uk": "Копії з паролем або PIN (PIN — лише диски ПК)"}),
    (2, "second_place", {"ru": "Копия на второй диск или флешку", "uk": "Копія на другий диск або флешку"}),
    (3, "real_password", {"ru": "Пароль копий, а не PIN", "uk": "Пароль копій, а не PIN"}),
    (3, "offsite", {"ru": "Одно из мест — вне ПК (флешка, Google Drive, NAS, Telegram)", "uk": "Одне з місць — поза ПК (флешка, Google Drive, NAS, Telegram)"}),
    (3, "check_month", {"ru": "Проверка пароля копий не реже раза в месяц", "uk": "Перевірка пароля копій не рідше разу на місяць"}),
    (3, "storage_acks", {"ru": "Отмечено, где хранится пароль копий", "uk": "Позначено, де зберігається пароль копій"}),
    (3, "after_events", {"ru": "Копии после значимых событий", "uk": "Копії після значущих подій"}),
    (4, "pin", {"ru": "PIN для важных действий", "uk": "PIN для важливих дій"}),
    (4, "lock_30", {"ru": "Блокировка экрана не позже 30 минут бездействия", "uk": "Блокування екрана не пізніше 30 хвилин бездіяльності"}),
    (4, "email_login_2fa", {"ru": "Вход по коду из почты — только вместе с ключом или Google Authenticator (почта не должна быть единственным способом входа без второго фактора)",
                            "uk": "Вхід за кодом із пошти — лише разом із ключем або Google Authenticator (пошта не має бути єдиним способом входу без другого фактора)"}),
    (5, "integrity", {"ru": "Ежедневная проверка целостности базы", "uk": "Щоденна перевірка цілісності бази"}),
    (5, "chain", {"ru": "Цепочка копий проверяется", "uk": "Ланцюжок копій перевіряється"}),
    (6, "office_5", {"ru": "Режим «Офис», блокировка через 5 минут", "uk": "Режим «Офіс», блокування через 5 хвилин"}),
    (6, "places_3", {"ru": "3 и больше носителей", "uk": "3 і більше носіїв"}),
    (6, "check_14", {"ru": "Проверка пароля раз в 2 недели", "uk": "Перевірка пароля раз на 2 тижні"}),
    (6, "sheet_stored", {"ru": "Аварийный лист с отпечатком ключа — в сейфе", "uk": "Аварійний аркуш із відбитком ключа — у сейфі"}),
    (6, "notify_all", {"ru": "Уведомления безопасности в бот «Система»", "uk": "Сповіщення безпеки в бот «Система»"}),
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
        "pin_login": f.pin_login,
        "lock_any": f.lock,
        "pin": f.pin,
        "lock_30": f.lock and short,
        "email_login_2fa": not f.email_login_weak,
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
    """Достигнутый уровень. Цепочка 2–6 накопительная (прежние 1–5): наибольший уровень, все меры которого и нижних до 2 выполнены.
    Если до уровня 2 не дошли, уровень 1 даёт «вход по PIN + блокировка экрана», иначе 0 «Без защиты»."""
    reached = 0
    for value in range(2, MAX_LEVEL + 1):
        if all(_done(code, facts) for lvl, code, _texts in _MEASURES if lvl == value):
            reached = value
        else:
            break
    if reached:
        return reached
    return 1 if all(_done(code, facts) for lvl, code, _texts in _MEASURES if lvl == 1) else 0


def _in_branch(measure_level: int, target: int) -> bool:
    """Меры уровня 1 («вход по PIN», блокировка) входят в список только для выбранного уровня 1: цепочка 2–6 — прежние уровни 1–5, их вход остаётся по паролю."""
    return measure_level >= 2 or target == 1


def level_measures_for(target: int, lang: str = "ru") -> list[tuple[int, str]]:
    """Меры выбранного уровня накопительно — для списка под ползунком (мастер, справка): (уровень меры, текст)."""
    lang = lang if lang in LEVEL_TITLES else "ru"
    return [(lvl, texts[lang]) for lvl, _code, texts in _MEASURES if lvl <= target and _in_branch(lvl, target)]


def missing_for(facts: LevelFacts, target: int, lang: str = "ru") -> list[Measure]:
    """Отклонения от выбранного уровня: меры уровня `target` и ниже, которые сейчас не выполнены (блок «Уровень защиты»)."""
    return [m for m in level_measures(facts, lang) if m.level <= target and _in_branch(m.level, target) and not m.done]

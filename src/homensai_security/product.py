# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Настройка модуля под продукт (решение владельца 28.10-332: модуль подключают разные проекты).

Тексты модуля (ошибки, помощь, аварийный лист) написаны для первого продукта — HomenS.AI Rent: в них есть название
продукта, команды на ПК и папка копий. `configure(Product(...))` один раз при старте продукта подставляет свои значения
во все таблицы текстов модуля. Без вызова действуют значения Rent (`RENT`), поэтому Rent работает без изменений.

Замена — точная подстановка известных строк (`Product.replacements`), без шаблонизатора и без выполнения кода; исходные
таблицы сохраняются при импорте, поэтому повторный `configure` всегда начинает с исходного текста, а `configure(RENT)`
возвращает всё как было. Модуль не хранит состояние продукта вне этих таблиц.
"""

from __future__ import annotations

import copy
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class Product:
    """Что подставить в тексты модуля.

    `name` — название продукта в текстах («HomenS.AI Rent»); `ctl` — команда служебной утилиты на ПК (сброс пароля входа,
    восстановление копии); `bot` — команда запуска бота; `copies_folder` — имя корневой папки копий на носителе.
    """

    name: str
    ctl: str
    bot: str
    copies_folder: str

    def replacements(self) -> tuple[tuple[str, str], ...]:
        """Пары «исходная строка Rent → строка продукта»; длинные раньше коротких, чтобы части не заменялись дважды."""
        pairs = ((RENT.name, self.name), (RENT.ctl, self.ctl), (RENT.bot, self.bot), (RENT.copies_folder, self.copies_folder))
        return tuple(sorted(pairs, key=lambda pair: -len(pair[0])))


RENT = Product(name="HomenS.AI Rent", ctl="python -m app.ctl", bot="python -m app.bot", copies_folder="HomensaiRent")

_current: Product = RENT
_originals: list[tuple[Any, Any]] = []  # (живая таблица, её исходная копия)


def current() -> Product:
    """Продукт, под который сейчас настроены тексты."""
    return _current


def _register(*tables: Any) -> None:
    for table in tables:
        if all(table is not live for live, _orig in _originals):
            _originals.append((table, copy.deepcopy(table)))


def _substitute(value: Any, pairs: tuple[tuple[str, str], ...]) -> Any:
    if isinstance(value, str):
        for old, new in pairs:
            value = value.replace(old, new)
        return value
    if isinstance(value, dict):
        return {key: _substitute(item, pairs) for key, item in value.items()}
    if isinstance(value, list):
        return [_substitute(item, pairs) for item in value]
    if isinstance(value, tuple):
        return tuple(_substitute(item, pairs) for item in value)
    return value


def _tables() -> None:
    """Регистрирует все таблицы текстов модуля (импорт здесь, чтобы `product` не зависел от порядка импорта)."""
    from homensai_security import auth_errors, auth_texts, errors, help_ru, help_uk, sheet

    _register(errors.ERRORS, auth_errors.AUTH_ERRORS, auth_texts.TEXTS, sheet.TEXTS)
    for module in (help_ru, help_uk):
        _register(module.UI, module.PAGES, module.INCIDENTS, module.LEVELS, module.PC, module.WIZARD, module.TRAINING)


def configure(product: Product) -> Product:
    """Подставляет значения продукта во все тексты модуля; возвращает прежний продукт. Повторный вызов безопасен."""
    global _current
    for field in (product.name, product.ctl, product.bot, product.copies_folder):
        if not field.strip():
            raise ValueError("Все поля Product обязательны")
    _tables()
    previous = _current
    pairs = product.replacements()
    for live, original in _originals:
        fresh = _substitute(original, pairs)
        if isinstance(live, dict):
            live.clear()
            live.update(fresh)
        else:  # pragma: no cover — все таблицы модуля — словари
            raise TypeError(f"неизменяемая таблица текстов: {type(live).__name__}")
    _current = product
    return previous

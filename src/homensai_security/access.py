# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Роли и права без привязки к продукту (MOD.extract-access, решения 286, 332).

Источник — Rent `app/platform/permissions.py` (каталог прав, старые имена, предустановленные роли Совладелец / Помощник /
Риэлтор / Бухгалтер) и правила проверки из `app/platform/access.py`. Продукт описывает свой каталог `Catalog`
(права, старые имена → новые, роли), модуль только решает:

- неизвестное право **никогда** не разрешено (опечатка в имени не превращается в доступ);
- старое имя права переводится в новое по явной таблице;
- обновление предустановленной роли не перезаписывает роль, которую владелец изменил сам (`preset_update_allowed`).

Пользователи и хранение ролей — у продукта или ядра (HomenS.AI Core); модуль не хранит состояние.
"""

from __future__ import annotations

from collections.abc import Iterable, Mapping
from dataclasses import dataclass, field
from types import MappingProxyType


class UnknownPermissionError(KeyError):
    """Права нет в каталоге продукта: запрет, а не молчаливое разрешение."""


@dataclass(frozen=True)
class Role:
    """Предустановленная роль: идентификатор, название для людей, набор прав."""

    id: str
    name: str
    permissions: frozenset[str]


@dataclass(frozen=True)
class Catalog:
    """Каталог прав продукта: полные имена (`rent.units.read`), старые короткие имена и предустановленные роли."""

    permissions: frozenset[str]
    legacy: Mapping[str, str] = field(default_factory=lambda: MappingProxyType({}))
    roles: tuple[Role, ...] = ()

    def __post_init__(self) -> None:
        unknown = {target for target in self.legacy.values() if target not in self.permissions}
        for role in self.roles:
            unknown |= role.permissions - self.permissions
        if unknown:
            raise UnknownPermissionError(f"права вне каталога: {sorted(unknown)}")

    def canonical(self, name: str) -> str:
        """Полное имя права; неизвестное — UnknownPermissionError."""
        if name in self.permissions:
            return name
        if name in self.legacy:
            return self.legacy[name]
        raise UnknownPermissionError(name)

    def role(self, role_id: str) -> Role:
        for role in self.roles:
            if role.id == role_id:
                return role
        raise KeyError(role_id)


def allowed(catalog: Catalog, granted: Iterable[str], name: str) -> bool:
    """Есть ли право `name` (полное или старое имя) среди выданных `granted`. Неизвестное имя — False, не исключение."""
    try:
        wanted = catalog.canonical(name)
    except UnknownPermissionError:
        return False
    have = set()
    for item in granted:
        try:
            have.add(catalog.canonical(item))
        except UnknownPermissionError:
            continue  # устаревшее выданное право, которого больше нет, ничего не открывает
    return wanted in have


def require(catalog: Catalog, granted: Iterable[str], name: str) -> None:
    """Как `allowed`, но отказ — PermissionError (адаптер переводит в 403 / ForbiddenError продукта)."""
    if not allowed(catalog, granted, name):
        raise PermissionError(name)


def preset_update_allowed(saved_name: str, saved_permissions: Iterable[str], preset: Role, previous_presets: Iterable[frozenset[str]]) -> bool:
    """Можно ли обновить сохранённую роль до нового набора предустановки.

    Да — только если сохранённая роль совпадает с одной из прежних предустановок целиком, включая название: это штатное
    обновление, а не перезапись роли, настроенной владельцем (правило Rent `install_roles`)."""
    return saved_name == preset.name and frozenset(saved_permissions) in {frozenset(p) for p in previous_presets}

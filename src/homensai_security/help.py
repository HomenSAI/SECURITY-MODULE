# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Помощь по безопасности (решения 28.10-277, 283, 287, 289, 290): доступ к текстам RU/UK (`help_ru`, `help_uk`).

- «Если случилось» (`INCIDENT_IDS`) — первой страницей: 6 сценариев со ссылками на нужные места раздела;
- страница на каждую меру (`PAGE_IDS`) по одному шаблону: что это / от чего защищает / от чего НЕ защищает / что нужно от вас /
  схема «угроза → мера → результат» / частые вопросы;
- «Как защитить компьютер и аккаунты» (`PC_ITEMS`, 290); уровни 0–5 для интерактивного ползунка (278);
- `BLOCK_PAGES` — какая страница открывается по «?» у блока раздела «Безопасность».
Ссылки в данных — абстрактные цели (`section:<блок>`, `page:<страница>`, `errors`, `training:<дело>`): модуль не знает адресов
продукта; их подставляет привязка. `problems()` сверяет оба языка: одинаковые ключи и непустые тексты."""

from __future__ import annotations

from dataclasses import dataclass
from types import ModuleType

from homensai_security import help_ru, help_uk, levels
from homensai_security.errors import SecurityError
from homensai_security.recommendations import PC_ITEMS
from homensai_security.wizard import STEP_CODES

LANGS = ("ru", "uk")
PAGE_IDS = tuple(help_ru.PAGES)
INCIDENT_IDS = tuple(help_ru.INCIDENTS)
SECTION_BLOCKS = ("alerts", "level", "login", "actions", "backups", "integrity", "notify", "journal")
# «?» у блока раздела: alerts — «Если случилось» (пустая строка — главная страница помощи по безопасности)
BLOCK_PAGES = {"alerts": "", "level": "training", "login": "login-password", "actions": "pin", "backups": "backup-password",
               "integrity": "integrity", "notify": "notify", "journal": "journal"}
TARGET_KINDS = ("section", "page", "errors", "training")


def texts(lang: str) -> ModuleType:
    return help_uk if lang == "uk" else help_ru


def ui(key: str, lang: str = "ru", **values: object) -> str:
    text = str(texts(lang).UI[key])
    return text.format(**values) if values else text


@dataclass(frozen=True)
class Page:
    ident: str
    title: str
    section: str
    what: str
    protects: tuple[str, ...]
    not_protects: tuple[str, ...]
    needs: tuple[str, ...]
    diagram: tuple[tuple[str, str, str], ...]
    faq: tuple[tuple[str, str], ...]


@dataclass(frozen=True)
class Incident:
    ident: str
    title: str
    steps: tuple[str, ...]
    links: tuple[tuple[str, str], ...]  # (подпись, цель)


@dataclass(frozen=True)
class PcItem:
    code: str
    title: str
    minutes: int
    without: str
    how: str


def _strs(value: object) -> tuple[str, ...]:
    return tuple(str(x) for x in value) if isinstance(value, list | tuple) else ()


def page(ident: str, lang: str = "ru") -> Page:
    data = texts(lang).PAGES.get(ident)
    if not isinstance(data, dict):
        raise SecurityError("help_unknown")
    diagram = tuple((str(r[0]), str(r[1]), str(r[2])) for r in data["diagram"])
    faq = tuple((str(q), str(a)) for q, a in data["faq"])
    return Page(ident, str(data["title"]), str(data["section"]), str(data["what"]), _strs(data["protects"]),
                _strs(data["not_protects"]), _strs(data["needs"]), diagram, faq)


def pages(lang: str = "ru") -> list[Page]:
    return [page(ident, lang) for ident in PAGE_IDS]


def incident(ident: str, lang: str = "ru") -> Incident:
    data = texts(lang).INCIDENTS.get(ident)
    if not isinstance(data, dict):
        raise SecurityError("help_unknown")
    return Incident(ident, str(data["title"]), _strs(data["steps"]), tuple((str(t), str(target)) for t, target in data["links"]))


def incidents(lang: str = "ru") -> list[Incident]:
    return [incident(ident, lang) for ident in INCIDENT_IDS]


def pc_item(code: str, lang: str = "ru") -> PcItem:
    data = texts(lang).PC.get(code)
    if not isinstance(data, dict):
        raise SecurityError("help_unknown")
    return PcItem(code, str(data["title"]), int(data["minutes"]), str(data["without"]), str(data["how"]))


def pc_items(lang: str = "ru") -> list[PcItem]:
    return [pc_item(code, lang) for code in PC_ITEMS]


@dataclass(frozen=True)
class LevelInfo:
    level: int
    title: str
    threats: str
    measures: tuple[tuple[int, str], ...]  # (уровень меры, текст) — накопительно: меры всех уровней до этого


def level_info(value: int, lang: str = "ru") -> LevelInfo:
    """Описание уровня для ползунка в справке: что защищает и меры (накопительно)."""
    if isinstance(value, bool) or not isinstance(value, int) or not 0 <= value <= 5:
        raise SecurityError("wizard_level")
    titles = levels.LEVEL_TITLES["uk" if lang == "uk" else "ru"]
    return LevelInfo(value, titles[value], str(texts(lang).LEVELS[value]), tuple(levels.level_measures_for(value, lang)))


def wizard_text(step: str, lang: str = "ru") -> tuple[str, str]:
    data = texts(lang).WIZARD.get(step)
    if not isinstance(data, dict):
        raise SecurityError("wizard_step")
    return str(data["title"]), str(data["lead"])


def training_text(key: str, lang: str = "ru") -> str:
    return str(texts(lang).TRAINING.get(key, key))


def problems() -> list[str]:
    """Расхождения языков и пропуски: одинаковые ключи, непустые тексты, верные цели ссылок, шаблон страницы целиком."""
    found: list[str] = []
    ru, uk = help_ru, help_uk
    for name in ("UI", "PAGES", "INCIDENTS", "LEVELS", "PC", "WIZARD", "TRAINING"):
        a, b = getattr(ru, name), getattr(uk, name)
        if set(a) != set(b):
            found.append(f"{name}: ключи RU/UK различаются: {sorted(set(a) ^ set(b), key=str)}")
    for module in (ru, uk):
        lang = module.__name__.rsplit("_", 1)[-1]
        for ident, data in module.PAGES.items():
            for part in ("title", "section", "what", "protects", "not_protects", "needs", "diagram", "faq"):
                if not data.get(part):
                    found.append(f"{lang}:{ident}: нет части {part}")
            if data.get("section") not in SECTION_BLOCKS:
                found.append(f"{lang}:{ident}: неизвестный блок {data.get('section')}")
            if any(len(row) != 3 or not all(row) for row in data.get("diagram", [])):
                found.append(f"{lang}:{ident}: схема — три непустых части")
        for ident, data in module.INCIDENTS.items():
            for _label, target in data["links"]:
                kind, _, rest = str(target).partition(":")
                if kind not in TARGET_KINDS or (kind == "page" and rest not in module.PAGES) or (kind == "section" and rest not in SECTION_BLOCKS):
                    found.append(f"{lang}:{ident}: неверная цель {target}")
        if set(module.PC) != set(PC_ITEMS):
            found.append(f"{lang}: пункты «Как защитить компьютер» не совпадают с PC_ITEMS")
        if set(module.WIZARD) != set(STEP_CODES):
            found.append(f"{lang}: тексты мастера не совпадают с шагами")
        if set(module.LEVELS) != set(range(6)):
            found.append(f"{lang}: уровни 0–5")
    if len(INCIDENT_IDS) != 6:
        found.append("«Если случилось»: ровно 6 сценариев (283)")
    return found

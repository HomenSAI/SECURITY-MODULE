# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Сборка `docs/help/SECURITY_HELP.md` из данных помощи по безопасности (решения 28.10-283 п. 3.5, 286 п. 1, 289, 290).

Источник — `src/homensai_security/help_ru.py` (тот же текст, что во встроенной помощи `/help/security`); файл не правится руками.
Запуск: ``python scripts/build_security_help.py`` (записать) или ``--check`` (код 1, если файл устарел)."""

from __future__ import annotations

import argparse
from pathlib import Path
import sys

ROOT = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(ROOT / "src"))
from homensai_security import public_api as security  # noqa: E402 — корень проекта добавлен выше для запуска скрипта напрямую

TARGET = ROOT / "docs" / "help" / "SECURITY_HELP.md"
HEADER = "<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->"


def _link(target: str) -> str:
    kind, _, rest = target.partition(":")
    if kind == "section":
        return f"раздел «Безопасность», `/security#{rest}`"
    if kind == "page":
        return f"страница помощи `/help/security/{rest}`"
    if kind == "training":
        return f"тренировка `/security/training/{rest}`"
    return "коды ошибок `/help/security/errors`"


def build() -> str:
    """Текст файла: «Если случилось», «Как защитить компьютер и аккаунты», уровни 0–5, страницы мер."""
    help_ = security.help
    out: list[str] = [HEADER, "", "# Помощь по безопасности", "",
                      "Собрано из `src/homensai_security/help_ru.py` командой `python scripts/build_security_help.py`; тот же текст — во встроенной "
                      "помощи `/help/security` (украинский — `help_uk.py`). Не править руками.", "",
                      f"## {help_.ui('incidents')}", ""]
    for incident in help_.incidents():
        out += [f"### {incident.title}", ""]
        out += [f"{n}. {step}" for n, step in enumerate(incident.steps, 1)]
        out += ["", "Куда идти: " + "; ".join(f"{label} — {_link(target)}" for label, target in incident.links) + ".", ""]
    out += [f"## {help_.ui('protect_pc')}", "", help_.ui("protect_pc_lead"), ""]
    for item in help_.pc_items():
        line = f"- **{item.title}** ({help_.ui('minutes', minutes=item.minutes)}). {help_.ui('without')}: {item.without} {item.how}"
        if item.code in security.RECOMMENDATION_CODES:
            rec = security.recommendation(item.code)
            line += f" Ссылка: {rec.url}" + (f" ({rec.partner_note})." if rec.partner else ".")
        out.append(line)
    out += ["", f"## {help_.ui('levels')}", ""]
    for level in range(6):
        info = help_.level_info(level)
        out.append(f"- **{level} — {info.title}.** {help_.ui('level_threats')}: {info.threats}")
    out += ["", f"## {help_.ui('measures')}", ""]
    for page in help_.pages():
        out += [f"### {page.title}", "", f"**{help_.ui('what')}.** {page.what}", "", f"**{help_.ui('protects')}:**", ""]
        out += [f"- {x}" for x in page.protects]
        out += ["", f"**{help_.ui('not_protects')}:**", ""]
        out += [f"- {x}" for x in page.not_protects]
        out += ["", f"**{help_.ui('needs')}:**", ""]
        out += [f"- {x}" for x in page.needs]
        out += ["", f"**{help_.ui('diagram')}:**", "", f"| {help_.ui('threat')} | {help_.ui('measure')} | {help_.ui('result')} |", "|---|---|---|"]
        out += [f"| {t} | {m} | {r} |" for t, m, r in page.diagram]
        out += ["", f"**{help_.ui('faq')}:**", ""]
        out += [f"- *{q}* {a}" for q, a in page.faq]
        out.append("")
    return "\n".join(out)


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--check", action="store_true", help="только проверить, что файл совпадает с данными")
    args = parser.parse_args(argv)
    text = build()
    if args.check:
        current = TARGET.read_text(encoding="utf-8") if TARGET.exists() else ""
        if current != text:
            print("docs/SECURITY_HELP.md устарел: запустите python scripts/build_security_help.py")
            return 1
        return 0
    TARGET.write_text(text, encoding="utf-8")
    print(f"Записано: {TARGET.relative_to(ROOT)}")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

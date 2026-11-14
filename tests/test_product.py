# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Настройка текстов модуля под продукт (решение 28.10-332): подстановка названия, команд и папки копий; возврат к Rent."""

from __future__ import annotations

from collections.abc import Iterator
import json

import pytest

from homensai_security import public_api as security
from homensai_security import sheet
from homensai_security.product import RENT, Product, configure, current

JOBPILOT = Product(name="JobPilot Pro", ctl="jobpilot-ctl", bot="jobpilot-bot", copies_folder="JobPilot")


@pytest.fixture(autouse=True)
def _back_to_rent() -> Iterator[None]:
    yield
    configure(RENT)


def _all_text() -> str:
    from homensai_security import auth_errors, errors, help_ru, help_uk

    tables = [errors.ERRORS, auth_errors.AUTH_ERRORS, sheet.TEXTS, help_ru.PAGES, help_uk.PAGES, help_ru.INCIDENTS, help_uk.INCIDENTS]
    return json.dumps(tables, ensure_ascii=False, default=str)


def test_default_is_rent_and_texts_mention_rent() -> None:
    assert current() == RENT
    text = _all_text()
    assert "HomenS.AI Rent" in text
    assert "python -m app.ctl" in text


def test_configure_replaces_every_product_string_and_is_reversible() -> None:
    before = _all_text()
    assert configure(JOBPILOT) == RENT
    text = _all_text()
    for old in ("HomenS.AI Rent", "python -m app.ctl", "python -m app.bot", "HomensaiRent"):
        assert old not in text, old
    assert "JobPilot Pro" in text
    assert "jobpilot-ctl" in text
    lines = security.sheet_lines(security.SheetData(household_fingerprint="HR1-AAAA", signing_fingerprint=None))
    assert any("JobPilot Pro" in line for line in lines)
    configure(JOBPILOT)  # повтор — тот же результат, без двойной замены
    assert _all_text() == text
    configure(RENT)
    assert _all_text() == before


def test_configure_requires_all_fields() -> None:
    with pytest.raises(ValueError, match="обязательны"):
        configure(Product(name="X", ctl="", bot="b", copies_folder="c"))
    assert current() == RENT

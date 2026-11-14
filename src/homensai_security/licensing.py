# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Лицензирование: файл открытых ключей и порог бесплатного режима (MOD.extract-licensing, решения 286, 332).

Источник — Rent `app/platform/licensing.py`: файл содержит **только открытые ключи** (`{"keys": [{"key_id", "public_key_hex"}]}`);
без файла — бесплатный режим с порогом (в Rent — одна неархивная квартира); чтение, экспорт и копии не ограничиваются.
Проверку подписи лицензии и учёт ключей делает ядро HomenS.AI Core (`backend.modules.licensing`); модуль даёт продукту
разбор файла ключей (строгий, без лишних полей) и проверку роста числа объектов «до и после» внутри транзакции.
"""

from __future__ import annotations

from collections.abc import Callable
from dataclasses import dataclass
import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey


class LicenseConfigError(ValueError):
    """Файл открытых ключей лицензии повреждён или содержит лишнее."""


class QuotaExceededError(RuntimeError):
    """Бесплатный порог превышен: нужна лицензия (текст и код — у продукта)."""


@dataclass(frozen=True)
class VerificationKey:
    key_id: str
    public_key: bytes  # 32 байта Ed25519


def read_keys_file(path: Path) -> tuple[VerificationKey, ...]:
    """Открытые ключи из файла; любое отклонение от формата — LicenseConfigError (не молчаливый бесплатный режим)."""
    try:
        raw = json.loads(path.read_text(encoding="utf-8"))
        keys = []
        for item in raw["keys"]:
            if set(item) != {"key_id", "public_key_hex"}:
                raise ValueError("лишние или отсутствующие поля")
            public = bytes.fromhex(item["public_key_hex"])
            Ed25519PublicKey.from_public_bytes(public)  # не 32 байта / не точка кривой — ошибка
            if not isinstance(item["key_id"], str) or not item["key_id"].strip():
                raise ValueError("пустой key_id")
            keys.append(VerificationKey(item["key_id"], public))
    except (OSError, ValueError, KeyError, TypeError) as exc:
        raise LicenseConfigError("Не прочитан корректный файл открытых ключей лицензии") from exc
    return tuple(keys)


def growth_guard(count: Callable[[], int], allowed_without_license: int, licensed: Callable[[int], bool]) -> Callable[[], None]:
    """Снимок числа объектов (после BEGIN IMMEDIATE); возвращённая проверка вызывается до COMMIT.

    Рост выше порога без лицензии — QuotaExceededError. `licensed(n)` — разрешает ли лицензия n объектов (решает ядро)."""
    before = count()

    def check() -> None:
        after = count()
        if after > before and after > allowed_without_license and not licensed(after):
            raise QuotaExceededError(f"бесплатно доступно объектов: {allowed_without_license}")

    return check

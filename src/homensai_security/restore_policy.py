# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Правила вокруг восстановления копии и хранения (решение 333 пп. 4, 7).

- `stale_after_restore` (п. 7, как Actual Budget): после восстановления старой копии в базе снова лежат сообщения и
  напоминания из прошлого; отправлять их нельзя — жилец получил бы уже оплаченный счёт или старое напоминание. Продукт
  перед первым запуском после восстановления помечает такие записи «не отправлять».
- `object_lock_problem` (п. 4, как object lock Kopia): неизменяемость копий на стороне облака S3/NAS — срок блокировки должен
  перекрывать срок хранения ротации, иначе ротация не сможет удалить копию, а защита закончится раньше, чем нужно.
"""

from __future__ import annotations

from collections.abc import Iterable
from datetime import datetime


def stale_after_restore(pending: Iterable[tuple[str, datetime]], restored_at: datetime) -> list[str]:
    """Идентификаторы неотправленных сообщений/напоминаний, созданных до восстановления (они пришли из старой копии) —
    их не отправлять. Созданные после `restored_at` — новые, отправляются обычно."""
    return [ident for ident, created in pending if created < restored_at]


def object_lock_problem(lock_days: int, retention_days: int) -> str | None:
    """Проверка настройки неизменяемости в облаке: блокировка не короче хранения и не бесконечна (иначе место кончится)."""
    if lock_days <= 0:
        return "срок блокировки должен быть больше нуля"
    if lock_days < retention_days:
        return f"блокировка {lock_days} дн. короче хранения {retention_days} дн.: копия станет удаляемой раньше срока хранения"
    if lock_days > retention_days + 400:
        return "блокировка дольше хранения больше чем на год: удалить старые копии нельзя будет очень долго"
    return None

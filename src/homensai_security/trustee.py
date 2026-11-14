# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Доверенное лицо с ожиданием (решение 333 п. 3; образец — Bitwarden Emergency Access).

Владелец заранее назначает доверенное лицо (совладелец, наследник, бухгалтер) и срок ожидания. Доверенное лицо может
запросить доступ; владелец получает уведомления во все каналы и в течение срока может отказать. Нет отказа к концу
срока — доступ открыт (только тот уровень, что выбран при назначении: просмотр или полное восстановление). Владелец может
закрыть выданный доступ в любой момент. Модуль — только правила и состояние; хранение, уведомления и вход доверенного
лица делает продукт. Время передаёт вызывающий (секунды Unix).
"""

from __future__ import annotations

from dataclasses import dataclass, replace

from homensai_security.errors import SecurityError

WAIT_DAYS = (1, 2, 7, 14, 30)  # выбор владельца; по умолчанию 7
DEFAULT_WAIT_DAYS = 7
LEVELS = ("view", "takeover")  # просмотр данных | полное восстановление (копии, вход)
DAY = 86400


@dataclass(frozen=True)
class Trustee:
    """Назначение: кто, какой уровень, сколько ждать; состояние текущего запроса."""

    trustee_id: str
    level: str = "view"
    wait_days: int = DEFAULT_WAIT_DAYS
    requested_at: int | None = None
    denied_at: int | None = None
    revoked_at: int | None = None

    def __post_init__(self) -> None:
        if self.level not in LEVELS or self.wait_days not in WAIT_DAYS or not self.trustee_id.strip():
            raise SecurityError("trustee_invalid")


def request(t: Trustee, now: int) -> Trustee:
    """Доверенное лицо запрашивает доступ (повторный запрос при уже идущем — без изменений, ожидание не сбрасывается)."""
    if t.requested_at is not None and t.denied_at is None and t.revoked_at is None:
        return t
    return replace(t, requested_at=now, denied_at=None, revoked_at=None)


def deny(t: Trustee, now: int) -> Trustee:
    """Владелец отказал: запрос закрыт, доступ не открывается."""
    if t.requested_at is None:
        raise SecurityError("trustee_no_request")
    return replace(t, denied_at=now)


def revoke(t: Trustee, now: int) -> Trustee:
    """Владелец закрыл выданный или ожидающий доступ."""
    return replace(t, revoked_at=now)


def opens_at(t: Trustee) -> int | None:
    """Когда откроется доступ, если владелец не откажет; None — запроса нет или он закрыт."""
    if t.requested_at is None or t.denied_at is not None or t.revoked_at is not None:
        return None
    return t.requested_at + t.wait_days * DAY


def granted(t: Trustee, now: int) -> bool:
    """Открыт ли доступ сейчас."""
    moment = opens_at(t)
    return moment is not None and now >= moment


def state(t: Trustee, now: int) -> str:
    """none | waiting | granted | denied | revoked — для экрана и уведомлений."""
    if t.revoked_at is not None:
        return "revoked"
    if t.denied_at is not None:
        return "denied"
    if t.requested_at is None:
        return "none"
    return "granted" if granted(t, now) else "waiting"

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Доверенное лицо с ожиданием (решение 333 п. 3, как Bitwarden Emergency Access)."""

from __future__ import annotations

import pytest

from homensai_security import trustee
from homensai_security.errors import ERRORS, SecurityError

DAY = trustee.DAY


def test_access_opens_after_wait_without_denial() -> None:
    t = trustee.request(trustee.Trustee("own-b", level="takeover", wait_days=7), now=0)
    assert trustee.state(t, 7 * DAY - 1) == "waiting"
    assert not trustee.granted(t, 7 * DAY - 1)
    assert trustee.state(t, 7 * DAY) == "granted"
    assert trustee.request(t, now=3 * DAY) == t  # повторный запрос не сбрасывает ожидание


def test_owner_denies_or_revokes() -> None:
    t = trustee.request(trustee.Trustee("heir"), now=0)
    denied = trustee.deny(t, now=DAY)
    assert trustee.state(denied, 30 * DAY) == "denied"
    assert trustee.opens_at(denied) is None
    again = trustee.request(denied, now=40 * DAY)
    assert trustee.state(again, 40 * DAY) == "waiting"
    revoked = trustee.revoke(trustee.request(trustee.Trustee("acc"), 0), now=10 * DAY)
    assert trustee.state(revoked, 10 * DAY) == "revoked"
    assert not trustee.granted(revoked, 99 * DAY)


def test_invalid_settings_and_codes_in_catalog() -> None:
    for bad in ({"trustee_id": "x", "level": "admin"}, {"trustee_id": "x", "wait_days": 3}, {"trustee_id": " "}):
        with pytest.raises(SecurityError):
            trustee.Trustee(**bad)  # type: ignore[arg-type]
    with pytest.raises(SecurityError):
        trustee.deny(trustee.Trustee("x"), now=0)
    assert {"trustee_invalid", "trustee_no_request"} <= set(ERRORS)

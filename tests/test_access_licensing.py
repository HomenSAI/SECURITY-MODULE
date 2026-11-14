# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Роли и права (неизвестное право не разрешено, старые имена, обновление предустановки) и файл ключей лицензии."""

from __future__ import annotations

import json
from pathlib import Path

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from cryptography.hazmat.primitives.serialization import Encoding, PublicFormat
import pytest

from homensai_security import access, licensing

OWNER = access.Role("rent-owner", "Совладелец", frozenset({"rent.units.read", "rent.units.manage", "rent.payments.read"}))
ACCOUNTANT = access.Role("rent-accountant", "Бухгалтер", frozenset({"rent.units.read", "rent.payments.read"}))
CATALOG = access.Catalog(frozenset({"rent.units.read", "rent.units.manage", "rent.payments.read"}),
                         {"units.read": "rent.units.read", "units.manage": "rent.units.manage"}, (OWNER, ACCOUNTANT))


def test_unknown_permission_never_allowed() -> None:
    assert access.allowed(CATALOG, OWNER.permissions, "rent.units.manage")
    assert access.allowed(CATALOG, ["units.read"], "rent.units.read")  # старое имя в выданных
    assert access.allowed(CATALOG, ACCOUNTANT.permissions, "units.read")  # старое имя в запросе
    assert not access.allowed(CATALOG, ACCOUNTANT.permissions, "rent.units.manage")
    assert not access.allowed(CATALOG, OWNER.permissions, "rent.unit.manage")  # опечатка — запрет
    assert not access.allowed(CATALOG, ["rent.removed.right"], "rent.units.read")
    with pytest.raises(PermissionError):
        access.require(CATALOG, ACCOUNTANT.permissions, "rent.units.manage")
    with pytest.raises(access.UnknownPermissionError):
        CATALOG.canonical("nope")


def test_catalog_rejects_roles_or_aliases_outside_it() -> None:
    with pytest.raises(access.UnknownPermissionError):
        access.Catalog(frozenset({"a"}), {"old": "b"})
    with pytest.raises(access.UnknownPermissionError):
        access.Catalog(frozenset({"a"}), roles=(access.Role("r", "R", frozenset({"b"})),))
    assert CATALOG.role("rent-accountant") == ACCOUNTANT


def test_preset_update_only_for_untouched_role() -> None:
    old = [OWNER.permissions - {"rent.payments.read"}]
    assert access.preset_update_allowed("Совладелец", OWNER.permissions - {"rent.payments.read"}, OWNER, old)
    assert not access.preset_update_allowed("Мой совладелец", OWNER.permissions - {"rent.payments.read"}, OWNER, old)
    assert not access.preset_update_allowed("Совладелец", {"rent.units.read"}, OWNER, old)


def _key_hex() -> str:
    return Ed25519PrivateKey.generate().public_key().public_bytes(Encoding.Raw, PublicFormat.Raw).hex()


def test_keys_file_strict(tmp_path: Path) -> None:
    good = tmp_path / "keys.json"
    good.write_text(json.dumps({"keys": [{"key_id": "k1", "public_key_hex": _key_hex()}]}), encoding="utf-8")
    keys = licensing.read_keys_file(good)
    assert keys[0].key_id == "k1"
    assert len(keys[0].public_key) == 32
    for bad in ({"keys": [{"key_id": "k1", "public_key_hex": _key_hex(), "private": "x"}]},
                {"keys": [{"key_id": "k1", "public_key_hex": "00"}]}, {"keys": [{"key_id": "", "public_key_hex": _key_hex()}]}, {}):
        path = tmp_path / "bad.json"
        path.write_text(json.dumps(bad), encoding="utf-8")
        with pytest.raises(licensing.LicenseConfigError):
            licensing.read_keys_file(path)
    with pytest.raises(licensing.LicenseConfigError):
        licensing.read_keys_file(tmp_path / "missing.json")


def test_growth_guard() -> None:
    count = [1]
    check = licensing.growth_guard(lambda: count[0], 1, licensed=lambda n: False)
    check()  # без роста — можно
    count[0] = 2
    with pytest.raises(licensing.QuotaExceededError):
        check()
    check2 = licensing.growth_guard(lambda: count[0], 1, licensed=lambda n: n <= 5)
    count[0] = 3
    check2()
    count[0] = 0
    licensing.growth_guard(lambda: count[0], 1, licensed=lambda n: False)()

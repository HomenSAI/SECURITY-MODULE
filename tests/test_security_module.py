# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Модуль безопасности с чистой границей (28.10-279, 284, 286 п. 6): ключ восстановления 128 бит с контрольной суммой,
запечатывание на ключ восстановления, Шамир «2 из 3», Argon2id по OWASP, аварийный лист. Модуль не импортирует денежные и
бизнес-модули Rent — его переносят в HomenSAI/SECURITY-MODULE как есть."""

from __future__ import annotations

import ast
from pathlib import Path
import re
import sys

import pytest

from homensai_security import public_api as security

ROOT = Path(__file__).resolve().parents[1]


# --- ключ восстановления -------------------------------------------------------------------------------------------


def test_recovery_key_is_128_bit_grouped_with_checksum() -> None:
    key = security.new_recovery_key()
    assert len(key.secret) == 16
    assert re.fullmatch(r"RK1(-[0-9A-HJKMNP-TV-Z]{5}){6}", key.text), key.text
    assert security.parse_recovery_key(key.text) == key.secret
    loose = key.text.lower().replace("-", " ")
    assert security.parse_recovery_key(loose) == key.secret  # регистр, пробелы и дефисы не важны


def test_recovery_key_typo_is_caught_by_checksum() -> None:
    key = security.new_recovery_key()
    body = key.text[4:]
    pos = next(i for i, ch in enumerate(body) if ch != "-")
    swapped = "0" if body[pos] != "0" else "1"
    with pytest.raises(security.SecurityError) as err:
        security.parse_recovery_key("RK1-" + body[:pos] + swapped + body[pos + 1 :])
    assert err.value.code == "recovery_checksum"
    with pytest.raises(security.SecurityError) as err:
        security.parse_recovery_key("not a key")
    assert err.value.code == "recovery_format"


def test_crockford_confusable_letters_are_accepted() -> None:
    key = security.new_recovery_key()
    confused = key.text.replace("0", "O").replace("1", "I")
    assert security.parse_recovery_key(confused) == key.secret


def test_sealed_secret_opens_only_with_its_recovery_key() -> None:
    key, other = security.new_recovery_key(), security.new_recovery_key()
    public = security.recovery_public(key.secret)
    sealed = security.seal_to(public, b"household-private-key-32-bytes!!", aad=b"ctx")
    assert security.open_with(key.secret, sealed, aad=b"ctx") == b"household-private-key-32-bytes!!"
    with pytest.raises(security.SecurityError) as err:
        security.open_with(other.secret, sealed, aad=b"ctx")
    assert err.value.code == "recovery_wrong"
    with pytest.raises(security.SecurityError):
        security.open_with(key.secret, sealed, aad=b"other")
    assert security.recovery_id(public).startswith("RK-")


# --- Шамир «2 из 3» ---------------------------------------------------------------------------------------------------


def test_any_two_of_three_shares_restore_the_key_one_gives_nothing(monkeypatch: pytest.MonkeyPatch) -> None:
    from homensai_security import codes

    labels = [b"\x00\x01", b"\x00\x02"]  # ревью B3: метки закреплены — случайное совпадение (1/65 536) не роняет тест
    monkeypatch.setattr(codes, "new_set_label", lambda: labels.pop(0))
    key = security.new_recovery_key()
    shares = security.split_key(key.secret)
    assert len(shares) == 3
    assert all(re.fullmatch(r"RS1-[1-3](-[0-9A-HJKMNP-TV-Z]{5}){7}", s) for s in shares), shares
    for pair in ((0, 1), (0, 2), (1, 2)):
        assert security.combine_shares([shares[pair[0]], shares[pair[1]]]) == key.secret
    with pytest.raises(security.SecurityError) as err:
        security.combine_shares([shares[0]])
    assert err.value.code == "shares_needed"
    stranger = security.split_key(security.new_recovery_key().secret)
    with pytest.raises(security.SecurityError) as err:
        security.combine_shares([shares[0], stranger[1]])
    assert err.value.code == "shares_mismatch"


def _labels(shares: tuple[str, ...] | list[str]) -> set[bytes]:
    from homensai_security import codes

    return {tag for _index, tag, _share in codes.find_shares("\n".join(shares))}


def test_share_set_label_is_random_and_says_nothing_about_the_key(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ревью DR-recovery №1: метка набора — случайная метка самого набора, а не 16 бит хэша ключа (держатель одной части
    не узнаёт о ключе ничего, 28.10-284 «одна часть ничего не даёт»). Два набора одного ключа не смешиваются."""
    from homensai_security import codes

    key = security.new_recovery_key().secret
    legacy = codes.set_tag(key)
    picked = [bytes([legacy[0] ^ 0x5A, legacy[1]]), bytes([legacy[0], legacy[1] ^ 0xA5])]
    monkeypatch.setattr(codes, "new_set_label", lambda: picked.pop(0))
    first, second = security.split_key(key), security.split_key(key)
    assert _labels(first) == {bytes([legacy[0] ^ 0x5A, legacy[1]])}
    assert _labels(second) == {bytes([legacy[0], legacy[1] ^ 0xA5])}
    assert legacy not in _labels(first) | _labels(second)  # метка не выводится из ключа
    assert security.combine_shares([first[0], first[2]]) == key
    assert security.combine_shares([second[1], second[2]]) == key
    with pytest.raises(security.SecurityError) as err:
        security.combine_shares([first[0], second[1]])  # части двух наборов одного ключа
    assert err.value.code == "shares_mismatch"


def test_share_label_collision_is_caught_by_third_share_or_by_the_key_itself(monkeypatch: pytest.MonkeyPatch) -> None:
    """Совпадение случайных меток двух наборов (1 из 65 536): третья часть ловит смешение сразу, а двух частей хватает
    только на неверный ключ — его отвергает расшифровка (ChaCha20-Poly1305), молча чужой ключ не принимается."""
    from homensai_security import codes

    key = security.new_recovery_key()
    monkeypatch.setattr(codes, "new_set_label", lambda: b"\x01\x02")
    first, second = security.split_key(key.secret), security.split_key(key.secret)
    with pytest.raises(security.SecurityError) as err:
        security.combine_shares([first[0], first[1], second[2]])
    assert err.value.code == "shares_mismatch"
    wrong = security.combine_shares([first[0], second[1]])
    assert wrong != key.secret
    sealed = security.seal_to(security.recovery_public(key.secret), b"household-private-key-32-bytes!!", aad=b"ctx")
    with pytest.raises(security.SecurityError) as err:
        security.open_with(wrong, sealed, aad=b"ctx")
    assert err.value.code == "recovery_wrong"


def test_legacy_share_sets_with_key_derived_label_still_combine(monkeypatch: pytest.MonkeyPatch) -> None:
    """Совместимость: наборы, выданные до исправления (метка = 16 бит SHA-256 от ключа), собираются как прежде."""
    from Cryptodome.Protocol.SecretSharing import Shamir

    from homensai_security import codes

    key = security.new_recovery_key().secret
    tag = codes.set_tag(key)
    monkeypatch.setattr(codes, "new_set_label", lambda: bytes([tag[0] ^ 0xFF, tag[1]]))  # ревью B3: метка чужого набора ≠ tag
    old = [codes.format_share(index, tag, share) for index, share in Shamir.split(2, 3, key, ssss=False)]
    for pair in ((0, 1), (0, 2), (1, 2)):
        assert security.combine_shares([old[pair[0]], old[pair[1]]]) == key
    assert security.combine_shares(old) == key
    stranger = security.split_key(security.new_recovery_key().secret)
    with pytest.raises(security.SecurityError) as err:
        security.combine_shares([old[0], stranger[1]])
    assert err.value.code == "shares_mismatch"


def test_legacy_share_set_is_recognized_only_for_key_derived_label(monkeypatch: pytest.MonkeyPatch) -> None:
    """Ревью B3 (вопрос 2, вариант 1): совет «перевыпустите части» — только когда части собираются и их метка вычислена
    из ключа (прежний образец); новый набор, одна часть, опечатка или смешение наборов — без совета."""
    from Cryptodome.Protocol.SecretSharing import Shamir

    from homensai_security import codes

    key = security.new_recovery_key().secret
    tag = codes.set_tag(key)
    old = [codes.format_share(index, tag, share) for index, share in Shamir.split(2, 3, key, ssss=False)]
    for pair in ((0, 1), (0, 2), (1, 2)):
        assert security.legacy_share_set(f"{old[pair[0]]}\n{old[pair[1]]}")
    assert security.legacy_share_set("\n".join(old))
    monkeypatch.setattr(codes, "new_set_label", lambda: bytes([tag[0] ^ 0xFF, tag[1]]))
    fresh = security.split_key(key)
    assert not security.legacy_share_set(f"{fresh[0]}\n{fresh[1]}")
    assert not security.legacy_share_set(old[0])  # одна часть не собирается
    assert not security.legacy_share_set(f"{old[0]}\n{fresh[1]}")  # разные наборы
    assert not security.legacy_share_set(security.new_recovery_key().text)  # ключ RK1, не части
    assert not security.legacy_share_set("просто текст")
    typo = old[1][:-1] + ("0" if old[1][-1] != "0" else "1")
    assert not security.legacy_share_set(f"{old[0]}\n{typo}")  # опечатка — recovery_checksum, без исключения


def test_shamir_vector_from_reference_library() -> None:
    """Вектор pycryptodomex (GF(2^128), Shamir.split(2, 3)): та же библиотека даёт тот же секрет."""
    raw = [(1, "3846b126f36e887f3a2594983bd97027"), (2, "70be04182a22ba66ede1d6fc22d4d34f"), (3, "48e9970d9d19546e5f5de8dfd5d04d97")]
    secret = bytes.fromhex("00112233445566778899aabbccddeeff")
    assert security.shamir_combine_raw([(i, bytes.fromhex(h)) for i, h in raw[:2]]) == secret
    assert security.shamir_combine_raw([(i, bytes.fromhex(h)) for i, h in raw[1:]]) == secret


def test_recovery_input_accepts_key_or_two_shares() -> None:
    key = security.new_recovery_key()
    a, _b, c = security.split_key(key.secret)
    assert security.recovery_from_input(key.text) == key.secret
    assert security.recovery_from_input(f"{a}\n{c}") == key.secret
    assert security.recovery_from_input("обычный пароль копий") is None


# --- Argon2id ---------------------------------------------------------------------------------------------------------


def test_argon2id_hash_meets_owasp_and_verifies() -> None:
    stored = security.hash_secret("Vymysl-Slovo-2026")
    assert stored.startswith("$argon2id$v=19$")
    params = security.argon2_params(stored)
    assert params["m"] >= 19456
    assert params["t"] >= 2
    assert params["p"] >= 1
    assert security.verify_secret("Vymysl-Slovo-2026", stored)
    assert not security.verify_secret("vymysl-slovo-2026", stored)
    assert not security.needs_rehash(stored)
    weak = security.hash_secret("1234", m=19456, t=2, p=1)
    assert security.needs_rehash(weak)


# --- аварийный лист ---------------------------------------------------------------------------------------------------


def test_emergency_sheet_prints_password_only_on_explicit_choice() -> None:
    key = security.new_recovery_key()
    data = security.SheetData(household_fingerprint="HR1-AAAA-BBBB-CCCC-DDDD", signing_fingerprint="HS1-1111-2222-3333-4444",
                              recovery_text=key.text, issued_at="2025-12-01")
    lines = security.sheet_lines(data)
    text = "\n".join(lines)
    assert "HR1-AAAA-BBBB-CCCC-DDDD" in text
    assert "HS1-1111-2222-3333-4444" in text
    assert key.text in text
    assert "Пароль копий: ____" in text
    with_password = security.sheet_lines(security.SheetData(**{**data.__dict__, "password": "Vymysl-Slovo-2026"}))
    assert any("Vymysl-Slovo-2026" in line for line in with_password)
    pdf = security.emergency_sheet_pdf(data)
    assert pdf.startswith(b"%PDF")
    assert b"Vymysl" not in pdf


def test_texts_and_error_codes_are_data_in_two_languages() -> None:
    for code in ("recovery_format", "recovery_checksum", "recovery_wrong", "shares_needed", "shares_mismatch"):
        entry = security.ERRORS[code]
        assert entry["ru"]
        assert entry["uk"]
        assert entry["what_to_do_ru"]
        assert entry["what_to_do_uk"]


def test_security_module_has_clean_boundary() -> None:
    """28.10-286 п. 6: только стандартная библиотека, проверенные криптобиблиотеки и сам модуль — без денег и бизнеса Rent."""
    third_party = {"cryptography", "Cryptodome", "reportlab", "qrcode", "segno"}
    for path in sorted((ROOT / "src" / "homensai_security").glob("*.py")):
        tree = ast.parse(path.read_text(encoding="utf-8"))
        for node in ast.walk(tree):
            names: list[str] = []
            if isinstance(node, ast.Import):
                names = [a.name for a in node.names]
            elif isinstance(node, ast.ImportFrom) and node.module and not node.level:
                names = [node.module]
            for name in names:
                root = name.split(".")[0]
                assert root in sys.stdlib_module_names or root in third_party or root == "homensai_security", (
                    f"{path.name}: импорт {name} нарушает границу модуля безопасности")

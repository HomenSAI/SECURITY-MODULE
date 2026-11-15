# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Вход по одноразовому коду из почты (решение Rent 28.10-344): правила рядом со сбросом (`reset`)."""

from __future__ import annotations

from dataclasses import replace

from homensai_security import auth_texts, levels, reset
from homensai_security.errors import ERRORS

T0 = 1_800_000_000


def test_defaults_match_decision() -> None:
    assert reset.LOGIN_CODE_TTL == 600
    assert reset.LOGIN_CODE_DIGITS == 8
    assert reset.LOGIN_CODE_ATTEMPTS == 5
    assert reset.LOGIN_CODES_PER_HOUR == 3


def test_enabled_only_with_verified_mail() -> None:
    assert not reset.email_login_allowed(enabled=False, mail_verified=True)
    assert not reset.email_login_allowed(enabled=True, mail_verified=False)
    assert reset.email_login_allowed(enabled=True, mail_verified=True)
    assert not reset.email_login_can_enable(mail_verified=False)
    assert reset.email_login_can_enable(mail_verified=True)


def test_code_shape_and_tokens() -> None:
    issued = reset.new_login_code()
    assert len(issued.code) == 8
    assert issued.code.isdigit()
    assert issued.link_token != issued.browser_token
    assert reset.token_shape_ok(issued.link_token)
    assert reset.normalize_login_code("1234 5678") == "12345678"
    assert reset.normalize_login_code("1234-5678") == "12345678"
    for bad in ("1234567", "123456789", "abcdefgh", "١٢٣٤٥٦٧٨"):
        assert reset.normalize_login_code(bad) is None, bad
    assert reset.login_code_message("r1", "12345678") != reset.login_code_message("r2", "12345678")


def test_lifetime_attempts_and_supersede() -> None:
    def state(**kw: object) -> str:
        base: dict[str, object] = {"created_at": T0, "now": T0 + 60, "attempts": 0, "used": False, "superseded": False}
        base.update(kw)
        return reset.login_code_state(**base)  # type: ignore[arg-type]

    assert state() == "active"
    assert state(now=T0 + 600) == "active"
    assert state(now=T0 + 601) == "expired"
    assert state(now=T0 - 1) == "expired"
    assert state(attempts=4) == "active"
    assert state(attempts=5) == "burned"
    assert state(used=True) == "used"
    assert state(superseded=True) == "superseded"


def test_verdict_browser_binding_and_wrong_code() -> None:
    assert reset.login_code_verdict(state="active", browser_ok=True, mac_ok=True) == "ok"
    assert reset.login_code_verdict(state="active", browser_ok=True, mac_ok=False) == "email_login_code_wrong"
    assert reset.login_code_verdict(state="active", browser_ok=False, mac_ok=True) == "email_login_browser"
    for gone in ("used", "burned", "expired", "superseded"):
        assert reset.login_code_verdict(state=gone, browser_ok=True, mac_ok=True) == "email_login_expired"
    assert reset.mac_equal("bi2:aa", "bi2:aa")
    assert not reset.mac_equal("bi2:aa", "bi2:ab")


def test_rate_three_mails_per_hour() -> None:
    assert reset.login_codes_rate_ok([], T0)
    assert reset.login_codes_rate_ok([T0 - 10, T0 - 20], T0)
    assert not reset.login_codes_rate_ok([T0 - 10, T0 - 20, T0 - 30], T0)
    assert reset.login_codes_rate_ok([T0 - 3600, T0 - 4000, T0 - 5000], T0)


def test_second_factor_still_required_and_level_lowered() -> None:
    assert reset.email_login_weakens(reset.Factors(), enabled=True)
    assert not reset.email_login_weakens(reset.Factors(totp=True), enabled=True)
    assert not reset.email_login_weakens(reset.Factors(), enabled=False)
    facts = levels.LevelFacts(backup_password=True, backup_pin_only=False, places=3, offsite=True, check_days=14, storage_acks=True,
                              after_events=True, pin=True, lock=True, ttl=300, integrity=True, chain=True, office=True, places_3=True,
                              check_14=True, sheet_stored=True, notify_all=True)
    assert levels.level(facts) == 5
    weak = replace(facts, email_login_weak=True)
    assert levels.level(weak) == 2
    missing = [m.code for m in levels.missing_for(weak, 3)]
    assert missing == ["email_login_2fa"]


def test_error_codes_and_texts_exist() -> None:
    for code in ("email_login_off", "email_login_mail", "email_login_code_wrong", "email_login_expired", "email_login_browser",
                 "email_login_rate"):
        assert code in ERRORS
        assert ERRORS[code]["ru"]
        assert ERRORS[code]["uk"]
    for lang in ("ru", "uk"):
        body = auth_texts.text("login_code_body", lang, app="HomenS.AI Rent", code="12345678", minutes=10, link="http://localhost/x")
        assert "12345678" in body
        assert "http://localhost/x" in body
        assert "12345678" not in auth_texts.text("login_code_subject", lang, app="A", code="12345678")  # П4: кода в теме нет
        assert auth_texts.text("tg_login_code", lang, when="10:00")

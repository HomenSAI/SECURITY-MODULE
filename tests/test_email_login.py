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
    """Прежний вызов без источника (секунды отправки): одно окно, 3 письма в час — как в 0.4.0."""
    assert reset.login_codes_rate_ok([], T0)
    assert reset.login_codes_rate_ok([T0 - 10, T0 - 20], T0)
    assert not reset.login_codes_rate_ok([T0 - 10, T0 - 20, T0 - 30], T0)
    assert reset.login_codes_rate_ok([T0 - 3600, T0 - 4000, T0 - 5000], T0)


def test_rate_counts_new_window_and_ceiling_separately() -> None:
    """Решение Rent 28.10-366 (Н1 ревью входа по почте): посторонний из новых окон браузера не закрывает владельцу вход.
    Окно — свой счётчик (3 в час); общий потолок хозяйства — 10 в час, из них последние 3 — запас только для доверенного
    источника (окно, где уже входили)."""
    stranger = [reset.LoginCodeSent(T0 - 60 * i, f"окно-{i}") for i in range(7)]  # 7 писем из 7 разных окон за час
    verdict = reset.login_codes_rate(stranger, T0, source="окно-новое", trusted=False)
    assert (verdict.ok, verdict.reason, verdict.important, verdict.recent) == (False, "ceiling", True, 7)
    owner = reset.login_codes_rate(stranger, T0, source="окно-владельца", trusted=True)
    assert (owner.ok, owner.reason, owner.important) == (True, "ok", False)
    assert not reset.login_codes_rate_ok(stranger, T0, source="окно-новое")
    assert reset.login_codes_rate_ok(stranger, T0, source="окно-владельца", trusted=True)
    full = [*stranger, *(reset.LoginCodeSent(T0 - 5, "окно-владельца") for _ in range(3))]
    assert reset.login_codes_rate(full, T0, source="окно-владельца", trusted=True).reason == "window"
    assert reset.login_codes_rate([*stranger, *(reset.LoginCodeSent(T0 - 5, f"x{i}") for i in range(3))], T0,
                                  source="окно-владельца", trusted=True).reason == "ceiling"


def test_rate_new_window_limit_and_old_letters_do_not_count() -> None:
    same = [reset.LoginCodeSent(T0 - 10 * i, "окно-а") for i in range(3)]
    window = reset.login_codes_rate(same, T0, source="окно-а", trusted=False)
    assert (window.ok, window.reason, window.important) == (False, "window", True)  # исчерпание — строка в «Важное»
    assert reset.login_codes_rate(same, T0, source="окно-б", trusted=False).ok  # другое окно — свой счётчик
    old = [reset.LoginCodeSent(T0 - 3600 - i, "окно-а") for i in range(20)]
    assert reset.login_codes_rate(old, T0, source="окно-а", trusted=False).ok
    future = [reset.LoginCodeSent(T0 + 100, "окно-а")] * 5  # часы ушли назад — не в счёт
    assert reset.login_codes_rate(future, T0, source="окно-а", trusted=False).ok


def test_rate_important_line_has_no_addresses_or_sources() -> None:
    """Строка «Важного» (модуль important) — только число запросов за час: без адресов, окон браузера и кодов; не тревога
    (пароль работает), но заметна: «если запрашивали не вы — смените пароль почты»."""
    from datetime import date

    from homensai_security import important

    sent = [reset.LoginCodeSent(T0 - i, "секрет-окна") for i in range(3)]
    verdict = reset.login_codes_rate(sent, T0, source="секрет-окна", trusted=False)
    for lang, word in (("ru", "почт"), ("uk", "пошт")):
        item = important.email_login_rate_item(verdict, date(2027, 1, 15), lang=lang)
        assert item is not None
        assert item.key == "email-login-rate"
        assert not item.alarm
        text = item.title + " " + item.note
        assert "3" in text
        assert word in text.lower()
        assert "секрет" not in text
        assert "@" not in text
    assert important.email_login_rate_item(reset.login_codes_rate([], T0, source="a"), date(2027, 1, 15)) is None


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


def test_link_carries_code_in_fragment_only() -> None:
    """Решение Rent 28.10-352 п. 1 (П3): код — во фрагменте ссылки «#…» (браузер не отправляет его на сервер); в адресе
    запроса — только токен ссылки. Продукт хранит только HMAC кода, шифротекста кода нет."""
    issued = reset.new_login_code()
    link = reset.login_code_link("http://localhost:8080/login/email/show", issued.link_token, issued.code)
    before, _, fragment = link.partition("#")
    assert issued.code not in before
    assert f"t={issued.link_token}" in before
    assert reset.fragment_code(fragment) == issued.code
    assert reset.fragment_code("#" + fragment) == issued.code
    for bad in ("", "#", "code=1234", "#1234567", "#abcdefgh", "#123456789"):
        assert reset.fragment_code(bad) is None, bad

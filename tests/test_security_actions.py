# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ядро безопасности, часть A (решения 28.10-272, 278, 285; чистая граница 286 п. 6): PIN важных действий, режимы
«Офис»/«Дом», срок действия и блокировка экрана, уровни 0–5, рекомендации по настройке системы. Без базы и без сети."""

from __future__ import annotations

from datetime import date

import pytest

from homensai_security import public_api as security


def test_pin_is_exactly_four_digits() -> None:
    assert security.check_pin("4826") == "4826"
    for bad in ("123", "12345", "12a4", " 482", "", "４８２６"):
        with pytest.raises(security.SecurityError) as err:
            security.check_pin(bad)
        assert err.value.code == "pin_format"


def test_pin_is_stored_only_as_argon2id_and_verifies() -> None:
    stored = security.hash_pin("4826")
    assert stored.startswith("$argon2id$v=19$")
    assert "4826" not in stored
    assert security.verify_pin("4826", stored)
    assert not security.verify_pin("4827", stored)
    assert not security.verify_pin("48", stored)


def test_ttl_choices_from_five_minutes_to_whole_day() -> None:
    # 272: 5, 10, 30 минут, 1 час, 2 часа или весь день (0 — до конца дня)
    assert security.TTL_CHOICES == (300, 600, 1800, 3600, 7200, 0)


def test_office_mode_always_has_pin_and_lock() -> None:
    policy = security.Policy.from_dict({"mode": "office", "pin": False, "lock": False, "ttl": 300})
    assert (policy.mode, policy.pin, policy.lock) == ("office", True, True)
    home = security.Policy.from_dict({"mode": "home", "pin": False, "lock": False, "ttl": 300})
    assert (home.pin, home.lock) == (False, False)
    assert security.Policy.from_dict(None) == security.Policy()
    assert security.Policy().pin is False  # 277: все меры необязательны, по умолчанию выключены


@pytest.mark.parametrize("value", [{"mode": "garage"}, {"ttl": 42}, {"actions": ["launch_rockets"]}, "office", {"pin": "yes"}])
def test_invalid_policy_is_refused(value: object) -> None:
    with pytest.raises(security.SecurityError) as err:
        security.Policy.from_dict(value)
    assert err.value.code == "policy_invalid"


def test_lowering_protection_is_detected() -> None:
    strong = security.Policy(mode="office", pin=True, lock=True, ttl=300)
    assert security.lowering(strong, security.Policy(mode="office", pin=True, lock=True, ttl=300)) == ()
    assert "office_to_home" in security.lowering(strong, security.Policy(mode="home", pin=True, lock=True, ttl=300))
    assert "ttl_longer" in security.lowering(strong, security.Policy(mode="office", pin=True, lock=True, ttl=3600))
    assert "ttl_longer" in security.lowering(strong, security.Policy(mode="office", pin=True, lock=True, ttl=0))
    home = security.Policy(mode="home", pin=True, lock=True, ttl=600)
    assert set(security.lowering(home, security.Policy(mode="home", pin=False, lock=False, ttl=600))) == {"pin_off", "lock_off"}
    fewer = security.Policy(mode="home", pin=True, lock=False, ttl=600, actions=("delete",))
    assert "actions_fewer" in security.lowering(home, fewer)
    assert security.lowering(home, security.Policy(mode="home", pin=True, lock=True, ttl=300)) == ()


def test_measures_switched_off_at_home_need_risk_ack() -> None:
    assert security.needs_risk_ack(security.Policy(mode="home", pin=True, lock=True), security.Policy(mode="home", pin=False, lock=True))
    assert not security.needs_risk_ack(security.Policy(mode="home"), security.Policy(mode="home", pin=True, lock=True))


def test_pin_and_lock_need_a_pin_to_be_set() -> None:
    with pytest.raises(security.SecurityError) as err:
        security.validate_policy(security.Policy(mode="home", pin=True), has_pin=False)
    assert err.value.code == "pin_not_set"
    security.validate_policy(security.Policy(mode="home"), has_pin=False)


def test_five_wrong_pins_pause_for_ten_minutes() -> None:
    count, paused = 0, 0
    for _ in range(4):
        count, paused = security.pin_failure(count, now=1000)
        assert paused == 0
    count, paused = security.pin_failure(count, now=1000)
    assert (count, paused) == (5, 1000 + 600)
    assert security.PIN_LOCK_AFTER == 5
    assert security.PIN_PAUSE_SECONDS == 600


def test_deadline_uses_ttl_or_end_of_day() -> None:
    assert security.deadline(1000, 300, day_end=50_000) == 1300
    assert security.deadline(1000, 0, day_end=50_000) == 50_000
    assert security.expired(1000, 1301, 300, day_end=50_000)
    assert not security.expired(1000, 1300, 300, day_end=50_000)


def test_actions_catalog_covers_decision_272() -> None:
    assert set(security.ACTIONS) == {"payment_change", "history_correction", "delete", "bank_details", "backup_settings",
                                     "security_settings", "users"}
    for code in security.ACTIONS:
        assert security.action_title(code, "ru")
        assert security.action_title(code, "uk")


def _facts(**changes: object) -> security.LevelFacts:
    base: dict[str, object] = {
        "backup_password": True, "backup_pin_only": False, "places": 2, "offsite": True, "check_days": 30, "storage_acks": True,
        "after_events": True, "pin": False, "lock": False, "ttl": 1800, "integrity": False, "chain": True, "office": False,
        "places_3": False, "check_14": False, "sheet_stored": False, "notify_all": False,
    }
    base.update(changes)
    return security.LevelFacts(**base)  # type: ignore[arg-type]


def test_level_is_cumulative_0_to_5() -> None:
    assert security.level(_facts(backup_password=False, backup_pin_only=False, places=1, offsite=False)) == 0
    assert security.level(_facts(offsite=False)) == 1
    assert security.level(_facts()) == 2
    assert security.level(_facts(pin=True, lock=True, ttl=1800)) == 3
    assert security.level(_facts(pin=True, lock=True, ttl=3600)) == 2  # блокировка дольше 30 минут — ниже уровня 3
    assert security.level(_facts(pin=True, lock=True, integrity=True)) == 4
    full = _facts(pin=True, lock=True, ttl=300, integrity=True, office=True, places_3=True, check_14=True, sheet_stored=True, notify_all=True)
    assert security.level(full) == 5
    rows = security.level_measures(_facts(), "ru")
    assert [row.level for row in rows] == sorted(row.level for row in rows)
    assert any(row.level == 3 and not row.done for row in rows)
    assert security.LEVEL_TITLES["ru"][0] == "Ненадёжно"
    assert security.LEVEL_TITLES["ru"][5] == "Максимальная надёжность"


def test_recommendations_links_and_partner_mark() -> None:
    nord = security.recommendation("nordvpn", "ru")
    assert nord.url == "https://refer-nordvpn.com/KUlQvWjutsD"
    assert nord.partner
    assert "партнёрская ссылка" in nord.partner_note
    assert security.recommendation("eset", "ru").url == "https://www.eset.com/ua-ru/"
    assert security.recommendation("eset", "uk").url == "https://www.eset.com/ua/"
    assert not security.recommendation("eset", "uk").partner
    assert security.DEFER_DAYS == (7, 14, 30, 90, 180)


def test_nordpass_recommendation_has_owner_partner_link() -> None:
    """28.10-289 п. 3: NordPass — менеджер паролей для пароля копий, ключей восстановления и passkey; ссылка владельца с пометкой."""
    for lang in ("ru", "uk"):
        item = security.recommendation("nordpass", lang)
        assert item.url == "https://refer-nordvpn.com/AvFQZMkgPJB"
        assert item.partner
        assert item.partner_note
        assert "NordPass" in item.title
        assert "passkey" in item.title


def test_recommendation_state_installed_or_deferred() -> None:
    today = date(2026, 11, 9)
    assert security.visible_recommendations({}, today) == ("nordvpn", "eset", "nordpass")
    state = {"nordvpn": {"state": "installed"}, "eset": {"state": "deferred", "until": "2026-11-16"}, "nordpass": {"state": "installed"}}
    assert security.visible_recommendations(state, today) == ()
    assert security.visible_recommendations(state, date(2026, 11, 16)) == ("eset",)
    new = security.recommendation_state(state, "eset", "defer", days=30, today=today)
    assert new["eset"] == {"state": "deferred", "until": "2026-12-09"}
    with pytest.raises(security.SecurityError):
        security.recommendation_state(state, "eset", "defer", days=5, today=today)
    with pytest.raises(security.SecurityError):
        security.recommendation_state(state, "kaspersky", "installed", today=today)


def test_new_error_codes_have_both_languages_and_what_to_do() -> None:
    for code in ("pin_format", "pin_wrong", "pin_paused", "pin_not_set", "pin_mismatch", "policy_invalid", "confirm_needed",
                 "risk_ack_needed", "recommendation_unknown"):
        entry = security.ERRORS[code]
        assert entry["ru"]
        assert entry["uk"]
        assert entry["what_to_do_ru"]
        assert entry["what_to_do_uk"]

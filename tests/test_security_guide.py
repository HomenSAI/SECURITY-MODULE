# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ядро мастера безопасности (28.10-277/278/290), тренировки (287) и помощи по безопасности (283/289/290) — чистые правила
модуля `homensai_security` без базы и часов."""

from __future__ import annotations

from datetime import date, timedelta

import pytest

from homensai_security import public_api as security

TODAY = date(2026, 11, 9)
W = security.wizard
T = security.training


# --- мастер --------------------------------------------------------------------------------------------------------


def test_wizard_steps_start_with_protect_pc_and_level() -> None:
    assert W.STEP_CODES[:2] == ("protect_pc", "level")  # 290: первый шаг — «Как защитить компьютер и аккаунты»
    assert {"backup_password", "places", "pin_lock", "integrity", "chain", "training", "recommendations"} <= set(W.STEP_CODES)
    assert W.DEFER_DAYS == (7, 14, 30, 90, 180)


def test_skip_needs_risk_ack_and_defer_needs_known_period() -> None:
    state = W.WizardState()
    with pytest.raises(security.SecurityError) as err:
        W.decide(state, "pin_lock", "skipped", today=TODAY)
    assert err.value.code == "wizard_risk"
    skipped = W.decide(state, "pin_lock", "skipped", today=TODAY, risk_ack=True)
    assert W.skipped(skipped) == ["pin_lock"]
    with pytest.raises(security.SecurityError) as err:
        W.decide(state, "places", "deferred", today=TODAY, days=3)
    assert err.value.code == "defer_period"
    deferred = W.decide(state, "places", "deferred", today=TODAY, days=14)
    assert W.deferred(deferred) == [("places", TODAY + timedelta(days=14))]
    assert W.due_deferred(deferred, TODAY) == []
    assert W.due_deferred(deferred, TODAY + timedelta(days=14)) == [("places", TODAY + timedelta(days=14))]
    with pytest.raises(security.SecurityError) as err:
        W.decide(state, "nope", "chosen", today=TODAY)
    assert err.value.code == "wizard_step"
    with pytest.raises(security.SecurityError):
        W.decide(state, "places", "maybe", today=TODAY)


def test_decision_can_be_changed_any_time() -> None:
    state = W.decide(W.WizardState(), "chain", "skipped", today=TODAY, risk_ack=True)
    state = W.decide(state, "chain", "chosen", today=TODAY + timedelta(days=1))
    assert state.steps["chain"].choice == "chosen"
    assert W.skipped(state) == []


def test_wizard_is_finished_when_every_step_is_decided_deferred_counts() -> None:
    state = W.require(W.WizardState())
    assert state.required
    assert W.forced(state, TODAY)
    assert W.reminder_due(state, TODAY)
    for code in W.STEP_CODES:
        assert not W.finished(state)
        state = W.set_target(state, 2, today=TODAY) if code == "level" else W.decide(state, code, "deferred", today=TODAY, days=7)
    assert W.finished(state)
    assert state.finished_on == TODAY
    assert not state.required
    assert not W.forced(state, TODAY)
    assert not W.reminder_due(state, TODAY)
    assert W.next_step(state) is None
    assert W.progress(state) == (len(W.STEP_CODES), len(W.STEP_CODES))


def test_level_slider_default_two_and_risky_levels_need_ack() -> None:
    state = W.WizardState()
    assert W.shown_level(state) == 2 == security.RECOMMENDED_LEVEL
    for level in (0, 1):
        with pytest.raises(security.SecurityError) as err:
            W.set_target(state, level, today=TODAY)
        assert err.value.code == "wizard_risk"
        assert W.set_target(state, level, today=TODAY, risk_ack=True).target == level
    with pytest.raises(security.SecurityError) as err:
        W.set_target(state, 6, today=TODAY)
    assert err.value.code == "wizard_level"
    chosen = W.set_target(state, 4, today=TODAY)
    assert chosen.steps["level"].choice == "chosen"
    assert W.in_level("integrity", 4)
    assert not W.in_level("notify", 4)
    assert not W.in_level("login", 5)


def test_snooze_hides_reminder_and_forced_show_until_date() -> None:
    state = W.snooze(W.require(W.WizardState()), today=TODAY, days=7)
    assert not W.forced(state, TODAY + timedelta(days=6))
    assert not W.reminder_due(state, TODAY + timedelta(days=6))
    assert W.forced(state, TODAY + timedelta(days=7))
    assert W.reminder_due(state, TODAY + timedelta(days=7))
    with pytest.raises(security.SecurityError):
        W.snooze(state, today=TODAY, days=2)


def test_wizard_state_round_trip_and_spoiled_state_is_ignored() -> None:
    state = W.decide(W.set_target(W.require(W.WizardState()), 3, today=TODAY), "places", "deferred", today=TODAY, days=30)
    assert W.WizardState.from_dict(state.to_dict()) == state
    spoiled = W.WizardState.from_dict({"steps": {"places": {"choice": "deferred", "on": "x"}, "bogus": {"choice": "chosen", "on": "2026-11-09"}},
                                      "target": True, "required": "yes", "finished_on": "2026-11-09"})
    assert spoiled == W.WizardState()  # испорченное не прячет напоминание
    assert W.WizardState.from_dict(None) == W.WizardState()


def test_level_measures_and_deviations() -> None:
    assert [lvl for lvl, _text in security.level_measures_for(1)] == [1, 1]
    assert len(security.level_measures_for(5)) == len(security.level_measures_for(5, "uk"))
    facts = security.LevelFacts(backup_password=True, backup_pin_only=False, places=2, offsite=False, check_days=30, storage_acks=True,
                                after_events=True, pin=False, lock=False, ttl=1800, integrity=False, chain=False, office=False,
                                places_3=False, check_14=False, sheet_stored=False, notify_all=False)
    assert [m.code for m in security.missing_for(facts, 2)] == ["offsite"]
    assert [m.code for m in security.missing_for(facts, 3)] == ["offsite", "pin", "lock_30"]


# --- тренировка ----------------------------------------------------------------------------------------------------


def test_smart_intervals_3_7_14_30_mistake_brings_closer() -> None:
    assert T.LADDER == (3, 7, 14, 30)
    assert T.interval([], 30) == 3
    assert T.interval([True], 30) == 7
    assert T.interval([True, True], 30) == 14
    assert T.interval([True, True, True, True], 30) == 30
    assert T.interval([True, True, True, False], 30) == 14  # ошибка — ступень вниз
    assert T.interval([False, False], 30) == 3
    assert T.interval([True, True, True], 14) == 14  # не реже выбранного срока 270
    start = date(2026, 11, 1)
    assert T.smart_due(start, (), 30) == date(2026, 11, 4)
    assert T.smart_due(start, ((date(2026, 11, 4), True),), 30) == date(2026, 11, 11)
    with pytest.raises(security.SecurityError):
        T.interval([], 0)


def test_checkup_after_28_days_needs_proof_on_or_after_due() -> None:
    enabled = date(2026, 10, 1)
    assert T.checkup_due(enabled) == date(2026, 10, 29)
    assert not T.checkup_done(enabled, (date(2026, 10, 20),))  # раньше срока — ещё не та проверка
    assert T.checkup_done(enabled, (date(2026, 10, 29),))


def test_only_overdue_blinks_after_a_week() -> None:
    due = date(2026, 11, 1)
    assert T.state_of(due, date(2026, 10, 31)) == "later"
    assert T.state_of(due, due) == "due"
    assert T.state_of(due, due + timedelta(days=T.OVERDUE_GRACE - 1)) == "due"
    assert T.state_of(due, due + timedelta(days=T.OVERDUE_GRACE)) == "overdue"


def test_training_plan_covers_checkup_smart_review_and_drill() -> None:
    start = date(2026, 5, 1)
    facts = T.Facts(
        enabled=True, start=start, methods={"pin": date(2026, 10, 1), "recovery_key": date(2026, 10, 8)}, proofs={"pin": ()},
        smart={"backup_password": T.Smart(date(2026, 10, 1), ((date(2026, 10, 4), True),), 14),
               "pin": T.Smart(date(2026, 10, 1), (), 30)},
        last_review=None, last_drill=date(2026, 9, 1), drill_possible=True, review_possible=True,
    )
    plan = {i.key: i for i in T.plan(facts, TODAY)}
    assert plan["train:checkup:pin"].due == date(2026, 10, 29)
    assert plan["train:checkup:pin"].overdue
    assert "train:smart:pin" not in plan  # пора проверка 28 дней — одна строка на способ
    assert plan["train:checkup:recovery_key"].state == "due"
    assert plan["train:smart:backup_password"].due == date(2026, 10, 11)
    assert plan["train:review"].due == start + timedelta(days=T.REVIEW_DAYS)
    assert plan["train:drill"].due == date(2026, 9, 1) + timedelta(days=T.DRILL_DAYS)
    assert all(i.state != "later" for i in T.due_items(facts, TODAY))
    assert T.plan(T.Facts(enabled=False, start=start), TODAY) == []


def test_review_needs_every_applicable_item_and_code_pick_is_random_index() -> None:
    assert T.REVIEW_ITEMS == ("email", "keys", "codes", "sheet", "trustees")
    assert T.review_complete(["email", "keys", "codes", "sheet"], ["email", "keys", "codes", "sheet"])
    assert not T.review_complete(["email"], ["email", "sheet"])
    with pytest.raises(security.SecurityError):
        T.review_complete(["bogus"], ["email"])
    picks = {T.pick_code(10) for _ in range(200)}
    assert picks <= set(range(1, 11))
    assert len(picks) > 3
    with pytest.raises(security.SecurityError):
        T.pick_code(0)


# --- помощь и рекомендации ---------------------------------------------------------------------------------------


def test_help_texts_are_complete_in_ru_and_uk() -> None:
    assert security.help.problems() == []
    assert len(security.help.INCIDENT_IDS) == 6  # «Если случилось»: 6 сценариев
    assert len(security.help.PAGE_IDS) >= 14  # страница на каждую меру (~14) + passkey, коды, тренировка, уведомления
    for ident in ("login-password", "totp", "hardware-keys", "passkey", "email-reset", "recovery-codes", "pin", "screen-lock", "modes",
                  "backup-password", "places", "password-check", "recovery-key", "chain", "integrity", "journal"):
        for lang in ("ru", "uk"):
            page = security.help.page(ident, lang)
            assert page.what
            assert page.protects
            assert page.not_protects
            assert page.needs
            assert page.diagram
            assert page.faq
    with pytest.raises(security.SecurityError):
        security.help.page("nope")


def test_passkey_page_explains_password_manager_and_prf() -> None:
    """28.10-289: passkey в менеджере паролей; копии через passkey — только с PRF, иначе пароль / ключ восстановления."""
    for lang in ("ru", "uk"):
        page = security.help.page("passkey", lang)
        text = " ".join([page.what, *page.not_protects, *[a for _q, a in page.faq]])
        assert "NordPass" in text
        assert "PRF" in text


def test_protect_pc_page_items_with_minutes_and_partner_links() -> None:
    """28.10-290: 13 пунктов, у каждого «без этого» и минуты; NordPass/NordVPN — ссылки владельца с пометкой."""
    assert security.PC_ITEMS[:3] == ("nordpass", "nordvpn", "eset")
    assert {"hardware_key", "email", "updates", "phishing", "passwords", "two_factor", "backups", "screen_lock", "no_admin",
            "disk_encryption"} <= set(security.PC_ITEMS)
    for lang in ("ru", "uk"):
        for item in security.help.pc_items(lang):
            assert item.without
            assert item.how
            assert 1 <= item.minutes <= 30
    assert security.recommendation("nordpass").url == "https://refer-nordvpn.com/AvFQZMkgPJB"
    assert security.recommendation("nordvpn").partner
    assert security.recommendation("nordpass").partner
    state = security.recommendation_state({}, "updates", "installed", today=TODAY)
    state = security.recommendation_state(state, "no_admin", "defer", today=TODAY, days=30)
    assert security.item_status(state, "updates", TODAY) == ("done", None)
    assert security.item_status(state, "no_admin", TODAY)[0] == "deferred"
    assert security.pc_remaining(state, TODAY) == len(security.PC_ITEMS) - 2
    assert security.visible_recommendations(state, TODAY) == ("nordvpn", "eset", "nordpass")  # пункты 290 — не строки 285


def test_level_info_for_help_slider() -> None:
    info = security.help.level_info(2, "uk")
    assert info.title == security.LEVEL_TITLES["uk"][2]
    assert info.threats
    assert [lvl for lvl, _t in info.measures] == [lvl for lvl, _t in security.level_measures_for(2)]
    with pytest.raises(security.SecurityError):
        security.help.level_info(9)


def test_security_help_doc_is_built_from_data() -> None:
    """docs/help/SECURITY_HELP.md собирается из тех же данных, что и встроенная помощь (283 п. 3.5)."""
    import importlib.util
    from pathlib import Path

    root = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location("build_security_help", root / "scripts" / "build_security_help.py")
    assert spec is not None
    assert spec.loader is not None
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    assert module.main(["--check"]) == 0
    text = (root / "docs" / "help" / "SECURITY_HELP.md").read_text(encoding="utf-8")
    for word in ("/help/security", "NordPass", "passkey", "PRF"):
        assert word in text, word

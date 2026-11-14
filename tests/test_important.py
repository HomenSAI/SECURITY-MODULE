# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Строки «Безопасность» для ленты напоминаний: мастер, отложенное, рекомендации, тренировка, пауза PIN, тревоги."""

from __future__ import annotations

from datetime import date, timedelta

from homensai_security import important, training, wizard

TODAY = date(2026, 11, 14)


def test_new_install_reminds_to_set_up_security_without_blinking() -> None:
    items = important.guide_items(wizard.WizardState(), TODAY)
    assert items
    assert items[0].key == "security-wizard"
    assert all(not i.alarm and not i.blink for i in items)
    assert items[0].href == "/security/wizard"


def test_deferred_step_and_custom_hrefs() -> None:
    state = wizard.decide(wizard.WizardState(), "protect_pc", "deferred", today=TODAY - timedelta(days=8), days=7)
    hrefs = important.Hrefs(wizard="/sec/setup", wizard_step="/sec/setup/{code}")
    items = important.guide_items(state, TODAY, hrefs=hrefs, lang="uk")
    deferred = [i for i in items if i.key.startswith("security-wizard-deferred:")]
    assert deferred
    assert deferred[0].href == "/sec/setup/protect_pc"
    assert deferred[0].title.startswith("Відкладений захід")


def test_overdue_training_blinks_but_is_not_alarm() -> None:
    facts = training.Facts(enabled=True, start=TODAY - timedelta(days=400), methods={"pin": TODAY - timedelta(days=400)})
    items = important.guide_items(wizard.WizardState(), TODAY, training_facts=facts)
    overdue = [i for i in items if i.key.startswith(important.OVERDUE_PREFIX)]
    assert overdue
    assert all(i.blink and not i.alarm for i in overdue)


def test_recommendations_pin_pause_and_alarm() -> None:
    reco = important.recommendation_items({}, TODAY)
    assert {i.key for i in reco} >= {"security-reco:nordvpn", "security-reco:eset"}
    assert any("партнёр" in i.note for i in reco)
    assert all(not i.blink for i in reco)
    assert important.pin_paused_item(100, 100, TODAY) is None
    paused = important.pin_paused_item(200, 100, TODAY)
    assert paused is not None
    assert not paused.alarm
    alarm = important.alarm_item("backup-chain-broken", "Цепочка копий нарушена", "…", "/archive/checks", TODAY)
    assert alarm.alarm
    assert alarm.blink

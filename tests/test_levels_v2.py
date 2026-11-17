# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ползунок на 7 делений (решения Rent 28.10-373 и 28.10-374): уровни 0–6, перенос по маркеру, PIN 4–6, настройка печати."""

from __future__ import annotations

from datetime import date

import pytest

from homensai_security import public_api as security

TODAY = date(2026, 11, 17)
W = security.wizard


def facts(**kw: object) -> security.LevelFacts:
    base: dict[str, object] = dict(
        backup_password=False, backup_pin_only=False, places=1, offsite=False, check_days=0, storage_acks=False, after_events=False,
        pin=False, lock=False, ttl=1800, integrity=False, chain=False, office=False, places_3=False, check_14=False,
        sheet_stored=False, notify_all=False, login_protected=True)
    base.update(kw)
    return security.LevelFacts(**base)  # type: ignore[arg-type]


def test_seven_titles_in_both_languages_and_recommended_three() -> None:
    for lang in ("ru", "uk"):
        assert sorted(security.LEVEL_TITLES[lang]) == [0, 1, 2, 3, 4, 5, 6]
    assert security.LEVEL_TITLES["ru"][0] == "Без защиты"
    assert security.LEVEL_TITLES["ru"][1] == "Только PIN"
    assert security.LEVEL_TITLES["ru"][2] == "Пароль копий"
    assert security.LEVEL_TITLES["uk"][0] == "Без захисту"
    assert security.RECOMMENDED_LEVEL == 3


def test_level_zero_only_when_there_is_no_login_at_all() -> None:
    assert security.level(facts(login_protected=False)) == 0
    assert security.level(facts(login_protected=False, pin_login=True)) == 0  # pin_login — признак показа, вход считает login_protected
    assert security.level(facts(login_protected=True)) == 1  # пароль или PIN входа — минимум уровень 1, без мер копий
    assert security.level(facts()) == 1  # по умолчанию вход считается защищённым (в Rent пароль входа обязателен)
    assert security.level(facts(pin_login=True, login_protected=True, lock=True)) == 1


def test_password_login_without_backup_measures_is_not_shown_as_zero() -> None:
    """Хозяйство со входом по паролю, но без мер копий (бывший уровень 0 «Ненадёжно»): не «Без защиты», а уровень 1."""
    old_zero = facts(backup_password=False, backup_pin_only=False, places=1, offsite=False, login_protected=True)
    assert security.level(old_zero) == 1
    assert [m.code for m in security.level_measures(old_zero) if m.level == 1] == ["login_protected"]
    assert [m.done for m in security.level_measures(old_zero) if m.level == 1] == [True]


def test_old_chain_keeps_its_levels_shifted_by_one() -> None:
    """Прежние наборы фактов дают прежний уровень + 1 и без мер уровня 1 (вход по паролю остаётся)."""
    l2 = facts(backup_password=True, places=2)
    assert security.level(l2) == 2
    l3 = facts(backup_password=True, places=2, offsite=True, check_days=30, storage_acks=True, after_events=True)
    assert security.level(l3) == 3
    l4 = facts(**{**l3.__dict__, "pin": True, "lock": True, "ttl": 1800})
    assert security.level(l4) == 4
    l5 = facts(**{**l4.__dict__, "integrity": True, "chain": True})
    assert security.level(l5) == 5
    l6 = facts(**{**l5.__dict__, "office": True, "ttl": 300, "places_3": True, "check_14": True, "sheet_stored": True, "notify_all": True})
    assert security.level(l6) == 6


def test_measures_levels_one_to_six() -> None:
    assert [lvl for lvl, _t in security.level_measures_for(1)] == [1]
    assert max(lvl for lvl, _t in security.level_measures_for(6)) == 6
    assert len(security.level_measures_for(6)) == len(security.level_measures_for(6, "uk"))
    assert [m.code for m in security.level_measures(facts()) if m.level == 1] == ["login_protected"]


def test_risky_levels_are_zero_one_two_and_range_is_zero_to_six() -> None:
    state = W.WizardState()
    assert W.RISKY_LEVELS == (0, 1, 2)
    assert W.shown_level(state) == 3
    for level in (0, 1, 2):
        with pytest.raises(security.SecurityError) as err:
            W.set_target(state, level, today=TODAY)
        assert err.value.code == "wizard_risk"
        assert W.set_target(state, level, today=TODAY, risk_ack=True).target == level
    assert W.set_target(state, 6, today=TODAY).target == 6
    for bad in (-1, 7, True, "3"):
        with pytest.raises(security.SecurityError):
            W.set_target(state, bad, today=TODAY)  # type: ignore[arg-type]


def test_step_levels_are_shifted_and_pin_login_is_level_one() -> None:
    assert W.step("pin_login").level == 1
    assert W.step("backup_password").level == 2
    assert W.step("pin_lock").level == 4
    assert W.step("integrity").level == 5
    assert W.step("notify").level == 6


@pytest.mark.parametrize(("old", "new"), [(0, 2), (1, 2), (2, 3), (3, 4), (4, 5), (5, 6)])
def test_old_scale_target_moves_by_marker(old: int, new: int) -> None:
    state = W.WizardState.from_dict({"v": 1, "target": old, "steps": {}})
    assert state.target == new
    assert state.to_dict()["scale"] == 7


def test_migration_is_idempotent_and_marker_is_respected() -> None:
    once = W.WizardState.from_dict({"v": 1, "target": 3, "steps": {}})
    again = W.WizardState.from_dict(once.to_dict())
    assert once.target == again.target == 4
    assert W.WizardState.from_dict({"scale": 7, "target": 0, "steps": {}}).target == 0
    assert W.WizardState.from_dict({"scale": 7, "target": 6, "steps": {}}).target == 6
    assert W.WizardState.from_dict({"v": 1, "target": None}).target is None
    assert W.WizardState.from_dict({"scale": 9, "target": 3}).target is None  # неизвестная шкала — как испорченная
    assert W.WizardState.from_dict({"v": 1, "target": 7}).target is None  # вне старой шкалы
    assert W.WizardState.from_dict({"scale": 7, "target": 7}).target is None


def test_migration_marks_new_pin_login_step_as_skipped_for_old_state() -> None:
    state = W.WizardState.from_dict({"v": 1, "target": 2, "steps": {"level": {"choice": "chosen", "on": "2026-11-09"}}})
    assert state.steps["pin_login"].choice == "skipped"
    fresh = W.WizardState.from_dict({"scale": 7, "target": 2, "steps": {}})
    assert "pin_login" not in fresh.steps  # новое состояние шаг не добавляет само


@pytest.mark.parametrize("pin", ["1234", "12345", "123456", "0000"])
def test_pin_accepts_four_to_six_digits(pin: str) -> None:
    assert security.check_pin(pin) == pin
    assert security.verify_pin(pin, security.hash_pin(pin))


@pytest.mark.parametrize("pin", ["123", "1234567", "12a4", "١٢٣٤", " 1234", "12 34", "", 1234])
def test_pin_rejects_other_formats(pin: object) -> None:
    with pytest.raises(security.SecurityError) as err:
        security.check_pin(pin)  # type: ignore[arg-type]
    assert err.value.code == "pin_format"
    assert not security.verify_pin(pin, security.hash_pin("1234"))  # type: ignore[arg-type]


def test_policy_seal_setting_defaults_to_auto_only_and_round_trips() -> None:
    assert security.Policy().seal_manual_without_pin is False
    policy = security.Policy.from_dict({"mode": "home", "pin": True, "lock": True, "ttl": 1800, "seal_manual_without_pin": True})
    assert policy.seal_manual_without_pin is True
    assert security.Policy.from_dict(policy.to_dict()) == policy
    assert security.Policy.from_dict({"mode": "office", "seal_manual_without_pin": True}).seal_manual_without_pin is True  # normalized() хранит
    with pytest.raises(security.SecurityError):
        security.Policy.from_dict({"seal_manual_without_pin": "yes"})
    assert security.Policy.from_dict({"mode": "home"}).seal_manual_without_pin is False  # старая настройка без поля


def test_level_info_covers_all_seven_in_both_languages() -> None:
    for lang in ("ru", "uk"):
        for value in range(7):
            info = security.help.level_info(value, lang)
            assert info.title == security.LEVEL_TITLES[lang][value] and info.threats
    with pytest.raises(security.SecurityError):
        security.help.level_info(7)


# --- периодическое предложение повысить уровень (28.10-375) ---------------------------------------------------------------

U = security.upgrade


def test_offer_defaults_and_periods() -> None:
    assert U.DEFAULT_PERIOD == 30 and U.OfferState().period_days == 30
    assert U.PERIODS == (14, 30, 60, 90, 180)


def test_first_schedule_starts_the_count_and_does_not_show_at_once() -> None:
    state = U.OfferState()
    assert not U.due(state, 3, TODAY)  # отсчёта нет — предложения нет
    started = U.schedule(state, TODAY)
    assert started.anchor == TODAY and U.next_on(started) == date(2026, 12, 17)
    assert U.schedule(started, date(2027, 1, 1)).anchor == TODAY  # повторный вызов срок не сдвигает
    assert not U.due(started, 3, date(2026, 12, 16))
    assert U.due(started, 3, date(2026, 12, 17))
    assert U.due(started, 3, date(2027, 3, 1))


def test_not_now_is_remembered_and_postpones_by_period() -> None:
    started = U.schedule(U.OfferState(), TODAY)
    later = U.decline(started, date(2026, 12, 20))
    assert (later.answer, later.answered_on, later.declines) == ("later", date(2026, 12, 20), 1)
    assert not U.due(later, 3, date(2027, 1, 18))
    assert U.due(later, 3, date(2027, 1, 19))
    again = U.decline(later, date(2027, 1, 25))
    assert again.declines == 2 and U.next_on(again) == date(2027, 2, 24)
    assert U.OfferState.from_dict(again.to_dict()) == again


def test_accept_is_remembered_and_restarts_the_count() -> None:
    accepted = U.accept(U.schedule(U.OfferState(), TODAY), date(2026, 12, 18))
    assert accepted.answer == "accepted" and U.next_on(accepted) == date(2027, 1, 17)


def test_level_six_is_never_offered_and_other_levels_are() -> None:
    started = U.schedule(U.OfferState(), TODAY)
    far = date(2030, 1, 1)
    assert not U.due(started, 6, far)
    assert U.offer(6) is None
    assert all(U.due(started, level, far) for level in range(6))
    for bad in (-1, 7, True):
        assert not U.due(started, bad, far)  # type: ignore[arg-type]


def test_period_change_counts_from_last_answer_and_rejects_unknown_values() -> None:
    later = U.decline(U.schedule(U.OfferState(), TODAY), date(2026, 12, 20))
    longer = U.set_period(later, 90, date(2026, 12, 21))
    assert longer.period_days == 90 and longer.anchor == date(2026, 12, 20) and U.next_on(longer) == date(2027, 3, 20)
    assert U.set_period(U.OfferState(), 14, TODAY).anchor == TODAY
    for bad in (0, 7, 31, True, "30"):
        with pytest.raises(security.SecurityError) as err:
            U.set_period(later, bad, TODAY)  # type: ignore[arg-type]
        assert err.value.code == "offer_period"


def test_broken_saved_state_falls_back_to_default() -> None:
    assert U.OfferState.from_dict(None) == U.OfferState()
    broken = U.OfferState.from_dict({"period_days": 5, "anchor": "bad", "answer": "x", "declines": -3})
    assert broken == U.OfferState()


@pytest.mark.parametrize("lang", ["ru", "uk"])
def test_offer_texts_exist_for_every_level_and_language(lang: str) -> None:
    for level in range(6):
        found = U.offer(level, lang)
        assert found is not None and found.to_level == level + 1
        assert found.adds and found.stay_risk and found.loss_risk
        assert all(text.strip() for text in found.adds)
    ru = U.offer(3, "ru")
    uk = U.offer(3, "uk")
    assert ru is not None and uk is not None and ru.stay_risk != uk.stay_risk
    assert len(ru.adds) == len(uk.adds)


def test_offer_adds_are_the_measures_of_the_next_level_only() -> None:
    offer = U.offer(1, "ru")
    assert offer is not None and offer.adds == tuple(t for lvl, t in security.level_measures_for(2, "ru") if lvl == 2)
    first = U.offer(0, "ru")
    assert first is not None and first.adds == tuple(t for _lvl, t in security.level_measures_for(1, "ru"))


def test_offer_period_error_has_texts_in_both_languages() -> None:
    entry = security.ERRORS["offer_period"]
    assert entry["ru"] and entry["uk"] and entry["what_to_do_ru"] and entry["what_to_do_uk"]


def test_no_login_means_level_zero_whatever_else_is_done() -> None:
    """Ревью С1: все остальные меры выполнены, а входа нет — уровень 0; значения по умолчанию у login_protected нет."""
    full = dict(backup_password=True, places=3, offsite=True, check_days=30, storage_acks=True, after_events=True, pin=True, lock=True, ttl=300,
                integrity=True, chain=True, office=True, places_3=True, check_14=True, sheet_stored=True, notify_all=True)
    assert security.level(facts(**full)) == 6
    assert security.level(facts(login_protected=False, **full)) == 0
    with pytest.raises(TypeError):
        security.LevelFacts(**{k: v for k, v in dict(backup_password=False, backup_pin_only=False, places=1, offsite=False, check_days=0,
                                                       storage_acks=False, after_events=False, pin=False, lock=False, ttl=1800,
                                                       integrity=False, chain=False, office=False, places_3=False, check_14=False,
                                                       sheet_stored=False, notify_all=False).items()})  # type: ignore[arg-type]


def test_level_never_drops_when_a_measure_is_added() -> None:
    """Монотонность: добавление выполненной меры не понижает уровень (перебор по одной мере)."""
    import itertools
    names = ["backup_password", "offsite", "storage_acks", "after_events", "pin", "lock", "integrity", "chain", "office", "places_3",
             "check_14", "sheet_stored", "notify_all"]
    for combo in itertools.chain.from_iterable(itertools.combinations(names, r) for r in range(0, 4)):
        base = {n: True for n in combo}
        for extra in names:
            assert security.level(facts(**{**base, extra: True})) >= security.level(facts(**base))


def test_target_is_stored_under_new_key_and_rollback_does_not_shift_twice() -> None:
    """Ревью С2: 0.6.0 пишет target_v2 без прежнего target; состояние, переписанное 0.5.0 (без scale и target_v2), не сдвигается повторно."""
    state = W.WizardState.from_dict({"v": 1, "target": 2, "steps": {}})
    data = state.to_dict()
    assert data["target_v2"] == 3 and "target" not in data
    assert W.WizardState.from_dict(data).target == 3
    # 0.5.0 читает такой файл: ключа target нет — выбор потерян, но не искажён; после сохранения 0.5.0 пишет без scale и target_v2
    rewritten = {"v": 1, "required": True, "target": None, "steps": data["steps"]}
    assert W.WizardState.from_dict(rewritten).target is None
    for _ in range(3):  # откат и возврат подряд ничего не подтягивают вверх
        assert W.WizardState.from_dict(W.WizardState.from_dict(rewritten).to_dict()).target is None
    assert W.WizardState.from_dict({"scale": 7, "target_v2": 7}).target is None


def test_seal_without_pin_is_a_lowering_needing_risk_ack() -> None:
    """Ревью С3: ручная печать месяца без PIN — ослабление."""
    safe = security.Policy(mode="home", pin=True, lock=True, ttl=300)
    loose = security.Policy(mode="home", pin=True, lock=True, ttl=300, seal_manual_without_pin=True)
    assert "seal_without_pin" in security.lowering(safe, loose)
    assert security.needs_risk_ack(safe, loose)
    assert security.lowering(loose, safe) == ()


def test_upgrade_due_with_future_anchor() -> None:
    """Ревью Н2: дата отсчёта в будущем не скрывает предложение."""
    state = security.upgrade.OfferState(30, date(2099, 1, 1), None, None, 0)
    assert security.upgrade.due(state, 2, TODAY)


def test_migrated_risky_choice_keeps_its_risk_ack_and_does_not_ask_twice() -> None:
    """Ревью Н4: прежний выбор 0/1 (с галочкой риска) переносится в 2; повторный выбор того же деления не просит галочку заново."""
    for old in (0, 1):
        state = W.WizardState.from_dict({"v": 1, "target": old, "steps": {}})
        assert state.target == 2
        assert state.risk_acked
        assert W.set_target(state, 2, today=TODAY).target == 2
        assert W.WizardState.from_dict(state.to_dict()).risk_acked
        with pytest.raises(security.SecurityError) as err:
            W.set_target(state, 1, today=TODAY)  # другое рискованное деление — галочка снова нужна
        assert err.value.code == "wizard_risk"
    fresh = W.WizardState.from_dict({"v": 1, "target": 3, "steps": {}})
    assert not fresh.risk_acked
    moved = W.set_target(W.set_target(fresh, 2, today=TODAY, risk_ack=True), 3, today=TODAY)
    assert not moved.risk_acked  # ушли с рискованного деления — подтверждение сбрасывается
    with pytest.raises(security.SecurityError):
        W.set_target(moved, 2, today=TODAY)


def test_pin_checks_reject_wide_digits_everywhere() -> None:
    """Ревью Н3: «широкие» цифры не принимаются ни при установке, ни при проверке PIN (NFKC в KDF их бы совпал)."""
    stored = security.hash_pin("1234")
    assert security.verify_pin("1234", stored)
    assert not security.verify_pin("１２３４", stored)
    assert not security.verify_pin("1234 ", stored)
    assert not security.verify_pin("1234\n", stored)
    with pytest.raises(security.SecurityError):
        security.check_pin("１２３４")

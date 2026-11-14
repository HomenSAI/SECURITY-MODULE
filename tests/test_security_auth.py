# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ядро входа и восстановления (28.10-282, 284, 289) в чистом модуле `homensai_security`: WebAuthn (виртуальный аутентификатор и
внешний вектор), TOTP по тест-векторам RFC 4226/6238, коды восстановления, правила сброса."""

from __future__ import annotations

import base64
import hashlib
import json

import pytest

from homensai_security import cbor
from homensai_security import public_api as security
from homensai_security.webauthn import ALG_EDDSA, ALG_ES256, ALG_RS256, b64url, unb64url
from virtual_authenticator import ORIGIN, VirtualKey

wa = security.webauthn
ORIGINS = (ORIGIN,)


def _register(key: VirtualKey, challenge: bytes | None = None) -> tuple[bytes, dict[str, object]]:
    challenge = challenge or wa.new_challenge()
    options = wa.creation_options(challenge=challenge, user_id=b"u" * 32, user_name="owner", display_name="Владелец", rp_name="HomenS.AI Rent")
    return challenge, key.create(options)


def _verify_reg(reply: dict[str, object], challenge: bytes, origins: tuple[str, ...] = ORIGINS) -> security.webauthn.RegisteredKey:
    return wa.verify_registration(client_data_json=unb64url(reply["clientDataJSON"]), attestation_object=unb64url(reply["attestationObject"]),
                                  challenge=challenge, origins=origins)


def _assert(key: VirtualKey, public: bytes, stored: int, *, challenge: bytes | None = None, origin: str = ORIGIN,
            require_uv: bool = True) -> security.webauthn.Assertion:
    challenge = challenge or wa.new_challenge()
    reply = key.get(wa.request_options(challenge=challenge), origin)
    return wa.verify_assertion(public_key=public, client_data_json=unb64url(reply["clientDataJSON"]),
                               authenticator_data=unb64url(reply["authenticatorData"]), signature=unb64url(reply["signature"]),
                               challenge=challenge, origins=ORIGINS, stored_sign_count=stored, require_uv=require_uv)


# --- WebAuthn: регистрация и вход --------------------------------------------------------------------------------------


@pytest.mark.parametrize("alg", [ALG_ES256, ALG_EDDSA, ALG_RS256])
def test_register_and_sign_in_with_each_algorithm(alg: int) -> None:
    key = VirtualKey(alg=alg)
    challenge, reply = _register(key)
    found = _verify_reg(reply, challenge)
    assert found.alg == alg
    assert found.credential_id == key.credential_id
    assert found.user_verified
    assert not found.backup_eligible  # аппаратный ключ
    result = _assert(key, found.public_key, found.sign_count)
    assert result.sign_count == found.sign_count + 1
    assert result.user_verified


def test_passkey_of_password_manager_is_backup_eligible_and_counter_zero_is_fine() -> None:
    key = VirtualKey(backup_eligible=True, counting=False)
    challenge, reply = _register(key)
    found = _verify_reg(reply, challenge)
    assert found.backup_eligible
    assert found.backed_up
    assert found.sign_count == 0
    assert _assert(key, found.public_key, 0).sign_count == 0
    assert _assert(key, found.public_key, 0).sign_count == 0


def test_registration_options_require_resident_key_and_user_verification() -> None:
    options = wa.creation_options(challenge=b"c" * 32, user_id=b"u" * 32, user_name="owner", display_name="o", rp_name="r",
                                  exclude=[b"x" * 20])
    assert options["rp"]["id"] == "localhost"
    assert options["authenticatorSelection"] == {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"}
    assert options["attestation"] == "none"
    assert {p["alg"] for p in options["pubKeyCredParams"]} == {-7, -8, -257}
    assert options["excludeCredentials"][0]["id"] == b64url(b"x" * 20)
    assert "prf" in options["extensions"]
    req = wa.request_options(challenge=b"c" * 32, prf_eval=wa.prf_input())
    assert req["allowCredentials"] == []
    assert req["userVerification"] == "required"
    assert req["extensions"]["prf"]["eval"]["first"] == b64url(wa.prf_input())


@pytest.mark.parametrize(
    ("change", "code"),
    [
        ("challenge", "webauthn_challenge"),
        ("origin", "webauthn_origin"),
        ("rp", "webauthn_origin"),
        ("uv", "webauthn_uv"),
        ("fmt", "webauthn_attestation"),
    ],
)
def test_registration_refusals(change: str, code: str) -> None:
    key = VirtualKey(uv=change != "uv", rp_id="evil.example" if change == "rp" else "localhost")
    challenge = wa.new_challenge()
    options = wa.creation_options(challenge=challenge, user_id=b"u" * 32, user_name="owner", display_name="o", rp_name="r")
    reply = key.create(options, "http://127.0.0.1:8820" if change == "origin" else ORIGIN, fmt="packed" if change == "fmt" else "none")
    with pytest.raises(security.SecurityError) as err:
        _verify_reg(reply, wa.new_challenge() if change == "challenge" else challenge)
    assert err.value.code == code


def test_assertion_refusals_signature_counter_origin_and_uv() -> None:
    key = VirtualKey()
    challenge, reply = _register(key)
    found = _verify_reg(reply, challenge)
    other = VirtualKey()
    with pytest.raises(security.SecurityError) as err:  # чужой ключ подписал — подпись не сходится
        _assert(other, found.public_key, 0)
    assert err.value.code == "webauthn_signature"
    with pytest.raises(security.SecurityError) as err:  # счётчик не вырос — возможно, клон
        _assert(key, found.public_key, 1000)
    assert err.value.code == "webauthn_counter"
    with pytest.raises(security.SecurityError) as err:
        _assert(key, found.public_key, 0, origin="http://localhost:9999")
    assert err.value.code == "webauthn_origin"
    key.uv = False
    with pytest.raises(security.SecurityError) as err:
        _assert(key, found.public_key, 0)
    assert err.value.code == "webauthn_uv"
    assert not _assert(key, found.public_key, 0, require_uv=False).user_verified  # касание без PIN — только где UV не нужен


def test_tampered_authenticator_data_breaks_the_signature() -> None:
    key = VirtualKey()
    challenge, reply = _register(key)
    found = _verify_reg(reply, challenge)
    challenge = wa.new_challenge()
    got = key.get(wa.request_options(challenge=challenge))
    auth = bytearray(unb64url(got["authenticatorData"]))
    auth[36] ^= 0x01  # счётчик подменён
    with pytest.raises(security.SecurityError) as err:
        wa.verify_assertion(public_key=found.public_key, client_data_json=unb64url(got["clientDataJSON"]), authenticator_data=bytes(auth),
                            signature=unb64url(got["signature"]), challenge=challenge, origins=ORIGINS, stored_sign_count=0)
    assert err.value.code == "webauthn_signature"


def test_external_none_attestation_vector_from_fido2_helpers() -> None:
    """Регистрация реального аутентификатора с аттестацией «none» (apowers313/fido2-helpers, через fxamacker/webauthn, Apache-2.0)."""
    attestation = unb64url(
        "o2NmbXRkbm9uZWdhdHRTdG10oGhhdXRoRGF0YVkBJkmWDeWIDoxodDQXD2R2YFuP5K65ooYyx5lc87qDHZdjQQAAAAAAAAAAAAAAAAAAAAAAAAAAAKIACKLdXqwahqjNbtNs1piUlonl"
        "uvxOsF9Feeh9k7qXay5zdrm239cW4WQUD_l5ptTzRLU9bSbghnv0FLaRA7tly7La9_QRKDXwZMsbWajlhKQh2ovYnjh6C37qtyPs151ITDFr-67FRgG0c2dJCoOa2hQB8z0tJYuXrkGM"
        "pVk0ZSn1qjfeYxJ1V9BDRsfN7r0lVC8sF_w5OJlSomw64qampRylAQIDJiABIVgguxHN3W6ehp0VWXKaMNie1J82MVJCFZYScau74o17cx8iWCDb1jkTLi7lYZZbgwUwpqAk8QmIiPMT"
        "VQUVkhGEyGrKww"
    )
    client = base64.b64decode(
        "eyJjaGFsbGVuZ2UiOiIzM0VIYXYtaloxdjlxd0g3ODNhVS1qMEFSeDZyNW8tWUhoLXdkN0M2alBiZDdXaDZ5dGJJWm9zSUlBQ2Vod2Y5LXM2aFhoeVNITy1ISFVqRXdaUzI5dyIsImNsaWVu"
        "dEV4dGVuc2lvbnMiOnt9LCJoYXNoQWxnb3JpdGhtIjoiU0hBLTI1NiIsIm9yaWdpbiI6Imh0dHBzOi8vbG9jYWxob3N0Ojg0NDMiLCJ0eXBlIjoid2ViYXV0aG4uY3JlYXRlIn0="
    )
    challenge = unb64url(json.loads(client)["challenge"])
    found = wa.verify_registration(client_data_json=client, attestation_object=attestation, challenge=challenge,
                                   origins=("https://localhost:8443",), require_uv=False)
    assert found.alg == ALG_ES256
    assert b64url(found.credential_id).startswith("AAii3V6sGoaozW7TbNaYlJaJ5br8")
    with pytest.raises(security.SecurityError):  # в векторе ключ без проверки пользователя: для входа без пароля не годится
        wa.verify_registration(client_data_json=client, attestation_object=attestation, challenge=challenge, origins=("https://localhost:8443",))


def test_ed25519_signature_check_uses_rfc8032_vector() -> None:
    """RFC 8032 §7.1, тест 1: пустое сообщение. Проверяем, что EdDSA-ветка проверки подписи совпадает со стандартом."""
    public = bytes.fromhex("d75a980182b10ab7d54bfed3c964073a0ee172f3daa62325af021a68f707511a")
    signature = bytes.fromhex("e5564300c360ac729086e2cc806e828a84877f1eb8e5d974d873e06522490155"
                              "5fb8821590a33bacc61e39701cf9b46bd25bf5f0595bbe24655141438e7a100b")
    alg, key = wa.parse_cose_key(cbor.encode({1: 1, 3: ALG_EDDSA, -1: 6, -2: public}))
    wa._verify_signature(alg, key, signature, b"")
    with pytest.raises(security.SecurityError):
        wa._verify_signature(alg, key, signature, b"x")


def test_cbor_rejects_hostile_input() -> None:
    for bad in (b"\x9f\x01\xff", b"\xc0\x01", b"\xa2\x01\x01\x01\x02", b"\x5a\xff\xff\xff\xff", b"\xfb" + bytes(8), b"\x81" * 20 + b"\x01", b""):
        with pytest.raises(security.SecurityError) as err:
            cbor.decode_all(bad)
        assert err.value.code == "webauthn_format"
    sample = {"fmt": "none", 1: [b"\x00", -7, True, None], -2: "ж"}
    assert cbor.decode_all(cbor.encode(sample)) == sample


def test_prf_gives_a_stable_recovery_secret_only_with_the_same_key() -> None:
    key, other = VirtualKey(), VirtualKey()
    salt = wa.prf_input()
    first = wa.prf_recovery_secret(key.prf_output(salt))
    assert len(first) == 16
    assert first == wa.prf_recovery_secret(key.prf_output(salt))
    assert first != wa.prf_recovery_secret(other.prf_output(salt))
    assert security.parse_recovery_key(_rk(first)) == first  # тот же вид, что у ключа восстановления копий
    with pytest.raises(security.SecurityError) as err:
        wa.prf_recovery_secret(b"short")
    assert err.value.code == "webauthn_prf"


def _rk(secret: bytes) -> str:
    from homensai_security import codes

    return codes.format_key(secret)


# --- TOTP: тест-векторы RFC --------------------------------------------------------------------------------------------

RFC_SECRET = b"12345678901234567890"


def test_hotp_matches_rfc4226_appendix_d() -> None:
    expected = ["755224", "287082", "359152", "969429", "338314", "254676", "287922", "162583", "399871", "520489"]
    assert [security.totp.hotp(RFC_SECRET, i) for i in range(10)] == expected


@pytest.mark.parametrize(
    ("now", "sha1", "sha256", "sha512"),
    [
        (59, "94287082", "46119246", "90693936"),
        (1111111109, "07081804", "68084774", "25091201"),
        (1111111111, "14050471", "67062674", "99943326"),
        (1234567890, "89005924", "91819424", "93441116"),
        (2000000000, "69279037", "90698825", "38618901"),
        (20000000000, "65353130", "77737706", "47863826"),
    ],
)
def test_totp_matches_rfc6238_appendix_b(now: int, sha1: str, sha256: str, sha512: str) -> None:
    seeds = {"sha1": RFC_SECRET, "sha256": b"12345678901234567890123456789012",
             "sha512": b"1234567890123456789012345678901234567890123456789012345678901234"}
    for alg, code in (("sha1", sha1), ("sha256", sha256), ("sha512", sha512)):
        assert security.totp.totp(seeds[alg], now, digits=8, algorithm=alg) == code


def test_totp_window_and_no_replay() -> None:
    secret = security.totp.new_secret()
    now = 1_800_000_000
    code = security.totp.totp(secret, now)
    step = security.totp.verify(secret, code, now)
    assert step == now // 30
    assert security.totp.verify(secret, code, now, last_step=step) is None  # тот же код второй раз не принимается
    assert security.totp.verify(secret, security.totp.totp(secret, now - 30), now) == now // 30 - 1  # часы отстают на шаг
    assert security.totp.verify(secret, security.totp.totp(secret, now - 90), now) is None
    assert security.totp.verify(secret, "12345", now) is None
    assert security.totp.parse_secret(security.totp.secret_text(secret)) == secret
    uri = security.totp.otpauth_uri(secret, account="owner", issuer="HomenS.AI Rent")
    assert uri.startswith("otpauth://totp/HomenS.AI%20Rent%3Aowner?secret=")
    assert "digits=6" in uri
    assert "period=30" in uri


# --- коды восстановления входа -----------------------------------------------------------------------------------------


def test_login_codes_ten_unique_125_bit_and_hashed_with_set() -> None:
    codes = security.login_codes.new_codes()
    assert len(codes) == 10
    assert len(set(codes)) == 10
    assert all(len(c) == 29 and c.count("-") == 4 for c in codes)
    set_id = security.login_codes.new_set_id()
    digest = security.login_codes.code_hash(codes[0], set_id)
    assert len(digest) == 64
    assert codes[0] not in digest
    assert security.login_codes.code_hash(codes[0].lower().replace("-", " "), set_id) == digest  # регистр и разделители не важны
    assert security.login_codes.code_hash(codes[0], "other") != digest  # новый набор — другие отпечатки
    assert security.login_codes.looks_like_code(codes[1])
    assert not security.login_codes.looks_like_code("123456")
    with pytest.raises(security.SecurityError) as err:
        security.login_codes.code_hash("abc", set_id)
    assert err.value.code == "login_code_format"


# --- правила сброса ----------------------------------------------------------------------------------------------------


def test_reset_rules_second_factor_and_timings() -> None:
    reset = security.reset
    token, digest = reset.new_token()
    assert reset.digest(token) == digest == hashlib.sha256(token.encode()).hexdigest()
    assert reset.token_shape_ok(token)
    assert not reset.email_expired(1000, 1000 + 900)
    assert reset.email_expired(1000, 1000 + 901)
    none = reset.Factors()
    with_key = reset.Factors(keys=1, codes_left=3, telegram=True)
    assert reset.reset_allowed(none, link_ok=True, proof=None)
    assert not reset.reset_allowed(none, link_ok=False, proof="totp")
    assert not reset.reset_allowed(with_key, link_ok=True, proof=None)
    assert reset.reset_allowed(with_key, link_ok=True, proof="telegram")  # 284: Telegram — второй фактор для восстановления
    assert reset.proofs_available(with_key) == ("webauthn", "code", "telegram")
    assert reset.delayed_state(0, 72 * 3600 - 1) == "waiting"
    assert reset.delayed_state(0, 72 * 3600) == "ready"
    assert reset.delayed_state(0, 72 * 3600 + 8 * 24 * 3600) == "expired"
    assert reset.mask_email("someone@gmail.com") == "s***@gmail.com"


def test_auth_error_codes_are_data_in_two_languages() -> None:
    for code in ("webauthn_origin", "webauthn_prf", "totp_wrong", "login_code_wrong", "reset_link_invalid", "telegram_denied", "factor_paused"):
        entry = security.ERRORS[code]
        assert entry["ru"]
        assert entry["uk"]
        assert entry["what_to_do_ru"]
        assert entry["what_to_do_uk"]

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Аппаратные ключи и passkey: проверка WebAuthn Level 3 (W3C) на этом ПК (решения владельца 28.10-282, 289).

Почему так: проверенного пакета WebAuthn в rent-runtime.lock нет (py_webauthn, fido2 не закреплены), а тянуть новую
зависимость в продукт с ограниченным списком библиотек нельзя. Поэтому проверка сделана строго по разделам 7.1 и 7.2
спецификации, а подписи проверяет pyca/cryptography (ECDSA P-256, Ed25519, RSA PKCS#1 v1.5). Сами примитивы не пишутся.

Что проверяется при регистрации (7.1): clientDataJSON.type = webauthn.create, challenge совпадает (одноразовый, 32 байта),
origin — из разрешённых (только http://localhost:<порт>), crossOrigin не true; объект аттестации — CBOR, формат «none»
(аттестацию мы не запрашиваем: статистика модели ключа не нужна и раскрывает лишнее), rpIdHash = SHA-256("localhost"),
флаги UP (касание), UV (проверка пользователя: PIN ключа, отпечаток, Windows Hello) и AT, ключ COSE — ES256, EdDSA или RS256.
При входе (7.2): webauthn.get, тот же контроль challenge/origin/rpIdHash/UP/UV, подпись над authenticatorData ‖
SHA-256(clientDataJSON) и счётчик подписей: если хоть один из счётчиков не 0, новый должен быть больше сохранённого —
иначе возможен клон ключа (`webauthn_counter`). Passkey в менеджерах паролей обычно шлют 0 — это допустимо.

Флаги BE/BS (резервируемый / синхронизированный ключ) отличают passkey из менеджера паролей (NordPass, iCloud, Google) от
аппаратного ключа: на экране это подсказка вида ключа, на решение о входе не влияет.

Открытие копий (282 п. 1, 289 п. 2): расширение PRF (hmac-secret у аппаратных ключей). Аутентификатор считает HMAC от
постоянной соли программы своим внутренним секретом; из 32 байт результата HKDF-SHA256 делает 16-байтовый ключ
восстановления (`prf_recovery_secret`) — дальше он работает как обычный ключ восстановления копий (получатель X25519).
Где PRF не поддержан (часть менеджеров паролей, старые браузеры), браузер не вернёт результат — программа так и пишет."""

from __future__ import annotations

import base64
from collections.abc import Iterable
from dataclasses import dataclass
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from homensai_security import cbor
from homensai_security.errors import SecurityError

RP_ID = "localhost"  # 282 п. 2: только на этом ПК; IP-адрес (127.0.0.1) идентификатором RP быть не может
ALG_ES256 = -7
ALG_EDDSA = -8
ALG_RS256 = -257
ALGORITHMS = (ALG_ES256, ALG_EDDSA, ALG_RS256)  # RS256 — для Windows Hello на части TPM
FLAG_UP = 0x01
FLAG_UV = 0x04
FLAG_BE = 0x08
FLAG_BS = 0x10
FLAG_AT = 0x40
FLAG_ED = 0x80
CHALLENGE_BYTES = 32
TIMEOUT_MS = 120_000
MAX_CREDENTIAL_ID = 1023  # W3C: не длиннее 1023 байт
MAX_CLIENT_DATA = 4096
MIN_RSA_BITS = 2048
PRF_LABEL = b"homensai-security/webauthn-prf/backup/1"
PRF_INFO = b"homensai-security/webauthn-prf/recovery/1"


def b64url(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii").rstrip("=")


def unb64url(text: object, *, limit: int = 1 << 16) -> bytes:
    if not isinstance(text, str) or len(text) > limit or any(ch not in _B64URL for ch in text):
        raise SecurityError("webauthn_format")
    try:
        return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))
    except ValueError as exc:
        raise SecurityError("webauthn_format") from exc


_B64URL = frozenset("ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789-_")


def new_challenge() -> bytes:
    return secrets.token_bytes(CHALLENGE_BYTES)


def origins_for(port: int) -> tuple[str, ...]:
    """Разрешённые origin: только localhost этого ПК на порту программы (без локального HTTPS, 282 п. 2)."""
    return (f"http://localhost:{port}",)


# --- authenticatorData и COSE ---------------------------------------------------------------------------------------


@dataclass(frozen=True)
class AuthData:
    rp_id_hash: bytes
    flags: int
    sign_count: int
    aaguid: bytes = b""
    credential_id: bytes = b""
    public_key: bytes = b""  # ключ COSE в виде CBOR, как прислал аутентификатор
    extensions: dict[Any, Any] | None = None


def parse_auth_data(data: bytes) -> AuthData:
    """Разбор authenticatorData (W3C 6.1): 32 байта rpIdHash, флаги, счётчик, затем данные ключа (AT) и расширения (ED)."""
    if not isinstance(data, bytes) or len(data) < 37:
        raise SecurityError("webauthn_format")
    rp_hash, flags, count = data[:32], data[32], int.from_bytes(data[33:37], "big")
    pos = 37
    aaguid = credential_id = public = b""
    if flags & FLAG_AT:
        if len(data) < pos + 18:
            raise SecurityError("webauthn_format")
        aaguid = data[pos : pos + 16]
        length = int.from_bytes(data[pos + 16 : pos + 18], "big")
        pos += 18
        if not 16 <= length <= MAX_CREDENTIAL_ID or len(data) < pos + length:
            raise SecurityError("webauthn_format")
        credential_id = data[pos : pos + length]
        pos += length
        _key, end = cbor.decode(data, pos)
        public = data[pos:end]
        pos = end
    extensions: dict[Any, Any] | None = None
    if flags & FLAG_ED:
        found, pos = cbor.decode(data, pos)
        if not isinstance(found, dict):
            raise SecurityError("webauthn_format")
        extensions = found
    if pos != len(data):
        raise SecurityError("webauthn_format")
    return AuthData(rp_hash, flags, count, aaguid, credential_id, public, extensions)


PublicKey = ec.EllipticCurvePublicKey | Ed25519PublicKey | rsa.RSAPublicKey


def parse_cose_key(cose: bytes) -> tuple[int, PublicKey]:
    """(алгоритм, открытый ключ) из ключа COSE (RFC 9053/8230): EC2 P-256 + ES256, OKP Ed25519 + EdDSA, RSA + RS256."""
    key = cbor.decode_all(cose)
    if not isinstance(key, dict):
        raise SecurityError("webauthn_key")
    kty, alg = key.get(1), key.get(3)
    try:
        if kty == 2 and alg == ALG_ES256 and key.get(-1) == 1:
            x, y = key.get(-2), key.get(-3)
            if not (isinstance(x, bytes) and isinstance(y, bytes) and len(x) == 32 and len(y) == 32):
                raise SecurityError("webauthn_key")
            numbers = ec.EllipticCurvePublicNumbers(int.from_bytes(x, "big"), int.from_bytes(y, "big"), ec.SECP256R1())
            return ALG_ES256, numbers.public_key()  # точка вне кривой — ValueError
        if kty == 1 and alg == ALG_EDDSA and key.get(-1) == 6:
            x = key.get(-2)
            if not (isinstance(x, bytes) and len(x) == 32):
                raise SecurityError("webauthn_key")
            return ALG_EDDSA, Ed25519PublicKey.from_public_bytes(x)
        if kty == 3 and alg == ALG_RS256:
            n, e = key.get(-1), key.get(-2)
            if not (isinstance(n, bytes) and isinstance(e, bytes)) or len(n) * 8 < MIN_RSA_BITS or len(e) > 8:
                raise SecurityError("webauthn_key")
            return ALG_RS256, rsa.RSAPublicNumbers(int.from_bytes(e, "big"), int.from_bytes(n, "big")).public_key()
    except ValueError as exc:
        raise SecurityError("webauthn_key") from exc
    raise SecurityError("webauthn_key")


def _verify_signature(alg: int, key: PublicKey, signature: bytes, data: bytes) -> None:
    try:
        if alg == ALG_ES256 and isinstance(key, ec.EllipticCurvePublicKey):
            key.verify(signature, data, ec.ECDSA(hashes.SHA256()))
        elif alg == ALG_EDDSA and isinstance(key, Ed25519PublicKey):
            key.verify(signature, data)
        elif alg == ALG_RS256 and isinstance(key, rsa.RSAPublicKey):
            key.verify(signature, data, padding.PKCS1v15(), hashes.SHA256())
        else:
            raise SecurityError("webauthn_key")
    except (InvalidSignature, ValueError) as exc:
        raise SecurityError("webauthn_signature") from exc


# --- clientDataJSON --------------------------------------------------------------------------------------------------


def _client_data(raw: bytes, *, kind: str, challenge: bytes, origins: Iterable[str]) -> None:
    if not isinstance(raw, bytes) or not 0 < len(raw) <= MAX_CLIENT_DATA:
        raise SecurityError("webauthn_format")
    try:
        data = json.loads(raw.decode("utf-8"))
    except (UnicodeDecodeError, ValueError) as exc:
        raise SecurityError("webauthn_format") from exc
    if not isinstance(data, dict) or data.get("type") != kind:
        raise SecurityError("webauthn_format")
    got = unb64url(data.get("challenge"), limit=256)
    if not hmac.compare_digest(got, challenge):
        raise SecurityError("webauthn_challenge")
    if data.get("origin") not in set(origins):
        raise SecurityError("webauthn_origin")
    if data.get("crossOrigin") is True or "topOrigin" in data:
        raise SecurityError("webauthn_origin")


def _flags(auth: AuthData, *, rp_id: str, require_uv: bool) -> None:
    if not hmac.compare_digest(auth.rp_id_hash, hashlib.sha256(rp_id.encode("ascii")).digest()):
        raise SecurityError("webauthn_origin")
    if not auth.flags & FLAG_UP:
        raise SecurityError("webauthn_presence")
    if require_uv and not auth.flags & FLAG_UV:
        raise SecurityError("webauthn_uv")
    if auth.flags & FLAG_BS and not auth.flags & FLAG_BE:
        raise SecurityError("webauthn_format")  # W3C: BS без BE недопустим


# --- регистрация -----------------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class RegisteredKey:
    credential_id: bytes
    public_key: bytes  # COSE (CBOR) — храним как есть
    alg: int
    sign_count: int
    user_verified: bool
    backup_eligible: bool  # BE: ключ может синхронизироваться — это passkey менеджера паролей или системы
    backed_up: bool
    aaguid: str


def verify_registration(*, client_data_json: bytes, attestation_object: bytes, challenge: bytes, origins: Iterable[str],
                        rp_id: str = RP_ID, require_uv: bool = True) -> RegisteredKey:
    """Проверка ответа navigator.credentials.create (W3C 7.1). Ошибка — SecurityError с кодом `webauthn_*`."""
    _client_data(client_data_json, kind="webauthn.create", challenge=challenge, origins=origins)
    obj = cbor.decode_all(attestation_object)
    if not isinstance(obj, dict) or not isinstance(obj.get("authData"), bytes):
        raise SecurityError("webauthn_format")
    if obj.get("fmt") != "none" or obj.get("attStmt") != {}:
        raise SecurityError("webauthn_attestation")
    auth = parse_auth_data(obj["authData"])
    _flags(auth, rp_id=rp_id, require_uv=require_uv)
    if not auth.flags & FLAG_AT or not auth.credential_id:
        raise SecurityError("webauthn_format")
    alg, _key = parse_cose_key(auth.public_key)
    return RegisteredKey(auth.credential_id, auth.public_key, alg, auth.sign_count, bool(auth.flags & FLAG_UV),
                         bool(auth.flags & FLAG_BE), bool(auth.flags & FLAG_BS), auth.aaguid.hex())


# --- вход и подтверждение --------------------------------------------------------------------------------------------


@dataclass(frozen=True)
class Assertion:
    sign_count: int
    user_verified: bool
    backed_up: bool


def verify_assertion(*, public_key: bytes, client_data_json: bytes, authenticator_data: bytes, signature: bytes, challenge: bytes,
                     origins: Iterable[str], stored_sign_count: int, rp_id: str = RP_ID, require_uv: bool = True) -> Assertion:
    """Проверка ответа navigator.credentials.get (W3C 7.2): подпись, rpIdHash, UP/UV, счётчик подписей."""
    _client_data(client_data_json, kind="webauthn.get", challenge=challenge, origins=origins)
    auth = parse_auth_data(authenticator_data)
    _flags(auth, rp_id=rp_id, require_uv=require_uv)
    alg, key = parse_cose_key(public_key)
    if not isinstance(signature, bytes) or not 0 < len(signature) <= 1024:
        raise SecurityError("webauthn_signature")
    _verify_signature(alg, key, signature, authenticator_data + hashlib.sha256(client_data_json).digest())
    if (auth.sign_count or stored_sign_count) and auth.sign_count <= stored_sign_count:
        raise SecurityError("webauthn_counter")
    return Assertion(auth.sign_count, bool(auth.flags & FLAG_UV), bool(auth.flags & FLAG_BS))


# --- параметры для браузера ------------------------------------------------------------------------------------------


def creation_options(*, challenge: bytes, user_id: bytes, user_name: str, display_name: str, rp_name: str,
                     exclude: Iterable[bytes] = (), prf: bool = True) -> dict[str, Any]:
    """publicKey для navigator.credentials.create (байты — base64url, их переводит rent-webauthn.js).
    Обнаруживаемый ключ (resident key) с обязательной проверкой пользователя (289 п. 1), аттестация «none»."""
    options: dict[str, Any] = {
        "rp": {"id": RP_ID, "name": rp_name},
        "user": {"id": b64url(user_id), "name": user_name, "displayName": display_name},
        "challenge": b64url(challenge),
        "pubKeyCredParams": [{"type": "public-key", "alg": alg} for alg in ALGORITHMS],
        "timeout": TIMEOUT_MS,
        "attestation": "none",
        "authenticatorSelection": {"residentKey": "required", "requireResidentKey": True, "userVerification": "required"},
        "excludeCredentials": [{"type": "public-key", "id": b64url(c)} for c in exclude],
        "extensions": {"credProps": True},
    }
    if prf:
        options["extensions"]["prf"] = {}
    return options


def request_options(*, challenge: bytes, allow: Iterable[bytes] = (), prf_eval: bytes | None = None) -> dict[str, Any]:
    """publicKey для navigator.credentials.get. Пустой `allow` — обнаруживаемые ключи (вход без пароля, выбор passkey)."""
    options: dict[str, Any] = {
        "rpId": RP_ID,
        "challenge": b64url(challenge),
        "timeout": TIMEOUT_MS,
        "userVerification": "required",
        "allowCredentials": [{"type": "public-key", "id": b64url(c)} for c in allow],
    }
    if prf_eval is not None:
        options["extensions"] = {"prf": {"eval": {"first": b64url(prf_eval)}}}
    return options


def prf_input(purpose: str = "backup") -> bytes:
    """Постоянная соль PRF программы (браузер сам добавляет префикс «WebAuthn PRF» по спецификации)."""
    return hashlib.sha256(PRF_LABEL + b"\x00" + purpose.encode("ascii")).digest()


def prf_recovery_secret(prf_output: bytes) -> bytes:
    """16-байтовый ключ восстановления копий из 32 байт PRF (HKDF-SHA256): ключ становится ещё одним получателем копий."""
    if not isinstance(prf_output, bytes) or len(prf_output) != 32:
        raise SecurityError("webauthn_prf")
    return HKDF(algorithm=hashes.SHA256(), length=16, salt=None, info=PRF_INFO).derive(prf_output)


def user_handle(seed: bytes) -> bytes:
    """Идентификатор пользователя WebAuthn: 32 случайных байта (W3C: без личных данных)."""
    return hashlib.sha256(b"homensai-security/webauthn-user/1\x00" + seed).digest()

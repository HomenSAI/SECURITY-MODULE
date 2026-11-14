# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ключ хозяйства для копий (Rent `app/archive/keys.py`, MOD.extract-backups; формат — spec/key-envelope.md).
Пароль не хранится, копии делаются без его ввода (28.10-269 → основа для 270/276/279).

Устройство (как age с паролем на ключе, restic/Borg с несколькими ключами):
- при включении пароля или PIN создаётся пара X25519; закрытый ключ шифруется ChaCha20-Poly1305 ключом из пароля через
  Argon2id (28.10-279, параметры не слабее OWASP; PIN — с большим числом проходов). В настройке хозяйства лежат только
  открытый ключ, отпечаток и этот «завёрнутый» закрытый ключ (`wrapped`); пароль и PIN нигде не сохраняются;
- каждая копия получает свой случайный секрет 256 бит, которым зашифрован внешний ZIP (WinZip AES-256: слабый PBKDF2
  формата не важен при случайном секрете). Секрет запечатан на открытый ключ хозяйства: эфемерный X25519 → HKDF-SHA256 →
  ChaCha20-Poly1305. Конверт и завёрнутый закрытый ключ лежат в комментарии внешнего ZIP («HRKEY1 {json}»), поэтому копию
  на любом носителе открывает один пароль, и на другом ПК тоже;
- проверка пароля — расшифровка закрытого ключа (270). Смена пароля — новая пара ключей: старые копии несут свой
  завёрнутый ключ и открываются прежним паролем (269).
Пакет `cryptography` (уже в rent-runtime.lock для шифрования полей). Параметры KDF из чужого файла ограничены сверху:
повреждённая или подложенная копия не заставит программу выделить гигабайты памяти.
"""

from __future__ import annotations

import base64
import hashlib
import json
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from homensai_security import public_api as security

ENVELOPE_PREFIX = b"HRKEY1 "
ENVELOPE_VERSION = 1
# SEC-parse (ревью B3-followup, Н-П4) и SEC-zip (ревью SEC-parse, Р1): в конверт идут все записи `state.recovery` —
# до 3 бумажных ключей и 10 аппаратных (`protection.MAX_RECOVERY + MAX_DEVICE_KEYS`): ≈ 3,6 КиБ (замер 11.11.2026;
# 3 ключа — ≈ 1,2 КиБ). Предел — максимум комментария ZIP (65535): рекурсия JSON ловится отдельно, а запас ×17 не даст
# росту числа ключей молча превратить настоящие копии в «прежние без конверта». Длиннее — повреждённый конверт.
ENVELOPE_LIMIT = 65535
WRAP_AAD = b"homensai-rent/archive-identity/1"
RECOVERY_AAD = b"homensai-rent/archive-identity-recovery/1"  # 28.10-279/284: закрытый ключ, запечатанный на ключ восстановления
SEAL_INFO = b"homensai-rent/archive-secret/1"
# OWASP (Password Storage Cheat Sheet): Argon2id m=19 МиБ, t=2, p=1 — минимум; берём сильнее. PIN — больше проходов:
# 10 000 вариантов перебираются быстрее любого пароля, поэтому каждая попытка дороже (и всё равно — предупреждение 269).
KDF_PASSWORD = {"m": 65536, "t": 3, "p": 4}
KDF_PIN = {"m": 65536, "t": 8, "p": 4}
KDF_LIMITS = {"m": (19456, 1024 * 1024), "t": (2, 32), "p": (1, 16)}  # снизу — OWASP, сверху — защита от подложенной копии
SECRET_BYTES = 32



class BackupKeyError(Exception):
    """Ошибка ключа копий. `code` — как в spec/error-codes.json (`corrupt`, `bad_password`, …); текст без путей и секретов."""

    def __init__(self, code: str, detail: str | None = None) -> None:
        self.code = code
        super().__init__(code if not detail else f"{code}: {detail}")


ArchiveError = BackupKeyError  # имя Rent для совместимости адаптеров


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: object, size: int | None = None) -> bytes:
    if not isinstance(text, str) or len(text) > 512:
        raise ArchiveError("corrupt", "неверный конверт ключа")
    try:
        data = base64.urlsafe_b64decode(text.encode("ascii"))
    except ValueError as exc:
        raise ArchiveError("corrupt", "неверный конверт ключа") from exc
    if size is not None and len(data) != size:
        raise ArchiveError("corrupt", "неверный конверт ключа")
    return data


def _kdf_params(wrapped: dict[str, Any]) -> tuple[int, int, int]:
    if wrapped.get("kdf") != "argon2id":
        raise ArchiveError("corrupt", "неизвестная функция ключа")
    values = []
    for name in ("m", "t", "p"):
        value = wrapped.get(name)
        low, high = KDF_LIMITS[name]
        if isinstance(value, bool) or not isinstance(value, int) or not low <= value <= high:
            raise ArchiveError("corrupt", "недопустимые параметры функции ключа")
        values.append(value)
    if values[0] < 8 * values[2]:
        raise ArchiveError("corrupt", "недопустимые параметры функции ключа")
    return values[0], values[1], values[2]


def _derive(password: bytes, salt: bytes, m: int, t: int, p: int) -> bytes:
    return Argon2id(salt=salt, length=32, iterations=t, lanes=p, memory_cost=m).derive(password)


def _public_raw(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def fingerprint_of(public_b64: str) -> str:
    """Отпечаток открытого ключа для бумаги: «HR1-» и 16 знаков sha256 группами по 4 (как коды Auto VPN)."""
    digest = hashlib.sha256(b"homensai-rent/archive-key\x00" + _unb64(public_b64, 32)).hexdigest()[:16].upper()
    return "HR1-" + "-".join(digest[i : i + 4] for i in range(0, 16, 4))


def new_raw_identity() -> bytes:
    """Новый закрытый ключ хозяйства X25519 (32 байта) — только в памяти."""
    private = X25519PrivateKey.generate()
    return private.private_bytes(serialization.Encoding.Raw, serialization.PrivateFormat.Raw, serialization.NoEncryption())


def new_identity(password: str, *, pin: bool = False) -> tuple[str, str, dict[str, Any]]:
    """Новая пара ключей хозяйства: (открытый ключ, отпечаток, закрытый ключ под паролем). Пароль не возвращается и не хранится."""
    return wrap_identity(new_raw_identity(), password, pin=pin)


def wrap_identity(raw: bytes, password: str, *, pin: bool = False) -> tuple[str, str, dict[str, Any]]:
    """Закрытый ключ хозяйства под паролем (Argon2id → ChaCha20-Poly1305): новый ключ или тот же ключ с новым паролем
    (сброс забытого пароля ключом восстановления, 28.10-279)."""
    private = X25519PrivateKey.from_private_bytes(raw)
    public = _b64(_public_raw(private))
    params = KDF_PIN if pin else KDF_PASSWORD
    salt, nonce = secrets.token_bytes(16), secrets.token_bytes(12)
    key = _derive(password.encode("utf-8"), salt, params["m"], params["t"], params["p"])
    sealed = ChaCha20Poly1305(key).encrypt(nonce, raw, WRAP_AAD + _unb64(public, 32))
    wrapped = {"v": 1, "kdf": "argon2id", **params, "salt": _b64(salt), "nonce": _b64(nonce), "ct": _b64(sealed)}
    return public, fingerprint_of(public), wrapped


def unwrap_identity(wrapped: object, password: str | bytes, *, public: str) -> bytes:
    """Закрытый ключ хозяйства (32 байта) по паролю; неверный пароль — ArchiveError('bad_password'), без текста пароля."""
    if not isinstance(wrapped, dict):
        raise ArchiveError("corrupt", "неверный конверт ключа")
    m, t, p = _kdf_params(wrapped)
    salt, nonce, sealed = _unb64(wrapped.get("salt"), 16), _unb64(wrapped.get("nonce"), 12), _unb64(wrapped.get("ct"), 48)
    secret = password.encode("utf-8") if isinstance(password, str) else bytes(password)
    try:
        raw = ChaCha20Poly1305(_derive(secret, salt, m, t, p)).decrypt(nonce, sealed, WRAP_AAD + _unb64(public, 32))
    except InvalidTag as exc:
        raise ArchiveError("bad_password") from exc
    if _b64(_public_raw(X25519PrivateKey.from_private_bytes(raw))) != public:
        raise ArchiveError("corrupt", "закрытый ключ не соответствует открытому")
    return raw


def public_of_raw(raw: bytes) -> str:
    return _b64(_public_raw(X25519PrivateKey.from_private_bytes(raw)))


def seal_identity(raw: bytes, recovery_public: str) -> dict[str, Any]:
    """Закрытый ключ хозяйства, запечатанный на открытый ключ получателя «ключ восстановления»; сам ключ восстановления не нужен."""
    public = public_of_raw(raw)
    return dict(security.seal_to(recovery_public, raw, aad=RECOVERY_AAD + _unb64(public, 32)))


def open_identity(sealed: object, secret: bytes, *, public: str) -> bytes:
    """Закрытый ключ хозяйства по ключу восстановления (16 байт); чужой ключ — ArchiveError('recovery_wrong')."""
    try:
        raw = security.open_with(secret, sealed, aad=RECOVERY_AAD + _unb64(public, 32))
    except security.SecurityError as exc:
        raise ArchiveError(exc.code) from exc
    if len(raw) != 32 or public_of_raw(raw) != public:
        raise ArchiveError("recovery_wrong")
    return raw


def recovery_secret(text: str) -> bytes | None:
    """Ключ восстановления из ввода (RK1-… или две части RS1-…); обычный пароль — None; опечатка — ArchiveError с кодом."""
    try:
        return security.recovery_from_input(text)
    except security.SecurityError as exc:
        raise ArchiveError(exc.code) from exc


def private_by_recovery(entries: list[Any] | tuple[Any, ...], secret: bytes, *, public: str) -> bytes:
    """Закрытый ключ хозяйства по ключу восстановления: перебираются все запечатанные записи (`sealed`), подошедшая открывает."""
    for entry in entries:
        sealed = entry.get("sealed") if isinstance(entry, dict) else getattr(entry, "sealed", None)
        try:
            return open_identity(sealed, secret, public=public)
        except ArchiveError:
            continue
    raise ArchiveError("recovery_wrong")


def _seal_key(shared: bytes, epk: bytes, pk: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + pk, info=SEAL_INFO).derive(shared)


def seal(mode: str, public: str, wrapped: dict[str, Any], recovery: list[dict[str, Any]] | tuple[Any, ...] = ()) -> tuple[bytes, bytes]:
    """Случайный секрет новой копии (пароль внешнего ZIP) и комментарий ZIP с конвертом. Пароль пользователя не нужен.
    `recovery` — записи ключей восстановления (28.10-279/284): в конверт попадает закрытый ключ, запечатанный на каждый из них,
    поэтому копию на другом ПК открывает и пароль, и любой действующий ключ восстановления."""
    pk = _unb64(public, 32)
    secret = _b64(secrets.token_bytes(SECRET_BYTES)).encode("ascii")
    ephemeral = X25519PrivateKey.generate()
    epk = _public_raw(ephemeral)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(pk))
    nonce = secrets.token_bytes(12)
    sealed = ChaCha20Poly1305(_seal_key(shared, epk, pk)).encrypt(nonce, secret, SEAL_INFO)
    envelope = {
        "v": ENVELOPE_VERSION, "mode": mode, "kid": fingerprint_of(public), "pub": public,
        "epk": _b64(epk), "nonce": _b64(nonce), "ct": _b64(sealed), "wrapped": wrapped,
    }
    entries = [{"id": r["id"], "sealed": r["sealed"]} if isinstance(r, dict) else {"id": r.id, "sealed": r.sealed} for r in recovery]
    if entries:
        envelope["recovery"] = entries
    return secret, ENVELOPE_PREFIX + json.dumps(envelope, separators=(",", ":"), sort_keys=True).encode("ascii")


def open_comment() -> bytes:
    """Комментарий копии без пароля (режим «none»): по нему восстановление знает, что пароль не нужен."""
    return ENVELOPE_PREFIX + json.dumps({"v": ENVELOPE_VERSION, "mode": "none"}, separators=(",", ":")).encode("ascii")


def envelope_from_comment(comment: bytes) -> dict[str, Any] | None:
    """Конверт из комментария внешнего ZIP; прежняя копия (без конверта) или мусор — None."""
    if not comment.startswith(ENVELOPE_PREFIX) or len(comment) > ENVELOPE_LIMIT:
        return None
    try:  # SEC-parse, Н-П4: глубокая вложенность (RecursionError) — тоже повреждённый конверт, а не исключение
        envelope = json.loads(comment[len(ENVELOPE_PREFIX):].decode("ascii"))
    except (ValueError, RecursionError):
        return None
    if not isinstance(envelope, dict) or envelope.get("v") != ENVELOPE_VERSION or envelope.get("mode") not in ("none", "generated", "custom", "pin"):
        return None
    return envelope


def open_password(envelope: dict[str, Any], password: bytes | None) -> bytes:
    """Секрет копии (пароль внешнего ZIP) из конверта по паролю или PIN пользователя."""
    if not password:
        raise ArchiveError("no_key")
    public = envelope.get("pub")
    if not isinstance(public, str):
        raise ArchiveError("corrupt", "неверный конверт ключа")
    pk = _unb64(public, 32)
    text = password.decode("utf-8", errors="replace")
    try:
        secret = recovery_secret(text) if security.looks_like_recovery(text) or "RS1" in text.upper() else None
    except ArchiveError as exc:
        if exc.code != "recovery_format":
            raise
        secret = None  # пароль, случайно похожий на начало ключа: проверяется как пароль
    if secret is not None:  # 28.10-279: забытый пароль — ключ восстановления или две части «2 из 3»
        entries = envelope.get("recovery")
        raw = private_by_recovery(entries if isinstance(entries, list) else [], secret, public=public)
    else:
        raw = unwrap_identity(envelope.get("wrapped"), password, public=public)
    private = X25519PrivateKey.from_private_bytes(raw)
    epk = _unb64(envelope.get("epk"), 32)
    shared = private.exchange(X25519PublicKey.from_public_bytes(epk))
    try:
        return ChaCha20Poly1305(_seal_key(shared, epk, pk)).decrypt(_unb64(envelope.get("nonce"), 12), _unb64(envelope.get("ct")), SEAL_INFO)
    except InvalidTag as exc:
        raise ArchiveError("corrupt", "конверт копии повреждён") from exc

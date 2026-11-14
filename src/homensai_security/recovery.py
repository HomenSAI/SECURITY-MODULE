# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Ключ восстановления как получатель (28.10-279 п. 2, 28.10-284 п. 2: несколько именованных ключей с отзывом).

Ключ восстановления (128 бит) детерминированно задаёт пару X25519: закрытый ключ = HKDF-SHA256(ключ восстановления).
На ПК хранится только открытый ключ получателя — сам ключ восстановления живёт на аварийном листе и в менеджере паролей.
Поэтому закрытый ключ хозяйства можно «запечатать» на ключ восстановления в любой момент без него: при смене пароля, при
отзыве другого ключа (новая пара ключей хозяйства) — так же, как age шифрует на несколько получателей X25519.

Запечатывание: эфемерный X25519 → общий секрет → HKDF-SHA256 (соль = эфемерный ключ ‖ ключ получателя) → ChaCha20-Poly1305
с привязкой к контексту (AAD). Растягивание пароля (Argon2id) здесь не нужно: у ключа 128 бит случайности, перебор
невозможен (NIST SP 800-132 растягивает только пароли с низкой энтропией).
"""

from __future__ import annotations

import base64
import hashlib
import secrets
from typing import Any

from cryptography.exceptions import InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers.aead import ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.hkdf import HKDF

from homensai_security.errors import SecurityError

KEY_INFO = b"homensai-security/recovery-key/1"
SEAL_INFO = b"homensai-security/recovery-seal/1"
MAX_PAYLOAD = 256


def _b64(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def _unb64(text: object, size: int | None = None) -> bytes:
    if not isinstance(text, str) or len(text) > 512:
        raise SecurityError("recovery_wrong")
    try:
        data = base64.urlsafe_b64decode(text.encode("ascii"))
    except ValueError as exc:
        raise SecurityError("recovery_wrong") from exc
    if size is not None and len(data) != size:
        raise SecurityError("recovery_wrong")
    return data


def _raw_public(private: X25519PrivateKey) -> bytes:
    return private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def _private(secret: bytes) -> X25519PrivateKey:
    seed = HKDF(algorithm=hashes.SHA256(), length=32, salt=None, info=KEY_INFO).derive(secret)
    return X25519PrivateKey.from_private_bytes(seed)


def public_of(secret: bytes) -> str:
    """Открытый ключ получателя (base64url) для ключа восстановления — его можно хранить на ПК."""
    return _b64(_raw_public(_private(secret)))


def recovery_id(public: str) -> str:
    """Короткий отпечаток ключа восстановления («RK-XXXX-XXXX»): по нему видно, какой ключ отозван, сам ключ не раскрывается."""
    digest = hashlib.sha256(b"homensai-security/recovery-id\x00" + _unb64(public, 32)).hexdigest()[:8].upper()
    return f"RK-{digest[:4]}-{digest[4:]}"


def _key(shared: bytes, epk: bytes, rpk: bytes) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=32, salt=epk + rpk, info=SEAL_INFO).derive(shared)


def seal_to(public: str, payload: bytes, *, aad: bytes) -> dict[str, Any]:
    """Запечатывает `payload` (например, закрытый ключ хозяйства) на открытый ключ получателя; ключ восстановления не нужен."""
    if len(payload) > MAX_PAYLOAD:
        raise SecurityError("recovery_format")
    rpk = _unb64(public, 32)
    ephemeral = X25519PrivateKey.generate()
    epk = _raw_public(ephemeral)
    nonce = secrets.token_bytes(12)
    shared = ephemeral.exchange(X25519PublicKey.from_public_bytes(rpk))
    sealed = ChaCha20Poly1305(_key(shared, epk, rpk)).encrypt(nonce, payload, aad)
    return {"v": 1, "rpk": public, "epk": _b64(epk), "nonce": _b64(nonce), "ct": _b64(sealed)}


def open_with(secret: bytes, sealed: object, *, aad: bytes) -> bytes:
    """Открывает запечатанное ключом восстановления; чужой ключ или подмена — SecurityError('recovery_wrong')."""
    if not isinstance(sealed, dict):
        raise SecurityError("recovery_wrong")
    private = _private(secret)
    rpk = _raw_public(private)
    if _unb64(sealed.get("rpk"), 32) != rpk:
        raise SecurityError("recovery_wrong")
    epk = _unb64(sealed.get("epk"), 32)
    try:
        shared = private.exchange(X25519PublicKey.from_public_bytes(epk))
        return ChaCha20Poly1305(_key(shared, epk, rpk)).decrypt(_unb64(sealed.get("nonce"), 12), _unb64(sealed.get("ct")), aad)
    except (InvalidTag, ValueError) as exc:
        raise SecurityError("recovery_wrong") from exc

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Виртуальный аутентификатор WebAuthn для проверок (28.10-282, 289): ключи создаются в самом тесте, сеть и браузер не нужны.

Делает то же, что браузер с ключом: clientDataJSON, authenticatorData с флагами UP/UV/BE/BS/AT, объект аттестации «none»
(CBOR), подпись ES256 / EdDSA / RS256 над authenticatorData ‖ SHA-256(clientDataJSON), счётчик подписей и PRF (HMAC-SHA256
внутренним секретом ключа над солью — как hmac-secret)."""

from __future__ import annotations

from dataclasses import dataclass, field
import hashlib
import hmac
import json
import secrets
from typing import Any

from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import ec, padding, rsa
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from homensai_security import cbor
from homensai_security.webauthn import ALG_EDDSA, ALG_ES256, ALG_RS256, b64url, unb64url

ORIGIN = "http://localhost:8820"


@dataclass
class VirtualKey:
    alg: int = ALG_ES256
    rp_id: str = "localhost"
    uv: bool = True
    backup_eligible: bool = False
    counter: int = 0
    counting: bool = True  # False — как passkey менеджера паролей: счётчик всегда 0
    prf: bool = True
    credential_id: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    cred_random: bytes = field(default_factory=lambda: secrets.token_bytes(32))
    private: Any = None

    def __post_init__(self) -> None:
        if self.private is None:
            if self.alg == ALG_ES256:
                self.private = ec.generate_private_key(ec.SECP256R1())
            elif self.alg == ALG_EDDSA:
                self.private = Ed25519PrivateKey.generate()
            else:
                self.private = rsa.generate_private_key(public_exponent=65537, key_size=2048)

    def cose(self) -> bytes:
        if self.alg == ALG_ES256:
            numbers = self.private.public_key().public_numbers()
            return cbor.encode({1: 2, 3: ALG_ES256, -1: 1, -2: numbers.x.to_bytes(32, "big"), -3: numbers.y.to_bytes(32, "big")})
        if self.alg == ALG_EDDSA:
            from cryptography.hazmat.primitives import serialization

            raw = self.private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
            return cbor.encode({1: 1, 3: ALG_EDDSA, -1: 6, -2: raw})
        numbers = self.private.public_key().public_numbers()
        return cbor.encode({1: 3, 3: ALG_RS256, -1: numbers.n.to_bytes(256, "big"), -2: numbers.e.to_bytes(3, "big")})

    def _flags(self, *, attested: bool) -> int:
        value = 0x01 | (0x04 if self.uv else 0) | (0x08 | 0x10 if self.backup_eligible else 0)
        return value | (0x40 if attested else 0)

    def _auth_data(self, *, attested: bool) -> bytes:
        if self.counting:
            self.counter += 1
        head = hashlib.sha256(self.rp_id.encode()).digest() + bytes([self._flags(attested=attested)])
        head += (self.counter if self.counting else 0).to_bytes(4, "big")
        if attested:
            head += bytes(16) + len(self.credential_id).to_bytes(2, "big") + self.credential_id + self.cose()
        return head

    def _sign(self, data: bytes) -> bytes:
        if self.alg == ALG_ES256:
            return bytes(self.private.sign(data, ec.ECDSA(hashes.SHA256())))
        if self.alg == ALG_EDDSA:
            return bytes(self.private.sign(data))
        return bytes(self.private.sign(data, padding.PKCS1v15(), hashes.SHA256()))

    def prf_output(self, salt: bytes) -> bytes:
        return hmac.new(self.cred_random, salt, hashlib.sha256).digest()

    def create(self, options: dict[str, Any], origin: str = ORIGIN, *, fmt: str = "none") -> dict[str, Any]:
        """Ответ navigator.credentials.create в виде, который шлёт rent-webauthn.js."""
        client = json.dumps({"type": "webauthn.create", "challenge": options["challenge"], "origin": origin, "crossOrigin": False}).encode()
        attestation = cbor.encode({"fmt": fmt, "attStmt": {}, "authData": self._auth_data(attested=True)})
        return {"id": b64url(self.credential_id), "clientDataJSON": b64url(client), "attestationObject": b64url(attestation),
                "prf": self.prf}

    def get(self, options: dict[str, Any], origin: str = ORIGIN) -> dict[str, Any]:
        """Ответ navigator.credentials.get (с результатом PRF, если его просили и ключ умеет)."""
        client = json.dumps({"type": "webauthn.get", "challenge": options["challenge"], "origin": origin}).encode()
        auth = self._auth_data(attested=False)
        reply: dict[str, Any] = {
            "id": b64url(self.credential_id), "clientDataJSON": b64url(client), "authenticatorData": b64url(auth),
            "signature": b64url(self._sign(auth + hashlib.sha256(client).digest())),
        }
        first = (((options.get("extensions") or {}).get("prf") or {}).get("eval") or {}).get("first")
        if first and self.prf:
            reply["prf"] = b64url(self.prf_output(unb64url(first)))
        return reply

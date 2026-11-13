# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Генератор тест-векторов спецификации (`spec/vectors/*.json`) и выписки кодов ошибок (`spec/error-codes.json`).

Вектора считаются кодом Rent (HomenSAI/Homensai-Rent), подключённым через `sys.path`: так спецификация закрепляет то,
что реально пишет и читает продукт. Все пароли, ключи и данные — вымышленные и нужны только для векторов.

Детерминизм: случайность Rent (`secrets.token_bytes`, генерация X25519, соль WinZip AES в pyzipper, многочлен Шамира
в pycryptodomex) на время генерации подменяется потоком SHA-256 от постоянной метки. Повторный запуск даёт те же байты;
`tests/test_vectors.py` это проверяет. Внутренние члены ZIP в векторе хранятся без сжатия (STORED), чтобы байты не
зависели от версии zlib (Rent сжимает их DEFLATE — читатель обязан понимать оба метода).

Запуск: `python scripts/gen_vectors.py [--rent ПУТЬ] [--out ПАПКА_spec]`. Путь к Rent — `--rent`, переменная
`HOMENSAI_RENT_PATH` или соседняя папка `../Homensai-Rent`.
"""

from __future__ import annotations

import argparse
import base64
import contextlib
import hashlib
import io
import json
import os
from pathlib import Path
import sys
import tempfile
from typing import Any
from unittest import mock
import zipfile

ROOT = Path(__file__).resolve().parents[1]
SEED = b"homensai-security/test-vectors/1\x00"
AUTHOR = "HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI"
NOTE = "Тест-вектор. Все пароли, ключи и данные вымышленные; в работе не использовать."
FIELD_KEY_TEXT = "TEST-VECTOR-ONLY-field-key-0123456789-abcdefghijklmn"  # вымышленный ключ полей (не рабочий)
VECTOR_VERSION = "0.0.0-vector"
WHEN = (2026, 1, 15, 3, 0, 0)


def rent_root(explicit: str | None = None) -> Path:
    """Папка исходников Rent: аргумент, `HOMENSAI_RENT_PATH` или соседняя `../Homensai-Rent`."""
    for candidate in (explicit, os.environ.get("HOMENSAI_RENT_PATH"), str(ROOT.parent / "Homensai-Rent")):
        if candidate and (Path(candidate) / "app" / "archive" / "keys.py").is_file():
            return Path(candidate).resolve()
    raise SystemExit("Не найден код Rent: укажите --rent или HOMENSAI_RENT_PATH")


class Drbg:
    """Детерминированный поток байт: SHA-256(SEED ‖ метка ‖ счётчик). Только для векторов."""

    def __init__(self, label: str) -> None:
        self.label = label.encode("utf-8")
        self.counter = 0
        self.issued: list[bytes] = []

    def read(self, size: int) -> bytes:
        out = b""
        while len(out) < size:
            out += hashlib.sha256(SEED + self.label + b"\x00" + self.counter.to_bytes(8, "big")).digest()
            self.counter += 1
        self.issued.append(out[:size])
        return out[:size]

    # интерфейс модуля `secrets`, который использует Rent
    def token_bytes(self, size: int = 32) -> bytes:
        return self.read(size)

    def choice(self, seq: Any) -> Any:  # pragma: no cover — Rent в векторах choice не вызывает
        return seq[self.read(1)[0] % len(seq)]


def b64u(data: bytes) -> str:
    return base64.urlsafe_b64encode(data).decode("ascii")


def b64(data: bytes) -> str:
    return base64.b64encode(data).decode("ascii")


class Generator:
    """Считает все вектора кодом Rent; каждую подмену случайности включает только на время одного вызова."""

    def __init__(self, rent: Path) -> None:
        sys.path.insert(0, str(rent))
        os.environ["HOMENSAI_RENT_DEV_KEY"] = FIELD_KEY_TEXT
        from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey
        import Cryptodome.Protocol.SecretSharing as secret_sharing
        import pyzipper
        import pyzipper.zipfile_aes as zipfile_aes

        from app.archive import chain, keys, pack
        from app.archive import domain as archive_domain
        from app.errorbook import public_api as errorbook
        from app.platform import sealing
        from app.security import codes, integrity, kdf, recovery, shamir, webauthn

        self.X25519PrivateKey = X25519PrivateKey
        self.secret_sharing, self.pyzipper, self.zipfile_aes = secret_sharing, pyzipper, zipfile_aes
        self.chain, self.keys, self.pack, self.archive_domain = chain, keys, pack, archive_domain
        self.errorbook, self.sealing = errorbook, sealing
        self.codes, self.integrity, self.kdf, self.recovery, self.shamir, self.webauthn = codes, integrity, kdf, recovery, shamir, webauthn

    # --- подмена случайности ---------------------------------------------------------------------------------------

    @contextlib.contextmanager
    def fixed(self, label: str):  # type: ignore[no-untyped-def]
        drbg = Drbg(label)
        real = self.X25519PrivateKey
        generated: list[bytes] = []

        class X25519Shim:
            @staticmethod
            def generate() -> Any:
                raw = drbg.read(32)
                generated.append(raw)
                return real.from_private_bytes(raw)

            from_private_bytes = staticmethod(real.from_private_bytes)

        class RandomShim:
            @staticmethod
            def new() -> Drbg:
                return drbg

        patches = [
            mock.patch.object(self.keys, "secrets", drbg),
            mock.patch.object(self.keys, "X25519PrivateKey", X25519Shim),
            mock.patch.object(self.recovery, "secrets", drbg),
            mock.patch.object(self.recovery, "X25519PrivateKey", X25519Shim),
            mock.patch.object(self.sealing, "secrets", drbg),
            mock.patch.object(self.kdf, "secrets", drbg),
            mock.patch.object(self.codes, "secrets", drbg),
            mock.patch.object(self.secret_sharing, "rng", drbg.read),
            mock.patch.object(self.zipfile_aes, "Random", RandomShim),
        ]
        with contextlib.ExitStack() as stack:
            for patch in patches:
                stack.enter_context(patch)
            drbg.generated = generated  # type: ignore[attr-defined]
            yield drbg

    def error_code(self, call: Any) -> str:
        """Код ошибки Rent (`ArchiveError`/`SecurityError`.code) или `ValueError` для полей; успех — исключение генератора."""
        try:
            call()
        except (self.archive_domain.ArchiveError, self.errorbook_security_error()) as exc:
            return str(exc.code)
        except ValueError:
            return "value_error"
        raise AssertionError("ожидалась ошибка")

    def errorbook_security_error(self) -> type[Exception]:
        from app.security.errors import SecurityError

        return SecurityError

    # --- Argon2id ----------------------------------------------------------------------------------------------------

    def argon2id(self) -> dict[str, Any]:
        keys, kdf = self.keys, self.kdf
        cases = []
        for name, password, params in (
            ("copies-password", "Пример-пароль-копий-2026", keys.KDF_PASSWORD),
            ("copies-pin", "4826", keys.KDF_PIN),
        ):
            salt = Drbg(f"argon2id/{name}").read(16)
            derived = keys._derive(password.encode("utf-8"), salt, params["m"], params["t"], params["p"])
            cases.append({"name": name, "password": password, "salt_hex": salt.hex(), **params, "length": 32, "key_hex": derived.hex()})
        phc = []
        for name, password, also in (
            ("phc-ascii", "Fictional-login-pass-01", None),
            ("phc-nfkc", "Ｐａｓｓ-Пример-①", "Pass-Пример-1"),  # полноширинные знаки и «①» → NFKC
        ):
            with self.fixed(f"argon2id/{name}"):
                stored = kdf.hash_secret(password)
            assert kdf.verify_secret(password, stored)
            case = {"name": name, "password": password, "phc": stored, "verify": True}
            if also is not None:
                assert kdf.verify_secret(also, stored)
                case["equivalent_password"] = also
            phc.append(case)
        return {"raw": cases, "phc": phc, "limits": {k: list(v) for k, v in keys.KDF_LIMITS.items()}}

    # --- закрытый ключ хозяйства под паролем ---------------------------------------------------------------------------

    def identity(self, name: str, password: str, *, pin: bool) -> dict[str, Any]:
        keys = self.keys
        raw = Drbg(f"identity/{name}/raw").read(32)
        with self.fixed(f"identity/{name}/wrap"):
            public, fingerprint, wrapped = keys.wrap_identity(raw, password, pin=pin)
        assert keys.unwrap_identity(wrapped, password, public=public) == raw
        wrong = self.error_code(lambda: keys.unwrap_identity(wrapped, password + "x", public=public))
        return {
            "name": name, "mode": "pin" if pin else "password", "password": password, "private_hex": raw.hex(),
            "public": public, "fingerprint": fingerprint, "wrapped": wrapped,
            "errors": [{"password": password + "x", "code": wrong}],
        }

    # --- ключ восстановления, части Шамира, PRF -------------------------------------------------------------------------

    def recovery_vectors(self) -> dict[str, Any]:
        codes, recovery, shamir, webauthn = self.codes, self.recovery, self.shamir, self.webauthn
        key = Drbg("recovery/key").read(16)
        text = codes.format_key(key)
        assert codes.parse_key(text) == key and codes.parse_key(text.lower().replace("-", " ")) == key
        public = recovery.public_of(key)
        typo = self._typo(text, codes.parse_key)
        with self.fixed("recovery/shamir"):
            shares = list(shamir.split(key))
        found = codes.find_shares("\n".join(shares))
        pairs = []
        for i, j in ((0, 1), (0, 2), (1, 2)):
            assert shamir.combine([shares[i], shares[j]]) == key
            pairs.append([i + 1, j + 1])
        assert shamir.combine(shares) == key
        one = self.error_code(lambda: shamir.combine([shares[0]]))
        prf = Drbg("recovery/prf").read(32)
        prf_key = webauthn.prf_recovery_secret(prf)
        return {
            "key": {
                "key_hex": key.hex(), "text": text, "checksum_hex": codes.key_checksum(key).hex(),
                "recipient_public": public, "recovery_id": recovery.recovery_id(public),
                "errors": [{"text": typo, "code": self.error_code(lambda: codes.parse_key(typo))},
                           {"text": "RK1-ABCDE", "code": self.error_code(lambda: codes.parse_key("RK1-ABCDE"))}],
            },
            "shamir": {
                "key_hex": key.hex(), "threshold": shamir.THRESHOLD, "parts": shamir.PARTS,
                "set_label_hex": found[0][1].hex(),
                "shares": [{"index": index, "share_hex": share.hex(), "text": shares[index - 1]} for index, _tag, share in found],
                "combine_pairs": pairs,
                "errors": [{"texts": [shares[0]], "code": one}],
            },
            "prf": {"prf_output_hex": prf.hex(), "info": webauthn.PRF_INFO.decode("ascii"), "recovery_key_hex": prf_key.hex(),
                    "recovery_key_text": codes.format_key(prf_key)},
        }

    @staticmethod
    def _typo(text: str, parse: Any) -> str:
        """Запись с одной заменённой буквой, которую ловит контрольная сумма (а не формат)."""
        from app.security.codes import ALPHABET
        from app.security.errors import SecurityError

        for position in range(len(text) - 1, 3, -1):
            if text[position] == "-":
                continue
            for ch in ALPHABET:
                if ch == text[position]:
                    continue
                candidate = text[:position] + ch + text[position + 1 :]
                try:
                    parse(candidate)
                except SecurityError as exc:
                    if exc.code == "recovery_checksum":
                        return candidate
        raise AssertionError("не нашлась опечатка")

    # --- конверт ключа копии ----------------------------------------------------------------------------------------------

    def envelope(self, ident: dict[str, Any], rec: dict[str, Any]) -> dict[str, Any]:
        keys, recovery = self.keys, self.recovery
        raw = bytes.fromhex(ident["private_hex"])
        rpk = rec["key"]["recipient_public"]
        with self.fixed("envelope/recovery-seal") as drbg:
            sealed = keys.seal_identity(raw, rpk)
            recovery_ephemeral = drbg.generated[0]  # type: ignore[attr-defined]
        entry = {"id": recovery.recovery_id(rpk), "sealed": sealed}
        with self.fixed("envelope/seal") as drbg:
            secret, comment = keys.seal("custom", ident["public"], ident["wrapped"], [entry])
            ephemeral = drbg.generated[0]  # type: ignore[attr-defined]
        envelope = keys.envelope_from_comment(comment)
        assert envelope is not None
        password = ident["password"].encode("utf-8")
        assert keys.open_password(envelope, password) == secret
        assert keys.open_password(envelope, rec["key"]["text"].encode("ascii")) == secret
        two = " ".join(s["text"] for s in rec["shamir"]["shares"][1:]).encode("ascii")
        assert keys.open_password(envelope, two) == secret
        other = self.codes.format_key(Drbg("envelope/other-key").read(16))
        none_comment = keys.open_comment()
        return {
            "prefix": keys.ENVELOPE_PREFIX.decode("ascii"),
            "keyed": {
                "comment": comment.decode("ascii"), "secret": secret.decode("ascii"), "identity": ident["name"],
                "ephemeral_private_hex": ephemeral.hex(), "recovery_ephemeral_private_hex": recovery_ephemeral.hex(),
                "open": [
                    {"by": "password", "input": ident["password"], "secret": secret.decode("ascii")},
                    {"by": "recovery_key", "input": rec["key"]["text"], "secret": secret.decode("ascii")},
                    {"by": "shamir_shares", "input": two.decode("ascii"), "secret": secret.decode("ascii")},
                ],
                "errors": [
                    {"input": ident["password"] + "x", "code": self.error_code(lambda: keys.open_password(envelope, password + b"x"))},
                    {"input": other, "code": self.error_code(lambda: keys.open_password(envelope, other.encode("ascii")))},
                    {"input": "", "code": self.error_code(lambda: keys.open_password(envelope, b""))},
                ],
            },
            "none": {"comment": none_comment.decode("ascii")},
        }

    # --- файл копии ---------------------------------------------------------------------------------------------------------

    def _inner(self, files: list[tuple[str, str, bytes]], on: str) -> tuple[bytes, dict[str, Any]]:
        domain = self.archive_domain
        manifest = {
            "format": domain.FORMAT,
            "created_at": "2026-01-15T03:00:00Z",
            "on": on,
            "rent_version": VECTOR_VERSION,
            "warnings": [],
            "file_scope": "registered attachments; invoices within selected months; no keys or unregistered files",
            "invoice_months": [],
            "applied_migrations": [],
            "content_fingerprint": {"counts": {}, "payments_minor": {}, "audit_last": None},
            "files": [{"path": name, "kind": kind, "size": len(data), "sha256": hashlib.sha256(data).hexdigest()} for name, kind, data in files],
        }
        entries = [(name, data) for name, _kind, data in files]
        entries.append((domain.INNER_MANIFEST, json.dumps(manifest, ensure_ascii=False, indent=1).encode("utf-8")))
        buffer = io.BytesIO()
        with zipfile.ZipFile(buffer, "w") as zf:
            for name, data in entries:
                info = zipfile.ZipInfo(name, date_time=WHEN)
                info.compress_type = zipfile.ZIP_STORED
                zf.writestr(info, data)
        return buffer.getvalue(), manifest

    def _outer(self, inner: bytes, password: bytes | None, comment: bytes, label: str) -> bytes:
        pyzipper, domain = self.pyzipper, self.archive_domain
        buffer = io.BytesIO()
        if password is None:
            with zipfile.ZipFile(buffer, "w") as plain:
                plain.comment = comment
                info = zipfile.ZipInfo(domain.OUTER_MEMBER, date_time=WHEN)
                info.compress_type = zipfile.ZIP_STORED
                plain.writestr(info, inner)
            return buffer.getvalue()
        with self.fixed(label), pyzipper.AESZipFile(buffer, "w", compression=pyzipper.ZIP_STORED, encryption=pyzipper.WZ_AES) as zf:
            zf.setpassword(password)
            zf.setencryption(pyzipper.WZ_AES, nbits=256)
            if comment:
                zf.comment = comment
            info = zf.zipinfo_cls(domain.OUTER_MEMBER, date_time=WHEN)
            info.compress_type = pyzipper.ZIP_STORED
            zf.writestr(info, inner)
        return buffer.getvalue()

    def archives(self, env: dict[str, Any], ident: dict[str, Any], rec: dict[str, Any]) -> dict[str, Any]:
        domain, pack = self.archive_domain, self.pack
        on = "2026-01-15"
        files = [
            ("Export/HomensaiRent_Export_2026-01-15.xlsx", "excel", "Вымышленная выгрузка: не настоящий файл xlsx\n".encode()),
            (domain.INNER_DB, "database", b"Fictional database bytes for the test vector (not SQLite)\n"),
        ]
        inner, manifest = self._inner(files, on)
        keyed_secret = env["keyed"]["secret"].encode("ascii")
        legacy_password = "Пример-BACKUP-пароль-2026!"
        cases = []
        for name, password, comment, open_with, mode in (
            ("keyed-custom", keyed_secret, env["keyed"]["comment"].encode("ascii"), ident["password"], "custom"),
            ("legacy-env", legacy_password.encode("utf-8"), b"", legacy_password, "env"),
            ("open-none", None, env["none"]["comment"].encode("ascii"), None, "none"),
        ):
            data = self._outer(inner, password, comment, f"archive/{name}")
            case: dict[str, Any] = {
                "name": name, "mode": mode, "file_name": domain.archive_filename(__import__("datetime").date(2026, 1, 15)),
                "file_b64": b64(data), "file_sha256": hashlib.sha256(data).hexdigest(), "size": len(data),
                "open_with": open_with, "zip_password": None if password is None else password.decode("utf-8"),
                "inner_sha256": hashlib.sha256(inner).hexdigest(), "manifest": manifest, "check_db": False, "errors": [],
            }
            with tempfile.TemporaryDirectory() as tmp:
                path = Path(tmp) / case["file_name"]
                path.write_bytes(data)
                given = None if open_with is None else open_with.encode("utf-8")
                with pack.open_archive(path, given, check_db=False) as opened:
                    assert opened.manifest == manifest
                    assert sorted(opened.names) == sorted([*(f[0] for f in files), domain.INNER_MANIFEST])
                if open_with is not None:
                    bad = (open_with + "x").encode("utf-8")
                    case["errors"].append({"input": open_with + "x", "code": self.error_code(lambda: pack.open_archive(path, bad, check_db=False))})
                broken = bytearray(data)
                at = data.index(domain.OUTER_MEMBER.encode()) + len(domain.OUTER_MEMBER) + 11 + 40  # внутри данных члена
                broken[at] ^= 0x01
                path.write_bytes(bytes(broken))
                case["errors"].append({"flip_byte_at": at, "input": open_with,
                                       "code": self.error_code(lambda: pack.open_archive(path, given, check_db=False))})
            cases.append(case)
        return {"cases": cases}

    # --- шифрование полей ---------------------------------------------------------------------------------------------

    def fields(self) -> dict[str, Any]:
        sealing = self.sealing
        base = FIELD_KEY_TEXT.encode("utf-8")
        context = sealing.FieldContext("acc-test-0001", "persons", "rnokpp_enc", 7)
        cases = []
        for name, plaintext, field in (
            ("person-rnokpp", "0000000001", context),
            ("phone-utf8", "+380 00 000-00-01 (Иванов Иван)", sealing.FieldContext("acc-test-0001", "person_contacts", "value_enc", "c-12")),
            ("no-context", "служебное значение", None),
        ):
            with self.fixed(f"field/{name}"):
                blob = sealing.seal(plaintext, field)
            assert sealing.open_v1(blob, base, field) == plaintext
            ctx = None if field is None else {"account_id": field.account_id, "table": field.table, "column": field.column, "row_id": str(field.row_id)}
            cases.append({"name": name, "plaintext": plaintext, "context": ctx, "aad_hex": sealing._aad(field).hex(), "blob_hex": blob.hex()})
        other = sealing.FieldContext("acc-test-0001", "persons", "rnokpp_enc", 8)
        first = bytes.fromhex(cases[0]["blob_hex"])
        wrong = self.error_code(lambda: sealing.open_v1(first, base, other))
        with self.fixed("field/v0"):
            legacy = sealing.seal_v0("0000000001", context)
        assert sealing.unseal(legacy, context) == "0000000001"
        return {
            "base_key_text": FIELD_KEY_TEXT,
            "hkdf_salt": "homensai-rent/v1",
            "gcm_key_hex": sealing._derive(base, b"gcm").hex(),
            "cases": cases,
            "errors": [{"case": "person-rnokpp", "context": {**cases[0]["context"], "row_id": "8"}, "code": wrong}],
            "blind_index": [
                {"normalized": "0000000001", "context": {"account_id": "acc-test-0001", "table": "persons", "column": "rnokpp_enc"},
                 "index": sealing.blind_index("0000000001", context)},
            ],
            "key_check": {"kcv_hex": sealing.key_check_value(), "fingerprint": sealing.key_fingerprint()},
            "legacy_v0stub": {"plaintext": "0000000001", "blob_hex": legacy.hex(), "read_only": True},
        }

    # --- цепочка копий и журнал -------------------------------------------------------------------------------------

    def chain_vectors(self, archive: dict[str, Any], ident: dict[str, Any]) -> dict[str, Any]:
        from cryptography.hazmat.primitives import serialization
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

        chain, integrity = self.chain, self.integrity
        seed = Drbg("chain/signing-key").read(32)
        private = Ed25519PrivateKey.from_private_bytes(seed)
        public = private.public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
        signer = chain.fingerprint_of(public)
        journal = []
        prev = integrity.ZERO
        for seq, payload in ((1, {"kind": "snapshot", "note": "вымышленная запись 1"}), (2, {"kind": "tx", "tables": ["units"]})):
            digest = integrity.link(prev, payload)
            journal.append({"seq": seq, "prev": prev, "payload": payload, "hash": digest})
            prev = digest
        assert not integrity.verify_chain([integrity_entry(integrity, e) for e in journal])
        keyed = archive["cases"][0]
        manifests = []
        prev = chain.ZERO
        for seq, created in ((1, "2026-01-15T03:00:00Z"), (2, "2026-01-16T03:00:00Z")):
            body: dict[str, Any] = {
                "format": chain.FORMAT, "seq": seq, "created_at": created, "archive": keyed["file_name"],
                "path": f"2026/01/{keyed['file_name']}", "sha256": keyed["file_sha256"], "size": keyed["size"],
                "prev": prev, "start": seq == 1, "media": ["external", "internal"], "rent_version": VECTOR_VERSION,
                "schema": "migrations:0", "encryption": {"mode": "custom", "kid": ident["fingerprint"]}, "signer": signer,
            }
            if seq == 2:
                body["integrity"] = {"journal_seq": journal[-1]["seq"], "journal_hash": journal[-1]["hash"]}
            signature = private.sign(chain.canonical(body).encode("utf-8"))
            text = chain.canonical({"manifest": body, "signature": b64u(signature)})
            parsed = chain._parse(text)
            assert parsed is not None and parsed[0] == body
            digest = chain.sha256_text(text)
            manifests.append({"file": chain.manifest_name(seq), "text": text, "manifest_sha256": digest, "signature_b64url": b64u(signature)})
            prev = digest
        tampered = json.loads(manifests[0]["text"])
        tampered["manifest"]["size"] += 1
        return {
            "signing_seed_hex": seed.hex(), "public_b64url": b64u(public), "signer": signer,
            "key_file_linux": f"{chain.KEY_MAGIC.decode('ascii')} raw {b64u(seed)}",
            "manifests": manifests,
            "tampered": {"text": chain.canonical(tampered), "signature_valid": False},
            "journal": journal,
        }

    # --- коды ошибок ------------------------------------------------------------------------------------------------------

    def error_codes(self) -> dict[str, Any]:
        wanted_places = ("backup", "restore", "recovery", "chain")
        extra = ("kdf_params",)
        found = []
        for entry in self.errorbook.catalog():
            if entry.where in wanted_places or entry.code in extra:
                found.append({"code": entry.code, "level": entry.level, "area": entry.area, "where": entry.where,
                              "title": {"ru": entry.title.get("ru", ""), "uk": entry.title.get("uk", "")}})
        return {
            "$comment": AUTHOR,
            "description": "Коды ошибок копий, восстановления, ключей восстановления и цепочки копий. Выписка из справочника "
                           "ошибок Rent (app/errorbook: data_archive.py, data_security.py). Полные тексты «Что делать» RU/UK — "
                           "там же; единый справочник модуля — пункт MOD.errors-help.",
            "source": "HomenSAI/Homensai-Rent app/errorbook/public_api.py catalog()",
            "codes": found,
        }

    def all(self) -> dict[str, dict[str, Any]]:
        ident = self.identity("custom-password", "Пример-пароль-копий-2026", pin=False)
        ident_pin = self.identity("pin", "4826", pin=True)
        rec = self.recovery_vectors()
        env = self.envelope(ident, rec)
        archive = self.archives(env, ident, rec)
        return {
            "argon2id": self.argon2id(),
            "identity": {"cases": [ident, ident_pin]},
            "recovery": rec,
            "envelope": env,
            "archive": archive,
            "field-aead": self.fields(),
            "chain": self.chain_vectors(archive, ident),
        }


def integrity_entry(integrity: Any, item: dict[str, Any]) -> Any:
    return integrity.Entry(item["seq"], item["prev"], item["payload"], item["hash"])


def dump(value: Any) -> str:
    return json.dumps(value, ensure_ascii=False, indent=1, sort_keys=False) + "\n"


def generate(rent: Path, out: Path) -> list[Path]:
    """Пишет `out/vectors/*.json` и `out/error-codes.json`; возвращает записанные файлы."""
    gen = Generator(rent)
    written = []
    (out / "vectors").mkdir(parents=True, exist_ok=True)
    for name, body in gen.all().items():
        path = out / "vectors" / f"{name}.json"
        path.write_text(dump({"$comment": AUTHOR, "note": NOTE, "spec": "spec/README.md", **body}), encoding="utf-8")
        written.append(path)
    path = out / "error-codes.json"
    path.write_text(dump(gen.error_codes()), encoding="utf-8")
    written.append(path)
    return written


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--rent", help="папка исходников Homensai-Rent")
    parser.add_argument("--out", default=str(ROOT / "spec"), help="папка spec (по умолчанию spec/ модуля)")
    args = parser.parse_args()
    for path in generate(rent_root(args.rent), Path(args.out)):
        print(path)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

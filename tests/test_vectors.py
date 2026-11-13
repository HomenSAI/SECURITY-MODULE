# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Проверка тест-векторов спецификации (`spec/vectors/*.json`).

Три слоя:
1. Независимая проверка по `spec/*.md` — только примитивы (pyca/cryptography, для AES-CTR WinZip — свой счётчик поверх
   AES-ECB) и свой разбор форматов: поле GF(2^128) Шамира, Crockford Base32, WinZip AE-2, канонический JSON. Rent не нужен.
2. Сверка с кодом Rent (если найден: `HOMENSAI_RENT_PATH` или соседняя `../Homensai-Rent`): те же вектора открывает и
   отвергает код продукта, коды ошибок совпадают.
3. Детерминизм: `scripts/gen_vectors.py` с тем же Rent даёт байт в байт те же файлы векторов.
JSON-схемы (`spec/schemas`) проверяются пакетом jsonschema, если он установлен.
"""

from __future__ import annotations

import base64
import hashlib
import hmac
import io
import json
import os
from pathlib import Path
import struct
import subprocess
import sys
from typing import Any
import unicodedata
import zipfile

from cryptography.exceptions import InvalidSignature, InvalidTag
from cryptography.hazmat.primitives import hashes, serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey
from cryptography.hazmat.primitives.asymmetric.x25519 import X25519PrivateKey, X25519PublicKey
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.ciphers.aead import AESGCM, ChaCha20Poly1305
from cryptography.hazmat.primitives.kdf.argon2 import Argon2id
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.kdf.pbkdf2 import PBKDF2HMAC
import pytest

ROOT = Path(__file__).resolve().parents[1]
SPEC = ROOT / "spec"
VECTORS = SPEC / "vectors"


def load(name: str) -> dict[str, Any]:
    return json.loads((VECTORS / f"{name}.json").read_text(encoding="utf-8"))


def unb64u(text: str) -> bytes:
    return base64.urlsafe_b64decode(text.encode("ascii"))


def hkdf(ikm: bytes, *, salt: bytes | None, info: bytes, length: int = 32) -> bytes:
    return HKDF(algorithm=hashes.SHA256(), length=length, salt=salt, info=info).derive(ikm)


def x25519_public(raw: bytes) -> bytes:
    return X25519PrivateKey.from_private_bytes(raw).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)


def grouped(prefix: str, digest_hex: str, groups: int) -> str:
    text = digest_hex[: groups * 4].upper()
    return prefix + "-".join(text[i : i + 4] for i in range(0, len(text), 4))


# --- Crockford Base32 (spec/key-envelope.md, «Запись ключа восстановления») ---------------------------------------------

CROCKFORD = "0123456789ABCDEFGHJKMNPQRSTVWXYZ"


def crockford(data: bytes, chars: int) -> str:
    bits = int.from_bytes(data, "big") << (chars * 5 - len(data) * 8)
    return "".join(CROCKFORD[(bits >> (5 * (chars - 1 - i))) & 31] for i in range(chars))


def uncrockford(text: str, size: int) -> bytes:
    bits = 0
    for ch in text:
        bits = (bits << 5) | CROCKFORD.index(ch)
    spare = len(text) * 5 - size * 8
    assert spare >= 0 and bits & ((1 << spare) - 1) == 0
    return (bits >> spare).to_bytes(size, "big")


def normalize_code(text: str) -> str:
    flat = "".join(ch for ch in text.upper() if ch not in " \t\r\n-_.,;:")
    return flat.translate(str.maketrans({"O": "0", "I": "1", "L": "1"}))


def key_text(key: bytes) -> str:
    body = crockford(key + hashlib.sha256(b"homensai-security/rk/1" + key).digest()[:2], 30)
    return "RK1-" + "-".join(body[i : i + 5] for i in range(0, 30, 5))


def parse_key_text(text: str) -> bytes | None:
    flat = normalize_code(text)
    if not flat.startswith("RK1") or len(flat) != 33:
        return None
    raw = uncrockford(flat[3:], 18)
    return raw[:16] if hashlib.sha256(b"homensai-security/rk/1" + raw[:16]).digest()[:2] == raw[16:] else None


def parse_share_text(text: str) -> tuple[int, bytes, bytes]:
    flat = normalize_code(text)
    assert flat.startswith("RS1") and len(flat) == 3 + 1 + 35
    index = int(flat[3])
    raw = uncrockford(flat[4:], 21)
    payload, checksum = raw[:19], raw[19:]
    assert hashlib.sha256(b"homensai-security/rs/1" + payload).digest()[:2] == checksum
    assert payload[0] == index
    return index, payload[1:3], payload[3:]


# --- GF(2^128) Шамира (x^128 + x^7 + x^2 + x + 1, целое из байт big-endian) -------------------------------------------

POLY = (1 << 128) | 0x87


def gf_mul(a: int, b: int) -> int:
    z = 0
    while b:
        if b & 1:
            z ^= a
        b >>= 1
        a <<= 1
        if a >> 128:
            a ^= POLY
    return z


def gf_inv(a: int) -> int:
    result, power, exponent = 1, a, (1 << 128) - 2  # a^(2^128 - 2)
    while exponent:
        if exponent & 1:
            result = gf_mul(result, power)
        power = gf_mul(power, power)
        exponent >>= 1
    return result


def shamir_combine_two(first: tuple[int, bytes], second: tuple[int, bytes]) -> bytes:
    """f(0) по двум точкам многочлена степени 1: (y1·x2 + y2·x1) / (x1 + x2); сложение в поле — XOR."""
    (x1, y1), (x2, y2) = (first[0], int.from_bytes(first[1], "big")), (second[0], int.from_bytes(second[1], "big"))
    return gf_mul(gf_mul(y1, x2) ^ gf_mul(y2, x1), gf_inv(x1 ^ x2)).to_bytes(16, "big")


# --- 1. независимая проверка -------------------------------------------------------------------------------------------


def test_argon2id_raw_and_phc() -> None:
    data = load("argon2id")
    for case in data["raw"]:
        key = Argon2id(salt=bytes.fromhex(case["salt_hex"]), length=case["length"], iterations=case["t"], lanes=case["p"],
                       memory_cost=case["m"]).derive(case["password"].encode("utf-8"))
        assert key.hex() == case["key_hex"], case["name"]
    for case in data["phc"]:
        _, name, version, params, salt, digest = case["phc"].split("$")
        assert (name, version) == ("argon2id", "v=19")
        values = dict(item.split("=") for item in params.split(","))
        pad = lambda s: s + "=" * (-len(s) % 4)  # noqa: E731
        expected = base64.b64decode(pad(digest))
        for password in (case["password"], case.get("equivalent_password", case["password"])):
            got = Argon2id(salt=base64.b64decode(pad(salt)), length=len(expected), iterations=int(values["t"]),
                           lanes=int(values["p"]), memory_cost=int(values["m"])).derive(unicodedata.normalize("NFKC", password).encode("utf-8"))
            assert hmac.compare_digest(got, expected), case["name"]


def unwrap(wrapped: dict[str, Any], password: str, public: bytes) -> bytes:
    key = Argon2id(salt=unb64u(wrapped["salt"]), length=32, iterations=wrapped["t"], lanes=wrapped["p"],
                   memory_cost=wrapped["m"]).derive(password.encode("utf-8"))
    return ChaCha20Poly1305(key).decrypt(unb64u(wrapped["nonce"]), unb64u(wrapped["ct"]), b"homensai-rent/archive-identity/1" + public)


def test_identity_wrap() -> None:
    for case in load("identity")["cases"]:
        public = unb64u(case["public"])
        raw = bytes.fromhex(case["private_hex"])
        assert x25519_public(raw) == public
        assert grouped("HR1-", hashlib.sha256(b"homensai-rent/archive-key\x00" + public).hexdigest(), 4) == case["fingerprint"]
        assert unwrap(case["wrapped"], case["password"], public) == raw
        with pytest.raises(InvalidTag):
            unwrap(case["wrapped"], case["errors"][0]["password"], public)


def test_recovery_key_shares_and_prf() -> None:
    data = load("recovery")
    key = bytes.fromhex(data["key"]["key_hex"])
    assert key_text(key) == data["key"]["text"]
    assert parse_key_text(data["key"]["text"].lower()) == key
    assert parse_key_text(data["key"]["errors"][0]["text"]) is None  # опечатка — контрольная сумма
    seed = hkdf(key, salt=None, info=b"homensai-security/recovery-key/1")
    rpk = x25519_public(seed)
    assert base64.urlsafe_b64encode(rpk).decode() == data["key"]["recipient_public"]
    digest = hashlib.sha256(b"homensai-security/recovery-id\x00" + rpk).hexdigest()[:8].upper()
    assert f"RK-{digest[:4]}-{digest[4:]}" == data["key"]["recovery_id"]
    shares = {}
    for share in data["shamir"]["shares"]:
        index, label, value = parse_share_text(share["text"])
        assert (index, label.hex(), value.hex()) == (share["index"], data["shamir"]["set_label_hex"], share["share_hex"])
        shares[index] = value
    for i, j in data["shamir"]["combine_pairs"]:
        assert shamir_combine_two((i, shares[i]), (j, shares[j])) == key
    prf = data["prf"]
    derived = hkdf(bytes.fromhex(prf["prf_output_hex"]), salt=None, info=prf["info"].encode("ascii"), length=16)
    assert derived.hex() == prf["recovery_key_hex"] and key_text(derived) == prf["recovery_key_text"]


def open_secret(envelope: dict[str, Any], private: bytes) -> bytes:
    pk, epk = unb64u(envelope["pub"]), unb64u(envelope["epk"])
    shared = X25519PrivateKey.from_private_bytes(private).exchange(X25519PublicKey.from_public_bytes(epk))
    key = hkdf(shared, salt=epk + pk, info=b"homensai-rent/archive-secret/1")
    return ChaCha20Poly1305(key).decrypt(unb64u(envelope["nonce"]), unb64u(envelope["ct"]), b"homensai-rent/archive-secret/1")


def private_by_recovery(envelope: dict[str, Any], key16: bytes) -> bytes:
    seed = hkdf(key16, salt=None, info=b"homensai-security/recovery-key/1")
    rpk = x25519_public(seed)
    pk = unb64u(envelope["pub"])
    for entry in envelope["recovery"]:
        sealed = entry["sealed"]
        if unb64u(sealed["rpk"]) != rpk:
            continue
        epk = unb64u(sealed["epk"])
        shared = X25519PrivateKey.from_private_bytes(seed).exchange(X25519PublicKey.from_public_bytes(epk))
        key = hkdf(shared, salt=epk + rpk, info=b"homensai-security/recovery-seal/1")
        raw = ChaCha20Poly1305(key).decrypt(unb64u(sealed["nonce"]), unb64u(sealed["ct"]), b"homensai-rent/archive-identity-recovery/1" + pk)
        assert x25519_public(raw) == pk
        return raw
    raise LookupError("recovery_wrong")


def parse_comment(comment: bytes) -> dict[str, Any] | None:
    if not comment.startswith(b"HRKEY1 ") or len(comment) > 65535:
        return None
    return json.loads(comment[7:].decode("ascii"))


def test_envelope_open_three_ways() -> None:
    data = load("envelope")
    identity = {c["name"]: c for c in load("identity")["cases"]}
    recovery = load("recovery")
    keyed = data["keyed"]
    envelope = parse_comment(keyed["comment"].encode("ascii"))
    assert envelope is not None and envelope["v"] == 1
    ident = identity[keyed["identity"]]
    assert envelope["kid"] == ident["fingerprint"] and envelope["pub"] == ident["public"] and envelope["wrapped"] == ident["wrapped"]
    # канонический вид: ключи по алфавиту, без пробелов, только ASCII
    assert keyed["comment"][7:] == json.dumps(envelope, separators=(",", ":"), sort_keys=True)
    # эфемерный ключ из вектора даёт тот же epk
    assert base64.urlsafe_b64encode(x25519_public(bytes.fromhex(keyed["ephemeral_private_hex"]))).decode() == envelope["epk"]
    secret = keyed["secret"].encode("ascii")
    assert len(base64.urlsafe_b64decode(secret)) == 32
    by_password = unwrap(envelope["wrapped"], keyed["open"][0]["input"], unb64u(envelope["pub"]))
    assert open_secret(envelope, by_password) == secret
    key16 = parse_key_text(keyed["open"][1]["input"])
    assert key16 is not None and open_secret(envelope, private_by_recovery(envelope, key16)) == secret
    parts = [parse_share_text(t) for t in keyed["open"][2]["input"].split()]
    combined = shamir_combine_two((parts[0][0], parts[0][2]), (parts[1][0], parts[1][2]))
    assert open_secret(envelope, private_by_recovery(envelope, combined)) == secret
    other = parse_key_text(keyed["errors"][1]["input"])
    assert other is not None
    with pytest.raises(LookupError):
        private_by_recovery(envelope, other)
    assert parse_comment(data["none"]["comment"].encode("ascii")) == {"v": 1, "mode": "none"}
    assert recovery["key"]["recovery_id"] == envelope["recovery"][0]["id"]


# --- WinZip AE-2 (spec/archive-format.md) ------------------------------------------------------------------------------


def aes_ctr_le(key: bytes, data: bytes) -> bytes:
    """AES-CTR WinZip: 128-битный счётчик little-endian, первый блок — 1."""
    ecb = Cipher(algorithms.AES(key), modes.ECB()).encryptor()
    out = bytearray()
    for block, start in enumerate(range(0, len(data), 16), start=1):
        stream = ecb.update(block.to_bytes(16, "little"))
        out += bytes(a ^ b for a, b in zip(data[start : start + 16], stream, strict=False))
    return bytes(out)


def ae2_member(archive: bytes, password: bytes | None) -> tuple[zipfile.ZipInfo, bytes]:
    """Единственный член внешнего ZIP; с паролем — расшифровка AE-2 по спецификации WinZip, без pyzipper."""
    zf = zipfile.ZipFile(io.BytesIO(archive))
    infos = zf.infolist()
    assert [i.filename for i in infos] == ["archive.zip"]
    info = infos[0]
    if password is None:
        assert info.flag_bits & 1 == 0 and info.compress_type == zipfile.ZIP_STORED
        return info, zf.read(info)
    assert info.flag_bits & 1 and info.compress_type == 99 and info.CRC == 0  # AE-2: CRC не пишется
    extra = info.extra
    found = None
    while extra:
        tag, size = struct.unpack("<HH", extra[:4])
        if tag == 0x9901:
            found = extra[4 : 4 + size]
        extra = extra[4 + size :]
    assert found is not None
    version, vendor, strength, method = struct.unpack("<H2sBH", found)
    assert (version, vendor, strength, method) == (2, b"AE", 3, 0)  # AE-2, AES-256, внутри STORED
    head = archive[info.header_offset : info.header_offset + 30]
    name_len, extra_len = struct.unpack("<HH", head[26:30])
    start = info.header_offset + 30 + name_len + extra_len
    body = archive[start : start + info.compress_size]
    salt, verifier, ciphertext, mac = body[:16], body[16:18], body[18:-10], body[-10:]
    material = PBKDF2HMAC(algorithm=hashes.SHA1(), length=66, salt=salt, iterations=1000).derive(password)  # noqa: S303 — формат WinZip
    enc_key, mac_key, check = material[:32], material[32:64], material[64:]
    if check != verifier:
        raise PermissionError("bad_password")
    if hmac.new(mac_key, ciphertext, hashlib.sha1).digest()[:10] != mac:
        raise ValueError("corrupt")
    return info, aes_ctr_le(enc_key, ciphertext)


def test_archive_files() -> None:
    data = load("archive")
    identity = {c["name"]: c for c in load("identity")["cases"]}
    for case in data["cases"]:
        archive = base64.b64decode(case["file_b64"])
        assert hashlib.sha256(archive).hexdigest() == case["file_sha256"] and len(archive) == case["size"]
        comment = zipfile.ZipFile(io.BytesIO(archive)).comment
        envelope = parse_comment(comment)
        if case["mode"] == "env":
            assert envelope is None and comment == b""
            password: bytes | None = case["open_with"].encode("utf-8")
        elif case["mode"] == "none":
            assert envelope == {"v": 1, "mode": "none"}
            password = None
        else:
            assert envelope is not None and envelope["mode"] == case["mode"]
            assert envelope["pub"] == identity["custom-password"]["public"]
            password = open_secret(envelope, unwrap(envelope["wrapped"], case["open_with"], unb64u(envelope["pub"])))
        assert (password.decode("utf-8") if password else None) == case["zip_password"]
        _, inner = ae2_member(archive, password)
        assert hashlib.sha256(inner).hexdigest() == case["inner_sha256"]
        with zipfile.ZipFile(io.BytesIO(inner)) as zf:
            manifest = json.loads(zf.read("manifest.json").decode("utf-8"))
            assert manifest == case["manifest"] and manifest["format"] == "homensai-rent-archive/1"
            assert sorted(zf.namelist()) == sorted([*(f["path"] for f in manifest["files"]), "manifest.json"])
            for entry in manifest["files"]:
                content = zf.read(entry["path"])
                assert hashlib.sha256(content).hexdigest() == entry["sha256"] and len(content) == entry["size"]
        if password is not None:
            with pytest.raises((PermissionError, ValueError)):
                ae2_member(archive, password + b"x")
        broken = bytearray(archive)
        broken[case["errors"][-1]["flip_byte_at"]] ^= 0x01
        with pytest.raises((ValueError, zipfile.BadZipFile)):  # с паролем — HMAC AE-2, без пароля — CRC члена
            ae2_member(bytes(broken), password)


def test_field_aead() -> None:
    data = load("field-aead")
    base = data["base_key_text"].encode("utf-8")
    salt = data["hkdf_salt"].encode("ascii")
    gcm_key = hkdf(base, salt=salt, info=b"gcm")
    assert gcm_key.hex() == data["gcm_key_hex"]
    for case in data["cases"]:
        ctx = case["context"]
        parts = ("", "", "", "") if ctx is None else (ctx["account_id"], ctx["table"], ctx["column"], ctx["row_id"])
        aad = b"homensai-rent/v1\x00" + "\x00".join(parts).encode("utf-8")
        assert aad.hex() == case["aad_hex"]
        blob = bytes.fromhex(case["blob_hex"])
        assert blob.startswith(b"v1gcm|")
        body = blob[6:]
        assert AESGCM(gcm_key).decrypt(body[:12], body[12:], aad).decode("utf-8") == case["plaintext"]
    wrong = data["errors"][0]["context"]
    body = bytes.fromhex(data["cases"][0]["blob_hex"])[6:]
    aad = b"homensai-rent/v1\x00" + "\x00".join((wrong["account_id"], wrong["table"], wrong["column"], wrong["row_id"])).encode()
    with pytest.raises(InvalidTag):
        AESGCM(gcm_key).decrypt(body[:12], body[12:], aad)
    for item in data["blind_index"]:
        ctx = item["context"]
        info = b"bidx2\x00" + "\x00".join((ctx["account_id"], ctx["table"], ctx["column"])).encode("utf-8")
        expected = "bi2:" + hmac.new(hkdf(base, salt=salt, info=info), item["normalized"].encode("utf-8"), hashlib.sha256).hexdigest()
        assert expected == item["index"]
    kcv = hmac.new(hkdf(base, salt=salt, info=b"kcv"), b"homensai-rent/kcv/v1", hashlib.sha256).hexdigest()
    assert kcv == data["key_check"]["kcv_hex"] and kcv[:8] == data["key_check"]["fingerprint"]
    legacy = bytes.fromhex(data["legacy_v0stub"]["blob_hex"])
    assert legacy.startswith(b"v0stub|")
    nonce, ct, tag = legacy[7:23], legacy[23:-32], legacy[-32:]
    enc = hmac.new(base, b"homensai-rent/enc", hashlib.sha256).digest()
    mac = hmac.new(base, b"homensai-rent/mac", hashlib.sha256).digest()
    assert hmac.compare_digest(tag, hmac.new(mac, nonce + ct, hashlib.sha256).digest())
    stream = b"".join(hmac.new(enc, nonce + i.to_bytes(8, "big"), hashlib.sha256).digest() for i in range(len(ct) // 32 + 1))
    assert bytes(a ^ b for a, b in zip(ct, stream, strict=False)).decode() == data["legacy_v0stub"]["plaintext"]


def canonical(value: object) -> str:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=False)


def test_chain_and_journal() -> None:
    data = load("chain")
    archive = load("archive")["cases"][0]
    seed = bytes.fromhex(data["signing_seed_hex"])
    public = Ed25519PrivateKey.from_private_bytes(seed).public_key().public_bytes(serialization.Encoding.Raw, serialization.PublicFormat.Raw)
    assert base64.urlsafe_b64encode(public).decode() == data["public_b64url"]
    assert grouped("HS1-", hashlib.sha256(b"homensai-rent/chain-key\x00" + public).hexdigest(), 4) == data["signer"]
    magic, kind, body = data["key_file_linux"].split(" ")
    assert (magic, kind, unb64u(body)) == ("HRSIGN1", "raw", seed)
    verifier = Ed25519PublicKey.from_public_bytes(public)
    prev = "0" * 64
    for seq, item in enumerate(data["manifests"], start=1):
        document = json.loads(item["text"])
        assert item["text"] == canonical(document) and item["file"] == f"{seq:06d}.json"
        manifest = document["manifest"]
        verifier.verify(unb64u(document["signature"]), canonical(manifest).encode("utf-8"))
        assert manifest["seq"] == seq and manifest["prev"] == prev and manifest["start"] == (seq == 1)
        assert manifest["sha256"] == archive["file_sha256"] and manifest["signer"] == data["signer"]
        assert hashlib.sha256(item["text"].encode("utf-8")).hexdigest() == item["manifest_sha256"]
        prev = item["manifest_sha256"]
    tampered = json.loads(data["tampered"]["text"])
    with pytest.raises(InvalidSignature):
        verifier.verify(unb64u(tampered["signature"]), canonical(tampered["manifest"]).encode("utf-8"))
    prev = "0" * 64
    for entry in data["journal"]:
        assert entry["prev"] == prev
        assert hashlib.sha256((prev + "\n" + canonical(entry["payload"])).encode("utf-8")).hexdigest() == entry["hash"]
        prev = entry["hash"]
    anchor = json.loads(data["manifests"][-1]["text"])["manifest"]["integrity"]
    assert anchor == {"journal_seq": data["journal"][-1]["seq"], "journal_hash": prev}


def test_error_codes_cover_vectors() -> None:
    known = {item["code"] for item in json.loads((SPEC / "error-codes.json").read_text(encoding="utf-8"))["codes"]}
    used: set[str] = set()

    def walk(value: object) -> None:
        if isinstance(value, dict):
            if isinstance(value.get("code"), str):
                used.add(value["code"])
            for item in value.values():
                walk(item)
        elif isinstance(value, list):
            for item in value:
                walk(item)

    for path in VECTORS.glob("*.json"):
        walk(json.loads(path.read_text(encoding="utf-8")))
    assert used - {"value_error"} <= known, used - known


def test_no_real_secrets_marker() -> None:
    """Каждый файл векторов помечен как вымышленный."""
    for path in VECTORS.glob("*.json"):
        assert "вымышленные" in json.loads(path.read_text(encoding="utf-8"))["note"], path.name


# --- JSON-схемы ---------------------------------------------------------------------------------------------------------


def test_schemas() -> None:
    jsonschema = pytest.importorskip("jsonschema")
    schemas = {p.name: json.loads(p.read_text(encoding="utf-8")) for p in (SPEC / "schemas").glob("*.schema.json")}
    assert set(schemas) == {"archive-manifest.schema.json", "key-envelope.schema.json", "chain-manifest.schema.json"}
    for schema in schemas.values():
        jsonschema.Draft202012Validator.check_schema(schema)
    check = lambda name, value: jsonschema.Draft202012Validator(schemas[name]).validate(value)  # noqa: E731
    for case in load("archive")["cases"]:
        check("archive-manifest.schema.json", case["manifest"])
    envelope = load("envelope")
    check("key-envelope.schema.json", json.loads(envelope["keyed"]["comment"][7:]))
    check("key-envelope.schema.json", json.loads(envelope["none"]["comment"][7:]))
    for item in load("chain")["manifests"]:
        check("chain-manifest.schema.json", json.loads(item["text"]))
    with pytest.raises(jsonschema.ValidationError):
        bad = json.loads(envelope["keyed"]["comment"][7:])
        bad["wrapped"]["m"] = 1024  # слабее OWASP
        check("key-envelope.schema.json", bad)


# --- 2. сверка с кодом Rent ----------------------------------------------------------------------------------------------


def rent_path() -> Path | None:
    for candidate in (os.environ.get("HOMENSAI_RENT_PATH"), str(ROOT.parent / "Homensai-Rent")):
        if candidate and (Path(candidate) / "app" / "archive" / "keys.py").is_file():
            return Path(candidate).resolve()
    return None


@pytest.fixture(scope="module")
def rent() -> Any:
    path = rent_path()
    if path is None:
        pytest.skip("код Rent не найден (HOMENSAI_RENT_PATH)")
    if str(path) not in sys.path:
        sys.path.insert(0, str(path))
    from app.archive import chain, keys, pack
    from app.archive.domain import ArchiveError
    from app.platform import sealing
    from app.security import codes, recovery, shamir
    from app.security.errors import SecurityError

    return type("Rent", (), {"chain": chain, "keys": keys, "pack": pack, "sealing": sealing, "codes": codes,
                             "recovery": recovery, "shamir": shamir, "ArchiveError": ArchiveError, "SecurityError": SecurityError})


def test_rent_opens_vectors(rent: Any, tmp_path: Path) -> None:
    for case in load("identity")["cases"]:
        assert rent.keys.unwrap_identity(case["wrapped"], case["password"], public=case["public"]).hex() == case["private_hex"]
        with pytest.raises(rent.ArchiveError) as err:
            rent.keys.unwrap_identity(case["wrapped"], case["errors"][0]["password"], public=case["public"])
        assert err.value.code == case["errors"][0]["code"]
    env = load("envelope")["keyed"]
    envelope = rent.keys.envelope_from_comment(env["comment"].encode("ascii"))
    for way in env["open"]:
        assert rent.keys.open_password(envelope, way["input"].encode("utf-8")).decode("ascii") == way["secret"]
    for bad in env["errors"]:
        with pytest.raises(rent.ArchiveError) as err:
            rent.keys.open_password(envelope, bad["input"].encode("utf-8"))
        assert err.value.code == bad["code"]
    rec = load("recovery")
    assert rent.codes.parse_key(rec["key"]["text"]).hex() == rec["key"]["key_hex"]
    for bad in rec["key"]["errors"]:
        with pytest.raises(rent.SecurityError) as err:
            rent.codes.parse_key(bad["text"])
        assert err.value.code == bad["code"]
    assert rent.recovery.public_of(bytes.fromhex(rec["key"]["key_hex"])) == rec["key"]["recipient_public"]
    assert rent.shamir.combine([s["text"] for s in rec["shamir"]["shares"]]).hex() == rec["key"]["key_hex"]
    for case in load("archive")["cases"]:
        path = tmp_path / case["file_name"]
        path.write_bytes(base64.b64decode(case["file_b64"]))
        given = None if case["open_with"] is None else case["open_with"].encode("utf-8")
        with rent.pack.open_archive(path, given, check_db=False) as opened:
            assert opened.manifest == case["manifest"]
        for bad in case["errors"]:
            data = bytearray(base64.b64decode(case["file_b64"]))
            if "flip_byte_at" in bad:
                data[bad["flip_byte_at"]] ^= 0x01
            path.write_bytes(bytes(data))
            attempt = None if bad["input"] is None else bad["input"].encode("utf-8")
            with pytest.raises(rent.ArchiveError) as err:
                rent.pack.open_archive(path, attempt, check_db=False)
            assert err.value.code == bad["code"], (case["name"], bad)
    fields = load("field-aead")
    base = fields["base_key_text"].encode("utf-8")
    for case in fields["cases"]:
        ctx = case["context"]
        field = None if ctx is None else rent.sealing.FieldContext(ctx["account_id"], ctx["table"], ctx["column"], ctx["row_id"])
        assert rent.sealing.open_v1(bytes.fromhex(case["blob_hex"]), base, field) == case["plaintext"]
    chain = load("chain")
    for item in chain["manifests"]:
        parsed = rent.chain._parse(item["text"])
        assert parsed is not None and rent.chain.sha256_text(item["text"]) == item["manifest_sha256"]
        assert rent.chain.canonical(parsed[0]) == canonical(parsed[0])


# --- 3. детерминизм ----------------------------------------------------------------------------------------------------


def test_generator_is_deterministic(tmp_path: Path) -> None:
    path = rent_path()
    if path is None:
        pytest.skip("код Rent не найден (HOMENSAI_RENT_PATH)")
    result = subprocess.run([sys.executable, str(ROOT / "scripts" / "gen_vectors.py"), "--rent", str(path), "--out", str(tmp_path)],
                            capture_output=True, text=True, timeout=600, check=False)
    assert result.returncode == 0, result.stderr[-2000:]
    for committed in VECTORS.glob("*.json"):
        assert (tmp_path / "vectors" / committed.name).read_bytes() == committed.read_bytes(), committed.name

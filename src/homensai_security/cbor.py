# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Разбор CBOR (RFC 8949) в объёме, нужном WebAuthn (28.10-282, 289): объект аттестации и ключ COSE.

Это разбор данных, а не криптография. Поддержано только то, что шлёт аутентификатор в каноническом виде CTAP2:
целые (типы 0 и 1), байтовые и текстовые строки (2, 3), массивы (4), словари (5), false/true/null (7). Неопределённая длина,
теги (6), числа с плавающей точкой, повтор ключа словаря и вложенность глубже 8 — отказ `webauthn_format`: подложенные данные
не заставят разбирать гигабайты или уходить в рекурсию. `decode` возвращает значение и число прочитанных байт — после ключа
COSE в authenticatorData могут идти расширения."""

from __future__ import annotations

from typing import Any

from homensai_security.errors import SecurityError

MAX_DEPTH = 8
MAX_ITEMS = 1024
MAX_LENGTH = 1 << 16


def _fail() -> SecurityError:
    return SecurityError("webauthn_format")


def _head(data: bytes, pos: int) -> tuple[int, int, int]:
    """(основной тип, аргумент, позиция после заголовка)."""
    if pos >= len(data):
        raise _fail()
    first = data[pos]
    major, info = first >> 5, first & 0x1F
    pos += 1
    if info < 24:
        return major, info, pos
    sizes = {24: 1, 25: 2, 26: 4, 27: 8}
    if info not in sizes:  # 28–30 зарезервированы, 31 — неопределённая длина
        raise _fail()
    size = sizes[info]
    if pos + size > len(data):
        raise _fail()
    return major, int.from_bytes(data[pos : pos + size], "big"), pos + size


def _item(data: bytes, pos: int, depth: int) -> tuple[Any, int]:
    if depth > MAX_DEPTH:
        raise _fail()
    major, arg, pos = _head(data, pos)
    if major == 0:
        return arg, pos
    if major == 1:
        return -1 - arg, pos
    if major in (2, 3):
        if arg > MAX_LENGTH or pos + arg > len(data):
            raise _fail()
        raw = data[pos : pos + arg]
        if major == 2:
            return bytes(raw), pos + arg
        try:
            return raw.decode("utf-8"), pos + arg
        except UnicodeDecodeError as exc:
            raise _fail() from exc
    if major == 4:
        if arg > MAX_ITEMS:
            raise _fail()
        items: list[Any] = []
        for _ in range(arg):
            value, pos = _item(data, pos, depth + 1)
            items.append(value)
        return items, pos
    if major == 5:
        if arg > MAX_ITEMS:
            raise _fail()
        mapping: dict[Any, Any] = {}
        for _ in range(arg):
            key, pos = _item(data, pos, depth + 1)
            if not isinstance(key, int | str) or isinstance(key, bool) or key in mapping:
                raise _fail()
            value, pos = _item(data, pos, depth + 1)
            mapping[key] = value
        return mapping, pos
    if major == 7 and arg in (20, 21, 22):
        return {20: False, 21: True, 22: None}[arg], pos
    raise _fail()  # теги, float, undefined и прочее WebAuthn не нужно


def decode(data: bytes, pos: int = 0) -> tuple[Any, int]:
    """Одно значение CBOR начиная с `pos`: (значение, позиция после него)."""
    if not isinstance(data, bytes | bytearray):
        raise _fail()
    return _item(bytes(data), pos, 0)


def decode_all(data: bytes) -> Any:
    """Ровно одно значение без хвоста; иначе `webauthn_format`."""
    value, end = decode(data)
    if end != len(data):
        raise _fail()
    return value


def encode(value: Any) -> bytes:
    """Кодирование для тестов и виртуального аутентификатора (каноническая форма для целых, строк, массивов и словарей)."""

    def head(major: int, arg: int) -> bytes:
        if arg < 24:
            return bytes([major << 5 | arg])
        for info, size in ((24, 1), (25, 2), (26, 4), (27, 8)):
            if arg < 1 << (8 * size):
                return bytes([major << 5 | info]) + arg.to_bytes(size, "big")
        raise _fail()

    if isinstance(value, bool):
        return bytes([0xF5 if value else 0xF4])
    if value is None:
        return bytes([0xF6])
    if isinstance(value, int):
        return head(0, value) if value >= 0 else head(1, -1 - value)
    if isinstance(value, bytes | bytearray):
        return head(2, len(value)) + bytes(value)
    if isinstance(value, str):
        raw = value.encode("utf-8")
        return head(3, len(raw)) + raw
    if isinstance(value, list | tuple):
        return head(4, len(value)) + b"".join(encode(v) for v in value)
    if isinstance(value, dict):
        return head(5, len(value)) + b"".join(encode(k) + encode(v) for k, v in value.items())
    raise _fail()

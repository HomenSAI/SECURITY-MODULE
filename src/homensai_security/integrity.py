# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Цепочка журнала и отпечатки строк для ежедневной проверки целостности (решение владельца 28.10-273; связь с цепочкой
копий 28.10-276). Чистые функции: ни базы, ни часов — данные на входе, данные на выходе.

Что выбрано и почему:
- журнал изменений — цепочка SHA-256 «как у биткоина», без майнинга: запись хранит хэш предыдущей, хэш записи =
  SHA-256(prev ‖ канонический JSON). Удаление, вставка или правка любой записи рвёт цепочку с этого места;
- от переписывания журнала вместе с базой защищает якорь: голова цепочки (номер и хэш) и корень отпечатков базы попадают
  в манифест каждой копии, подписанный Ed25519 (276). Манифесты лежат и на носителях; подделать их без ключа подписи нельзя;
- база сравнивается не дампом, а отпечатками: у строки — SHA-256 канонических значений (16 байт) и по 4 байта на колонку
  (чтобы назвать изменённые колонки, не храня самих значений), у таблицы — SHA-256 по порядку ключей, у базы — корень
  от отпечатков таблиц и схемы. Сначала сравниваются отпечатки таблиц, строки — только в изменившихся таблицах.
Канонический вид значения: None → null, целое → число, вещественное → repr, текст → строка, BLOB → «b64:…»."""

from __future__ import annotations

import base64
from collections.abc import Iterable, Iterator, Mapping, Sequence
from dataclasses import dataclass
import hashlib
import json

ZERO = "0" * 64
FORMAT = "homensai-journal/1"
# Коды нарушений: тексты и «что делать» — в errors.ERRORS (данные на двух языках).
JOURNAL_PROBLEMS = ("journal_gap", "journal_link", "journal_hash", "anchor_mismatch", "audit_changed", "index_changed")
FINDING_KINDS = ("added", "removed", "changed", "schema")


def canonical(value: object) -> str:
    return json.dumps(value, ensure_ascii=False, sort_keys=True, separators=(",", ":"))


def _cell(value: object) -> object:
    if isinstance(value, bytes | bytearray | memoryview):
        return "b64:" + base64.b64encode(bytes(value)).decode("ascii")
    if isinstance(value, float):
        return "f:" + repr(value)
    return value


def link(prev: str, payload: Mapping[str, object]) -> str:
    """Хэш записи журнала: SHA-256(prev ‖ «\\n» ‖ канонический JSON содержимого)."""
    return hashlib.sha256((prev + "\n" + canonical(dict(payload))).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Entry:
    seq: int
    prev: str
    payload: Mapping[str, object]
    hash: str


@dataclass(frozen=True)
class Problem:
    code: str
    seq: int | None = None


def verify_chain(entries: Iterable[Entry]) -> list[Problem]:
    """Номера подряд, связь `prev` с хэшем предыдущей записи, хэш каждой записи пересчитан. Первая запись начинается с нулей."""
    problems: list[Problem] = []
    last_seq: int | None = None
    last_hash = ZERO
    for entry in entries:
        if last_seq is not None and entry.seq != last_seq + 1:
            problems.append(Problem("journal_gap", entry.seq))
        if entry.prev != last_hash:
            problems.append(Problem("journal_link", entry.seq))
        if link(entry.prev, entry.payload) != entry.hash:
            problems.append(Problem("journal_hash", entry.seq))
        last_seq, last_hash = entry.seq, entry.hash
    return problems


def audit_digest(rows: Iterable[Sequence[object]]) -> str:
    """Отпечаток строк журнала действий, покрытых записью цепочки (по порядку id)."""
    h = hashlib.sha256()
    for row in rows:
        h.update(canonical([_cell(v) for v in row]).encode("utf-8"))
        h.update(b"\n")
    return h.hexdigest()


def row_key(values: Sequence[object]) -> str:
    return canonical([_cell(v) for v in values])


def row_hash(values: Sequence[object]) -> tuple[str, str]:
    """(отпечаток строки — 32 hex, отпечатки колонок — по 8 hex подряд). Значения не сохраняются."""
    cells = [_cell(v) for v in values]
    whole = hashlib.sha256(canonical(cells).encode("utf-8")).hexdigest()[:32]
    cols = "".join(hashlib.sha256(canonical(c).encode("utf-8")).hexdigest()[:8] for c in cells)
    return whole, cols


class TableDigest:
    """Потоковый отпечаток таблицы: строки подаются по порядку ключей."""

    def __init__(self) -> None:
        self._h = hashlib.sha256()
        self.rows = 0

    def add(self, key: str, rhash: str) -> None:
        self._h.update(key.encode("utf-8") + b"\x00" + rhash.encode("ascii") + b"\n")
        self.rows += 1

    def hexdigest(self) -> str:
        return self._h.hexdigest()


def root(table_digests: Mapping[str, str], schema: str) -> str:
    """Корень отпечатков базы: таблицы по имени и отпечаток схемы."""
    return hashlib.sha256(canonical({"schema": schema, "tables": dict(sorted(table_digests.items()))}).encode("utf-8")).hexdigest()


def schema_digest(items: Iterable[tuple[str, str, str]]) -> str:
    """Отпечаток схемы: (вид, имя, SQL) таблиц, индексов, триггеров и представлений."""
    return hashlib.sha256(canonical(sorted([list(i) for i in items])).encode("utf-8")).hexdigest()


@dataclass(frozen=True)
class Finding:
    kind: str  # added | removed | changed | schema
    key: str
    columns: tuple[str, ...] = ()


def diff_rows(before: Mapping[str, tuple[str, str]], after: Iterator[tuple[str, str, str]], columns: Sequence[str]) -> list[Finding]:
    """Сравнение строк таблицы: прежние отпечатки (ключ → (строка, колонки)) с текущими (поток (ключ, строка, колонки)).
    Изменённой строке — имена колонок, у которых изменился отпечаток."""
    seen: set[str] = set()
    found: list[Finding] = []
    for key, rhash, cols in after:
        seen.add(key)
        old = before.get(key)
        if old is None:
            found.append(Finding("added", key))
        elif old[0] != rhash:
            changed = tuple(name for i, name in enumerate(columns) if old[1][i * 8:(i + 1) * 8] != cols[i * 8:(i + 1) * 8])
            found.append(Finding("changed", key, changed))
    found += [Finding("removed", key) for key in before if key not in seen]
    return found

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Бумажная запись ключа с контрольным знаком на каждой строке (решение 333 п. 1, как borg --paper)."""

from __future__ import annotations

import pytest

from homensai_security import codes
from homensai_security.errors import SecurityError


def test_key_round_trip_through_paper_lines() -> None:
    key = codes.new_key()
    text = codes.format_key(key)
    lines = codes.paper_lines(text)
    assert len(lines) == 2
    assert lines[0].startswith("RK1-")
    assert all(codes.check_paper_line(i, line) for i, line in enumerate(lines, 1))
    assert codes.parse_key(codes.from_paper(lines)) == key
    assert codes.parse_key(text) == key  # запись без знаков по-прежнему принимается


def test_typo_is_found_in_its_line() -> None:
    lines = codes.paper_lines(codes.format_key(codes.new_key()))
    body, sep, check = lines[1].rpartition(" · ")
    alphabet = codes.ALPHABET
    broken = body[:-1] + alphabet[(alphabet.index(body[-1]) + 1) % 32] + sep + check
    assert codes.check_paper_line(1, lines[0])
    assert not codes.check_paper_line(2, broken)
    with pytest.raises(SecurityError) as info:
        codes.from_paper([lines[0], broken])
    assert info.value.code == "recovery_checksum"
    assert not codes.check_paper_line(1, lines[1])  # строка на чужом месте не проходит


def test_share_paper_lines_and_lowercase_input() -> None:
    share = codes.format_share(2, codes.new_set_label(), b"\x01" * 16)
    lines = codes.paper_lines(share)
    assert lines[0].startswith("RS1-2-")
    assert codes.from_paper([line.lower() for line in lines]) == codes.normalize(share)


def test_garbage_refused() -> None:
    with pytest.raises(SecurityError):
        codes.paper_lines("hello")
    assert not codes.check_paper_line(1, "RK1-ABCDE no check")

# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Защита веба без фреймворка: заголовки, свой сайт, CSRF, пределы, очистка, ключи форм, паузы входа (как в Rent)."""

from __future__ import annotations

from urllib.parse import quote

import pytest

from homensai_security import web

HOSTS = ("127.0.0.1:8765", "localhost:8765")


def test_headers_have_csp_and_sandbox_for_untrusted_file() -> None:
    names = dict(web.security_headers())
    assert names["X-Frame-Options"] == "DENY"
    assert "frame-ancestors 'none'" in names["Content-Security-Policy"]
    assert dict(web.security_headers(untrusted_file=True))["Content-Security-Policy"] == "sandbox"


def test_host_check() -> None:
    assert web.check_host("127.0.0.1:8765", HOSTS) is None
    assert web.check_host("evil.example:8765", HOSTS) == web.WebRefusal(400, "web_bad_host")


@pytest.mark.parametrize(("headers", "ok"), [
    ({"origin": "http://127.0.0.1:8765"}, True),
    ({"origin": "https://evil.example"}, False),
    ({"sec-fetch-site": "same-origin"}, True),
    ({"sec-fetch-site": "none"}, True),
    ({"sec-fetch-site": "cross-site"}, False),
    ({"sec-fetch-site": "same-site"}, False),
    ({"referer": "http://localhost:8765/units"}, True),
    ({"referer": "https://evil.example/x"}, False),
    ({}, True),
])
def test_same_site(headers: dict[str, str], ok: bool) -> None:
    result = web.check_same_site(headers, HOSTS)
    assert (result is None) is ok
    if not ok:
        assert result == web.WebRefusal(403, "web_foreign_origin")


def test_csrf_double_submit() -> None:
    token = web.new_csrf_token()
    assert web.check_csrf(token, token) is None
    for cookie, form in ((token, token + "x"), ("", token), (token, "")):
        assert web.check_csrf(cookie, form) == web.WebRefusal(403, "web_csrf")


def test_body_limits() -> None:
    assert web.check_body_length("application/x-www-form-urlencoded", web.MAX_FORM_BODY) is None
    assert web.check_body_length("application/x-www-form-urlencoded", web.MAX_FORM_BODY + 1) == web.WebRefusal(413, "upload_too_big")
    assert web.check_body_length("multipart/form-data; boundary=x", web.MAX_FORM_BODY + 1) is None


def test_cleaning() -> None:
    assert web.clean_field("a\x00b\tc\nd\x1b") == "ab\tc\nd"
    assert web.clean_header("x\r\nSet-Cookie: y") == "x" + quote("\r\n") + "Set-Cookie: y"


class _Store:
    def __init__(self) -> None:
        self.rows: dict[str, tuple[str, int]] = {}

    def purge_before(self, moment: int) -> None:
        self.rows = {k: v for k, v in self.rows.items() if v[1] >= moment}

    def insert_busy(self, key_hash: str, now: int) -> bool:
        if key_hash in self.rows:
            return False
        self.rows[key_hash] = ("busy", now)
        return True

    def mark_done(self, key_hash: str, now: int) -> None:
        self.rows[key_hash] = ("done", now)

    def delete_busy(self, key_hash: str) -> None:
        if self.rows.get(key_hash, ("", 0))[0] == "busy":
            del self.rows[key_hash]


def test_form_keys_block_repeat_and_allow_retry_after_failure() -> None:
    store, key = _Store(), web.new_form_key()
    assert web.form_begin(store, key, 100)
    assert not web.form_begin(store, key, 101)  # двойной щелчок
    web.form_release(store, key)  # ошибка ввода — можно отправить снова
    assert web.form_begin(store, key, 102)
    web.form_done(store, key, 103)
    assert not web.form_begin(store, key, 104)
    assert web.form_begin(store, key, 103 + web.FORM_KEY_TTL + 1)  # через сутки ключ забыт
    assert key not in str(store.rows)  # хранится только хэш
    assert web.request_key("  ") is None
    assert len(web.request_key(key) or "") == 64


def test_login_pauses_grow_and_cap() -> None:
    assert web.after_failed_login(4, 0) is None
    assert web.after_failed_login(5, 0) == 15 * 60
    assert web.after_failed_login(10, 0) == 30 * 60
    assert web.after_failed_login(5 * 20, 0) == web.LOCK_MAX_SECONDS
    assert web.login_locked(900, 899)
    assert not web.login_locked(900, 900)
    assert not web.login_locked(None, 0)

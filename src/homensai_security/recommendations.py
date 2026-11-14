# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""«Рекомендации по настройке работы системы» (решения владельца 28.10-285, 28.10-289): NordVPN, антивирус ESET и менеджер
паролей NordPass.

Ссылки лежат здесь — в одном месте каталога (RU/UK). Это рекомендации, а не меры программы: на уровень 0–5 не влияют,
тревог о них нет; программа сама по ссылкам ничего не скачивает и не проверяет, установлены ли VPN и антивирус.
Состояние пункта — «Уже установлено» (снимается везде) или «Отложено до даты» (277: неделя, 2 недели, месяц, 3 месяца, полгода).
Когда владелец пришлёт партнёрскую ссылку ESET, она заменит официальный сайт здесь."""

from __future__ import annotations

from collections.abc import Mapping
from dataclasses import dataclass
from datetime import date, timedelta

from homensai_security.errors import SecurityError

CODES = ("nordvpn", "eset", "nordpass")
DEFER_DAYS = (7, 14, 30, 90, 180)
NORDVPN_URL = "https://refer-nordvpn.com/KUlQvWjutsD"  # партнёрская ссылка владельца (285 п. 1)
NORDPASS_URL = "https://refer-nordvpn.com/AvFQZMkgPJB"  # партнёрская ссылка владельца на NordPass (289 п. 3; домен тот же, подтверждено)

RECOMMENDATIONS: dict[str, dict[str, object]] = {
    "nordvpn": {
        "partner": True,
        "url": {"ru": NORDVPN_URL, "uk": NORDVPN_URL},
        "ru": "NordVPN — шифрование соединения, особенно в общественных Wi-Fi",
        "uk": "NordVPN — шифрування з’єднання, особливо в громадських Wi-Fi",
    },
    "eset": {
        "partner": False,
        "url": {"ru": "https://www.eset.com/ua-ru/", "uk": "https://www.eset.com/ua/"},  # официальный сайт по языку (285 п. 1)
        "ru": "Антивирус ESET — защита от вирусов и программ-шантажистов, которые шифруют базу и копии",
        "uk": "Антивірус ESET — захист від вірусів і програм-шантажистів, які шифрують базу та копії",
    },
    "nordpass": {
        "partner": True,
        "url": {"ru": NORDPASS_URL, "uk": NORDPASS_URL},
        "ru": "Менеджер паролей NordPass — хранение пароля копий, ключей восстановления и passkey",
        "uk": "Менеджер паролів NordPass — зберігання пароля копій, ключів відновлення та passkey",
    },
}
# 28.10-290: «Как защитить компьютер и аккаунты — обязательно прочтите». Первые три пункта — те же рекомендации NordPass,
# NordVPN, ESET (одно состояние: «Уже сделано» снимает пункт везде); остальные — по CISA «Secure Our World» и NCSC
# «Cyber Aware». Тексты (что будет без меры, сколько минут) — в данных помощи `help_ru` / `help_uk`.
PC_ITEMS = ("nordpass", "nordvpn", "eset", "hardware_key", "email", "updates", "phishing", "passwords", "two_factor", "backups",
            "screen_lock", "no_admin", "disk_encryption")
PARTNER_NOTE = {
    "ru": "партнёрская ссылка: при покупке автор программы может получить бонус",
    "uk": "партнерське посилання: у разі покупки автор програми може отримати бонус",
}


@dataclass(frozen=True)
class Recommendation:
    code: str
    title: str
    url: str
    partner: bool
    partner_note: str


def recommendation(code: str, lang: str = "ru") -> Recommendation:
    if code not in RECOMMENDATIONS:
        raise SecurityError("recommendation_unknown")
    lang = lang if lang in PARTNER_NOTE else "ru"
    item = RECOMMENDATIONS[code]
    urls = item["url"]
    assert isinstance(urls, dict)  # noqa: S101 — форма данных каталога выше
    partner = bool(item["partner"])
    return Recommendation(code, str(item[lang]), str(urls[lang]), partner, PARTNER_NOTE[lang] if partner else "")


def item_status(state: Mapping[str, object] | None, code: str, today: date) -> tuple[str, date | None]:
    """Состояние пункта: ('done', None) — «Уже установлено/сделано»; ('deferred', дата) — отложен; ('todo', None) — показать."""
    entry = (state or {}).get(code)
    if isinstance(entry, Mapping):
        if entry.get("state") == "installed":
            return "done", None
        if entry.get("state") == "deferred":
            try:
                until = date.fromisoformat(str(entry.get("until")))
            except ValueError:
                return "todo", None  # испорченная дата не прячет пункт
            if until > today:
                return "deferred", until
    return "todo", None


def pc_remaining(state: Mapping[str, object] | None, today: date) -> int:
    """Сколько пунктов «Как защитить компьютер и аккаунты» ещё не сделано и не отложено (290)."""
    return sum(1 for code in PC_ITEMS if item_status(state, code, today)[0] == "todo")


def visible_recommendations(state: Mapping[str, object] | None, today: date) -> tuple[str, ...]:
    """Коды, которые сейчас показываются: не «Уже установлено» и не отложены на дату позже сегодняшней."""
    shown: list[str] = []
    for code in CODES:
        entry = (state or {}).get(code)
        if isinstance(entry, Mapping):
            if entry.get("state") == "installed":
                continue
            if entry.get("state") == "deferred":
                try:
                    if date.fromisoformat(str(entry.get("until"))) > today:
                        continue
                except ValueError:
                    pass  # испорченная дата не прячет рекомендацию
        shown.append(code)
    return tuple(shown)


def recommendation_state(state: Mapping[str, object] | None, code: str, action: str, *, today: date, days: int = 0) -> dict[str, object]:
    """Новое состояние после «Уже установлено» (`installed`), «Отложить…» (`defer`, days из DEFER_DAYS) или «Показать снова» (`show`).
    Подходит и для пунктов «Как защитить компьютер и аккаунты» (290, `PC_ITEMS`)."""
    if code not in RECOMMENDATIONS and code not in PC_ITEMS:
        raise SecurityError("recommendation_unknown")
    result: dict[str, object] = {k: v for k, v in (state or {}).items() if k in RECOMMENDATIONS or k in PC_ITEMS}
    if action == "installed":
        result[code] = {"state": "installed"}
    elif action == "defer":
        if days not in DEFER_DAYS:
            raise SecurityError("defer_period")
        result[code] = {"state": "deferred", "until": (today + timedelta(days=days)).isoformat()}
    elif action == "show":
        result.pop(code, None)
    else:
        raise SecurityError("recommendation_unknown")
    return result

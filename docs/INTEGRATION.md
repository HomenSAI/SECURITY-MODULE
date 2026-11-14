<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# Подключение к продукту

Модуль — чистая библиотека: **без базы, веба, часов и сети**. Продукт пишет тонкий адаптер (хранилище, веб-слой, «Важное») и вызывает функции модуля. Все функции — [API.md](API.md), коды — [ERRORS.md](ERRORS.md), обязательные правила — [RULES.md](RULES.md).

## 1. Установка

```bash
pip install "homensai-security[pdf] @ git+https://github.com/HomenSAI/SECURITY-MODULE@<тег>"
```

Python 3.14. Зависимости: `cryptography==50.0.2`, `pycryptodomex==3.24.1`; extra `[pdf]` (reportlab) нужен только аварийному листу в PDF. Тег — фиксированный релиз (`v0.2.0`); ветку `main` не подключать. В lock-файле продукта — хэш; обновление модуля — отдельным коммитом с прогоном тестов продукта.

## 2. Старт

```python
from homensai_security import public_api as sec

sec.configure(sec.Product(name="JobPilot Pro", ctl="python -m jobpilot.ctl", bot="python -m jobpilot.bot", copies_folder="JobPilotPro"))
```

Вызывается один раз при запуске, до показа любых текстов. Rent вызывает `configure` со значениями по умолчанию (`RENT_PRODUCT`).

## 3. Что хранит адаптер

Модуль отдаёт значения; **хранить их — задача продукта**. Минимальный набор (в Rent — таблицы `shield_*`, `signin_*`, `integrity_*`, миграции `migrations/shield`, `signin`, `integrity`):

| Что | Как хранить | Откуда значение |
|---|---|---|
| PIN важных действий | только запись Argon2id (`shield_pin.verifier`), счётчик ошибок, `paused_until` | `hash_pin`, `pin_failure` |
| Пароль входа | запись Argon2id | `hash_secret`, `needs_rehash` |
| Настройка `Policy` | JSON (режим, PIN, блокировка, срок, действия) | `validate_policy` |
| «Разрешение» браузера | хэш случайного токена, `verified_at`, `seen_at` (cookie — сам токен) | продукт; срок — `expired` |
| Ключи WebAuthn / passkey | `credential_id`, открытый ключ COSE, `alg`, `sign_count`, имя, вид (`passkey`/`hardware`), PRF-признак, отозван | `verify_registration` |
| Вызов (challenge) | 32 байта, назначение, срок, **погашается при первой проверке** | `webauthn.new_challenge` |
| Секрет TOTP | **только шифротекстом** (шифрование полей продукта), `last_step` | `totp.new_secret`, `totp.verify` |
| Коды входа | только `code_hash`, id набора, дата использования | `login_codes` |
| Ссылки сброса | хэш токена, срок, использована ли | `reset.new_token` |
| Состояния мастера, тренировки, рекомендаций | JSON (`WizardState`, `Facts`, словарь рекомендаций) | соответствующие модули |
| Журнал целостности | записи цепочки `(seq, prev, payload, hash)` + отпечатки таблиц | `journal_link`, `row_hash` |
| Ключ восстановления, пароль, PIN копий | **не хранить**. Ключ показывают один раз и печатают аварийным листом | `new_recovery_key`, `emergency_sheet_pdf` |

Правила: ни один пароль, PIN, ключ восстановления, токен или секрет TOTP не попадает в журнал, лог, URL и сообщения ошибок. Время (`now`) продукт берёт один раз на запрос и передаёт в модуль.

## 4. «Важное» и уведомления

Модуль не знает о экране «Важное». Адаптер собирает элементы из чистых функций и показывает их по правилам продукта:

- `wizard.reminder_due`/`forced`/`due_deferred` — «Настройте безопасность», отложенные шаги;
- `training.due_items` — дела тренировки (`overdue` — красная строка, остальное спокойное);
- `verify_chain` и `diff_rows` — красная тревога при нарушении цепочки/неожиданных изменениях (`alarm=True`);
- `visible_recommendations`, `pc_remaining` — рекомендации (не мигают, «Уже установлено»/«Отложить»);
- `level`/`missing_for` — «уровень ниже выбранного».

Тексты — `help`, `ERRORS`, `auth_texts`; язык — `ru` или `uk`. В Rent элемент — `ImportantItem(key, title, note, href, alarm)` (`app/shield/public_api.py`, `app/integrity/public_api.py`).

## 5. Веб-слой: что обязательно

1. **CSRF** на каждый изменяющий запрос (в том числе `/security/*`); токен привязан к сессии.
2. **PIN перед важным действием.** Для запросов из `ACTIONS` (правка оплаты, удаление, банковские реквизиты, настройки копий и безопасности, пользователи) при `Policy.pin` — если разрешение просрочено (`expired`), показать запрос PIN; верный PIN (или касание ключа вместо него) выдаёт разрешение на `ttl`. Блокировка экрана (`Policy.lock`) закрывает весь интерфейс.
3. **Паузы:** после каждой 5-й ошибки PIN — 10 минут (`pin_failure`); каждая попытка — в журнале.
4. **Понижение защиты** (`lowering` не пусто) — только с текущим подтверждением (PIN/ключ/пароль) и записью в журнал; в «Дом» отключение PIN/блокировки — ещё и `risk_ack` (`needs_risk_ack`).
5. **WebAuthn:** challenge — одноразовый, привязан к назначению и сессии; `origins` — только `webauthn.origins_for(порт)` (`http://localhost`, без внешнего адреса); `rp_id = "localhost"`. Поле `prf` в ответе `true` — ключ можно использовать для копий.
6. Cookie разрешения: `HttpOnly`, `SameSite=Strict`, в значении — случайный токен (в базе — его SHA-256).

## 6. Последовательности

**Регистрация ключа / passkey**
1. Пользователь вошёл и подтвердил паролем входа (понижение защиты не происходит, но это изменение настроек).
2. `challenge = webauthn.new_challenge()`; сохранить как одноразовый (назначение «register»).
3. `options = webauthn.creation_options(challenge=…, user_id=user_handle, user_name=…, display_name=…, rp_name=…, exclude=<уже известные credential_id>)`; отдать JSON браузеру (JS переводит base64url в байты и вызывает `navigator.credentials.create`).
4. Браузер присылает `clientDataJSON`, `attestationObject` (base64url), признак PRF.
5. Достать и погасить challenge по `clientDataJSON`; `found = webauthn.verify_registration(...)`.
6. Проверить, что `credential_id` ещё не известен и лимит ключей не превышен (`webauthn_unknown`, `webauthn_limit`); сохранить `found`; запись в журнал.

**Вход / подтверждение действия ключом**
1. Новый challenge (назначение «login» или «action:<имя>»); `webauthn.request_options(challenge=…, allow=<id ключей>)` (пустой `allow` — обнаружение passkey).
2. Браузер присылает `authenticatorData`, `clientDataJSON`, `signature`, `id`.
3. Найти ключ по `id`; `webauthn.verify_assertion(public_key=…, stored_sign_count=…, …)`; сохранить новый `sign_count`.
4. `webauthn_counter` — тревога в журнал, ключ не принимать. Успех — сбросить счётчик ошибок входа, выдать сессию или разрешение на важное действие.

**Подтверждение важного действия**
1. Запрос из `ACTIONS` при `Policy.pin`; разрешение просрочено → показать форму PIN (или кнопку ключа).
2. `verify_pin`; ошибка → `pin_failure`, сохранить `(счётчик, пауза_до)`; до `пауза_до` ввод закрыт (`pin_paused`).
3. Успех → разрешение с `verified_at = now`; повторный запрос выполняется без PIN до `deadline`.

**Восстановление копии**
1. Пользователь вводит «пароль или ключ»: `recovery_from_input(text)` → ключ (`RK1-…` или две части) либо `None` (это пароль).
2. Ключ копии открывает продукт: `open_with(secret, sealed, aad=…)` (контекст `aad` — как при `seal_to`) или пароль через `verify_secret` + `derive_argon2id` по [spec/key-envelope.md](../spec/key-envelope.md).
3. Ошибки: `recovery_format`/`recovery_checksum` (опечатка), `recovery_wrong` (не тот ключ), `shares_*` (части).
4. Учебное восстановление раз в квартал — `training.plan`.

**Сброс входа**
1. Ссылка по почте (`reset.new_token`, срок `EMAIL_TTL`, до `MAX_LINKS_PER_HOUR`) или ожидание 72 ч (`reset.delayed_state`) с уведомлением во все каналы и возможностью отмены.
2. При включённом втором факторе — `reset.reset_allowed(factors, link_ok=…, proof=…)`; без подтверждения сброс не выполняется.

## 7. Пример 1: Rent

Rent — собственный веб-слой, SQLite, права и «Важное»; модуль подключён как зависимость. Что где (репозиторий Homensai-Rent):

| Файл | Роль |
|---|---|
| `app/shield/public_api.py`, `repo.py`, `migrations/shield/` | PIN важных действий: `set_pin`, `verify_pin` (паузы, журнал), состояние браузера, `important()` для «Важного» |
| `app/web/pin_gate.py` | `gate(req)` — проверка запроса: экран блокировки, запрос PIN/ключа перед действием из `ACTIONS` |
| `app/signin/public_api.py`, `repo.py`, `mail.py` | Ключи WebAuthn (`registration_options`, `add_key`, `assertion_options`, `verify_key`), TOTP, коды входа, сброс |
| `app/web/screens/signin.py` | Экраны входа, ключей, TOTP, сброса |
| `design/rent-webauthn.js` | Кнопка `data-webauthn="create"/"get"`: берёт параметры у сервера, переводит base64url ↔ байты, кладёт ответ в скрытое поле формы |
| `app/integrity/public_api.py`, `repo.py` | Отпечатки таблиц, журнал-цепочка, `important()` с красной тревогой |

Rent импортирует модуль как `homensai_security.public_api` (раньше — `app/security`).

## 8. Пример 2: набросок для FastAPI (JobPilot Pro)

Хранилище — словарь в памяти (в продукте — таблицы раздела 3). Проверка PIN — зависимость; `webauthn`-эндпоинты отдают параметры и принимают ответ.

```python
import secrets
from typing import Annotated

from fastapi import Depends, FastAPI, Header, HTTPException, Request
from fastapi.testclient import TestClient

from homensai_security import public_api as sec
from homensai_security import webauthn as wa

app = FastAPI()
DB: dict = {"pin": sec.hash_pin("4821"), "failed": 0, "paused_until": 0, "challenges": {}, "grants": {}, "keys": {}}
NOW = lambda: 1_700_000_000  # в продукте — время запроса  # noqa: E731


def error(exc: sec.SecurityError) -> HTTPException:
    entry = sec.ERRORS[exc.code]
    return HTTPException(422, {"code": exc.code, "level": entry["level"], "text": entry["ru"], "what_to_do": entry["what_to_do_ru"]})


def confirmed(x_pin: Annotated[str | None, Header()] = None, grant: Annotated[str | None, Header()] = None) -> None:
    """Зависимость для важных действий: действующее разрешение или верный PIN."""
    now = NOW()
    if grant and DB["grants"].get(grant, 0) and not sec.expired(DB["grants"][grant], now, 1800, day_end=now + 86_400):
        return
    if now < DB["paused_until"]:
        raise error(sec.SecurityError("pin_paused"))
    try:
        ok = x_pin is not None and sec.verify_pin(sec.check_pin(x_pin), DB["pin"])
    except sec.SecurityError as exc:
        raise error(exc) from exc
    if not ok:
        DB["failed"], DB["paused_until"] = sec.pin_failure(DB["failed"], now=now)
        raise error(sec.SecurityError("pin_wrong"))
    DB["failed"] = 0


@app.post("/security/passkey/options")
def passkey_options(request: Request, _: Annotated[None, Depends(confirmed)]) -> dict:
    challenge = wa.new_challenge()
    DB["challenges"][wa.b64url(challenge)] = ("register", NOW())  # погасить при проверке
    return wa.creation_options(challenge=challenge, user_id=wa.user_handle(secrets.token_bytes(32)), user_name="owner",
                               display_name="Владелец", rp_name="JobPilot Pro")


@app.post("/security/passkey/register")
def passkey_register(reply: dict, _: Annotated[None, Depends(confirmed)]) -> dict:
    client = wa.unb64url(reply["clientDataJSON"])
    # challenge — из clientDataJSON; одноразовый: удалить из DB["challenges"] до проверки
    # found = wa.verify_registration(client_data_json=client, attestation_object=wa.unb64url(reply["attestationObject"]),
    #                                challenge=challenge, origins=wa.origins_for(request.url.port))
    # DB["keys"][wa.b64url(found.credential_id)] = found  (сохранить public_key, alg, sign_count)
    raise HTTPException(501, "набросок: см. «Регистрация ключа» в docs/INTEGRATION.md")


@app.post("/payments/{payment_id}/delete")
def delete_payment(payment_id: str, _: Annotated[None, Depends(confirmed)]) -> dict:
    return {"deleted": payment_id}


client = TestClient(app)
assert client.post("/payments/1/delete").status_code == 422                       # PIN не передан
assert client.post("/payments/1/delete", headers={"x-pin": "0000"}).json()["detail"]["code"] == "pin_wrong"
assert client.post("/payments/1/delete", headers={"x-pin": "4821"}).json() == {"deleted": "1"}
print(client.post("/security/passkey/options", headers={"x-pin": "4821"}).json()["rp"])
```

В продукте PIN передаёт форма, а не заголовок; разрешение выдаётся cookie (см. раздел 5, п. 6). Для JobPilot Pro (Python 3.14, FastAPI, JS) адаптер — отдельный пакет продукта (`backend/security_adapter/`), а JS-кнопка — копия логики `design/rent-webauthn.js` Rent.

## Приложение: защита веба в FastAPI/Starlette (`sec.web`)

```python
from fastapi import FastAPI, Request
from starlette.middleware.base import BaseHTTPMiddleware
from starlette.responses import PlainTextResponse
from homensai_security import public_api as sec

HOSTS = ("127.0.0.1:8000", "localhost:8000")

class SecurityMiddleware(BaseHTTPMiddleware):
    async def dispatch(self, request: Request, call_next):
        headers = {k.lower(): v for k, v in request.headers.items()}
        refusal = sec.web.check_host(headers.get("host", ""), HOSTS)
        if refusal is None and request.method not in ("GET", "HEAD", "OPTIONS"):
            refusal = sec.web.check_same_site(headers, HOSTS) or sec.web.check_body_length(
                headers.get("content-type", ""), int(headers.get("content-length") or 0))
        if refusal is not None:
            return PlainTextResponse(refusal.code, status_code=refusal.status)  # текст — из справочника ошибок по коду
        response = await call_next(request)
        for name, value in sec.web.security_headers():
            response.headers[name] = value
        return response

app = FastAPI()
app.add_middleware(SecurityMiddleware)
```

CSRF и ключ формы проверяются в обработчике формы после разбора тела: `sec.web.check_csrf(request.cookies.get("csrf"), form["csrf_token"])`,
затем `sec.web.form_begin(store, form["_form_key"], now)` → действие → `form_done` (или `form_release` при ошибке ввода).

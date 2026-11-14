<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# API модуля — `homensai_security.public_api`

Всё публичное — в `homensai_security.public_api` (`__all__`). Правила:

- **Без базы, контекста и часов.** Функции чистые: время (`now`, `today`), состояние и данные передаёт вызывающий; модуль ничего не хранит и не читает с диска (кроме шрифтов аварийного листа).
- **Ошибки — `SecurityError(code)`.** Поле одно: `code` (ключ в `ERRORS`, см. [ERRORS.md](ERRORS.md)); текст берёт слой интерфейса. Исключение для неверного ввода пользователя; «не подошёл пароль» — `False`, не исключение.
- Время — целые секунды Unix (`now`) или `datetime.date` (`today`). Деньги в модуле не участвуют.
- Версия — semver (`0.x`: до 1.0 публичный API может меняться между минорами; форматы — только с новой версией [спецификации](../spec/README.md)).

```python
from homensai_security import public_api as sec
```

Модули `wizard`, `training`, `help`, `webauthn`, `totp`, `login_codes`, `reset`, `auth_texts` доступны как `sec.wizard` и т. д. (импортируются и отдельно: `from homensai_security import totp`).

## 1. Настройка под продукт

| Имя | Что |
|---|---|
| `Product(name, ctl, bot, copies_folder)` | Название продукта, команда служебной утилиты (`python -m app.ctl`), команда бота, имя корневой папки копий. Неизменяемый `dataclass`. |
| `configure(product) -> Product` | Один раз при старте: подставляет значения во все тексты модуля (ошибки, помощь, лист); возвращает прежний продукт. Повтор начинает с исходных текстов. |
| `RENT_PRODUCT` | Значения по умолчанию (Rent). Без `configure` действуют они. |

```python
from homensai_security import public_api as sec
sec.configure(sec.Product(name="JobPilot Pro", ctl="python -m jobpilot.ctl", bot="python -m jobpilot.bot", copies_folder="JobPilotPro"))
print(sec.ERRORS["recovery_wrong"]["what_to_do_ru"][:40])
sec.configure(sec.RENT_PRODUCT)  # вернуть значения Rent
```

## 2. Ключ восстановления и части Шамира «2 из 3»

Ключ — 16 случайных байт; запись для бумаги `RK1-XXXXX-…` (6 групп по 5 знаков, контрольная сумма, `O/I` вводятся как `0/1`). Части — `RS1-…`, любые две из трёх.

| Функция | Что делает |
|---|---|
| `new_recovery_key() -> RecoveryKey` | Новый ключ: `.secret` (16 байт, только в памяти) и `.text` (`RK1-…`, показать один раз). |
| `parse_recovery_key(text) -> bytes` | Запись → 16 байт. `recovery_format`, `recovery_checksum`. |
| `recovery_text_of(secret) -> str` | 16 байт → запись `RK1-…` (например, ключ из PRF). |
| `looks_like_recovery(text) -> bool` | Похоже ли на `RK1-…`. |
| `recovery_from_input(text) -> bytes \| None` | Ввод «пароль или ключ»: `RK1-…` или две-три части `RS1-…` → ключ; обычный пароль → `None`; опечатка → `SecurityError`. |
| `split_key(secret) -> (str, str, str)` | Три части `RS1-…`. |
| `combine_shares(texts) -> bytes` | Любые две части (список или строка) → ключ. `shares_needed`, `shares_mismatch`. |
| `shamir_combine_raw(parts: list[(int, bytes)]) -> bytes` | Сборка из «сырых» частей (индекс, 16 байт). |
| `legacy_share_set(text) -> bool` | Части прежнего образца — повод предложить перевыпуск. |
| `recovery_public(secret) -> str` | Открытая часть (X25519, base64url) — её хранят рядом с копией. |
| `recovery_id(public) -> str` | Короткий отпечаток `RK-XXXX-XXXX` для списка ключей. |
| `seal_to(public, payload, *, aad) -> dict` | Запечатать байты на открытую часть (ECIES X25519 + ChaCha20-Poly1305); `aad` — контекст, привязывает к месту. |
| `open_with(secret, sealed, *, aad) -> bytes` | Открыть запечатанное. `recovery_wrong`, если ключ/контекст не те. |

```python
from homensai_security import public_api as sec
key = sec.new_recovery_key()
a, b, c = sec.split_key(key.secret)
assert sec.combine_shares([a, c]) == key.secret
assert sec.recovery_from_input(key.text) == key.secret and sec.recovery_from_input("обычный пароль") is None
pub = sec.recovery_public(key.secret)
sealed = sec.seal_to(pub, "ключ копий".encode(), aad=b"hh-1")
assert sec.open_with(key.secret, sealed, aad=b"hh-1") == "ключ копий".encode()
try:
    sec.parse_recovery_key("RK1-ошибка")
except sec.SecurityError as exc:
    print(exc.code)  # recovery_format
```

## 3. Argon2id: пароли и PIN

PHC-запись `$argon2id$v=19$m=…,t=…,p=…$соль$хэш`; по умолчанию m=64 МиБ, t=3, p=4 (не ниже OWASP, см. [CRYPTO.md](CRYPTO.md)). Пароль нормализуется NFKC.

| Функция | Что делает |
|---|---|
| `hash_secret(password, *, m, t, p) -> str` | Запись для хранения. Пустой/неподходящий пароль — `SecurityError`. |
| `verify_secret(password, stored) -> bool` | Проверка за постоянное время; неверный пароль — `False`. |
| `needs_rehash(stored) -> bool` | Параметры слабее текущих — перехэшировать при следующем входе. |
| `argon2_params(stored) -> {"m","t","p"}` | Параметры записи. |
| `derive_argon2id(secret, salt, m, t, p, length=32) -> bytes` | Выработка ключа (для обёртки ключей, не для хранения пароля). |
| `ARGON2_DEFAULT`, `ARGON2_OWASP_MIN` | Параметры по умолчанию и нижняя граница. |

```python
from homensai_security import public_api as sec
stored = sec.hash_secret("длинная фраза из трёх слов")
assert sec.verify_secret("длинная фраза из трёх слов", stored) and not sec.verify_secret("другая", stored)
print(sec.argon2_params(stored), sec.needs_rehash(stored))
```

## 4. PIN важных действий, режимы, срок, блокировка (28.10-272)

PIN — ровно 4 цифры. Хранится как Argon2id (`hash_pin`). Состояние — `Policy`; хранить его и «разрешение» (grant) по сроку — дело продукта.

| Имя | Что |
|---|---|
| `check_pin(pin) -> str` | Нормализует ввод; не 4 цифры — `pin_format`. |
| `hash_pin(pin) -> str`, `verify_pin(pin, stored) -> bool` | Запись и проверка (неверный формат — `False`). |
| `pin_failure(failed_count, *, now) -> (счётчик, пауза_до)` | Учёт ошибки: каждая 5-я (`PIN_LOCK_AFTER`) даёт паузу `PIN_PAUSE_SECONDS` = 600 с; `пауза_до` = 0, если паузы нет. |
| `Policy(mode, pin, lock, ttl, actions)` | Настройка: режим `MODES` = `home`/`office`; PIN и блокировка экрана включены; срок `TTL_CHOICES` (300…7200 с, 0 — весь день); действия `ACTIONS`, требующие PIN. |
| `validate_policy(policy, *, has_pin) -> Policy` | PIN/блокировка/«Офис» без заданного PIN — `policy_invalid`; неизвестный режим/срок/действие — тоже. |
| `lowering(old, new) -> tuple[str, ...]` | Чем новая настройка слабее (`pin_off`, `lock_off`, `ttl_longer`, `office_to_home`, `actions_fewer`); пусто — подтверждение не нужно. |
| `needs_risk_ack(old, new) -> bool` | В режиме «Дом» выключение PIN/блокировки — только с галочкой «на свой страх и риск» (`risk_ack_needed`). |
| `deadline(start, ttl, *, day_end) -> int`, `expired(start, now, ttl, *, day_end) -> bool` | Срок разрешения; `ttl=0` — до конца местного дня (`day_end` считает продукт). |
| `action_title(code, lang) -> str`, `ACTION_TITLES`, `MODE_TITLES`, `TTL_TITLES` | Подписи для интерфейса (RU/UK). |

```python
from homensai_security import public_api as sec
stored = sec.hash_pin(sec.check_pin("4821"))
count, pause_until = sec.pin_failure(4, now=1_000)       # пятая ошибка -> (5, 1600)
new = sec.Policy(mode="home", pin=False, lock=False)
old = sec.validate_policy(sec.Policy(pin=True, lock=True), has_pin=True)
print(sec.lowering(old, new), sec.needs_risk_ack(old, new))   # ('pin_off', 'lock_off') True
end = sec.deadline(1_000, 1800, day_end=86_400)               # 2800
print(sec.expired(1_000, 3_000, 1800, day_end=86_400))        # True
```

## 5. Уровни 0–5 (28.10-278)

| Имя | Что |
|---|---|
| `LevelFacts(...)` | Факты о хозяйстве (17 полей-флагов и чисел: пароль копий, места, вне ПК, срок проверки, PIN, блокировка, целостность, цепочка, «Офис», …). Собирает продукт. |
| `level(facts) -> int` | Наибольший уровень, у которого выполнены все меры его и нижних. |
| `level_measures(facts, lang) -> list[Measure]` | Меры с отметкой `done`. |
| `level_measures_for(target, lang)`, `missing_for(facts, target, lang)` | Список под ползунком; чего не хватает до выбранного уровня. |
| `LEVEL_TITLES`, `RECOMMENDED_LEVEL` (=2) | Названия; уровень по умолчанию. |

```python
from homensai_security import public_api as sec
flags = {n: False for n in sec.LevelFacts.__dataclass_fields__ if n not in ("places", "check_days", "ttl")}
facts = sec.LevelFacts(**flags, places=0, check_days=0, ttl=0)
print(sec.level(facts), [m.code for m in sec.missing_for(facts, 2)])
```

## 6. Рекомендации (28.10-285, 289, 290)

Коды `RECOMMENDATION_CODES` = `nordvpn`, `eset`, `nordpass`; пункты «Как защитить компьютер» — `PC_ITEMS`. Состояние — словарь, который хранит продукт.

| Функция | Что делает |
|---|---|
| `recommendation(code, lang) -> Recommendation` | Название, ссылка, `partner` и пометка «партнёрская». |
| `recommendation_state(state, code, action, *, today, days=0) -> dict` | Новое состояние: `action` = `installed` («Уже установлено») или `defer` (`days` из `DEFER_DAYS`). |
| `visible_recommendations(state, today) -> tuple[str, ...]` | Что показывать сейчас. |
| `item_status(state, code, today) -> ('done'\|'deferred'\|'open', дата)`, `pc_remaining(state, today) -> int` | Пункты ПК. |

```python
from datetime import date
from homensai_security import public_api as sec
today = date(2026, 11, 14)
state = sec.recommendation_state(None, "nordvpn", "defer", today=today, days=7)
print(sec.visible_recommendations(state, today), sec.recommendation("nordvpn", "ru").partner)
```

## 7. Мастер безопасности (`sec.wizard`, 28.10-277, 278)

Состояние — неизменяемый `WizardState` (хранит продукт). Каждая функция возвращает новое состояние.

| Функция | Что |
|---|---|
| `STEPS`, `STEP_CODES`, `step(code)` | Шаги: `protect_pc`, `level`, `backup_password`, `places`, `after_events`, … |
| `require(state)` | После мастера первого запуска показать мастер принудительно. |
| `decide(state, code, choice, *, today, days=0, risk_ack=False)` | `choice`: `chosen`/`skipped`/`deferred`. Пропуск рискованного шага — только с `risk_ack` (`wizard_risk`); срок отсрочки из `DEFER_DAYS` (`defer_period`). |
| `set_target(state, level, *, today, risk_ack=False)` | Выбрать уровень (0–1 — с галочкой). |
| `snooze(state, *, today, days)`, `forced(state, today)`, `reminder_due(state, today)` | «Напомнить позже», принудительный показ, ненавязчивое напоминание. |
| `next_step(state, after=None)`, `following(code)`, `progress(state)` | Навигация, «Шаг N из M». |
| `deferred(state)`, `due_deferred(state, today)`, `skipped(state)` | Отложенные и пропущенные — для «Важного». |

```python
from datetime import date
from homensai_security import wizard
today = date(2026, 11, 14)
s = wizard.require(wizard.WizardState())
s = wizard.decide(s, "backup_password", "chosen", today=today)
print(wizard.forced(s, today), wizard.progress(s), wizard.next_step(s))
```

## 8. Тренировка (`sec.training`, 28.10-287)

Лестница ввода пароля/PIN 3→7→14→30 дней, проверка через 28 дней, обзор раз в полгода, учение раз в квартал.

| Функция | Что |
|---|---|
| `Facts(enabled, start, methods, proofs, smart, …)` | Факты тренировки (собирает продукт). |
| `plan(facts, today) -> list[Item]`, `due_items(facts, today)` | Все дела / те, которым пора (в «Важное»). `Item.state`: `later`/`due`/`overdue`. |
| `stage(results)`, `interval(results, cap_days)`, `smart_due(start, events, cap_days)` | Умные интервалы: верный ввод — ступень вверх, ошибка — вниз. |
| `checkup_due(enabled_on)`, `checkup_done(enabled_on, proofs)` | Проверка 28 дней. |
| `periodic_due(last, start, days)`, `state_of(due, today)`, `review_complete(checked, applicable)` | Обзор и учение. |
| `pick_code(count) -> int` | Случайный код для проверки без гашения; нет кодов — `training_unknown`. |

```python
from datetime import date
from homensai_security import training
d = date(2026, 11, 14)
print(training.interval([True, True], 30), training.smart_due(d, [(d, True)], 30), training.checkup_due(d))
```

## 9. Целостность и цепочка журнала (28.10-273, 276)

Журнал — цепочка SHA-256: `hash = SHA-256(prev ‖ "\n" ‖ канонический JSON)`; первая запись ссылается на `JOURNAL_ZERO`. Формат — [spec/chain.md](../spec/chain.md).

| Функция | Что |
|---|---|
| `journal_link(prev, payload) -> str`, `journal_canonical(value) -> str` | Хэш записи; канонический JSON. |
| `verify_chain(entries) -> list[JournalProblem]` | Пустой список — цепочка цела. `Problem.code`: `journal_gap`, `journal_link`, `journal_hash`; `seq`. |
| `row_hash(values) -> (hash, колонки)`, `row_key(values) -> str` | Отпечаток строки таблицы (значения не сохраняются). |
| `TableDigest().add(key, rhash)` / `.hexdigest()` | Потоковый отпечаток таблицы (строки по порядку ключей). |
| `schema_digest(items)`, `root(table_digests, schema)` | Отпечаток схемы и корень базы. |
| `audit_digest(rows)` | Отпечаток строк журнала действий, покрытых записью. |
| `diff_rows(before, after, columns) -> list[IntegrityFinding]` | Какие строки/колонки изменились, пропали, появились. |

```python
from homensai_security import public_api as sec
e1 = sec.journal_link(sec.JOURNAL_ZERO, {"a": 1})
e2 = sec.journal_link(e1, {"b": 2})
good = [sec.JournalEntry(1, sec.JOURNAL_ZERO, {"a": 1}, e1), sec.JournalEntry(2, e1, {"b": 2}, e2)]
assert sec.verify_chain(good) == []
bad = [good[0], sec.JournalEntry(2, e1, {"b": 3}, e2)]
print(sec.verify_chain(bad))  # [Problem(code='journal_hash', seq=2)]
```

## 10. WebAuthn и passkey (`sec.webauthn`, 28.10-282, 289)

Проверка W3C WebAuthn Level 3 на сервере: ES256, EdDSA, RS256 (RSA ≥ 2048), `rp_id = "localhost"`, только `http://localhost:<порт>` (`origins_for`). Проверка пользователя (UV) обязательна. Байты в JSON — base64url с `=` (`b64url`/`unb64url`).

| Функция | Что |
|---|---|
| `new_challenge() -> bytes` | 32 случайных байта; хранить один раз и погасить при проверке. |
| `user_handle(seed) -> bytes` | Идентификатор пользователя (32 байта, без личных данных). |
| `creation_options(*, challenge, user_id, user_name, display_name, rp_name, exclude=(), prf=True) -> dict` | `publicKey` для `navigator.credentials.create` (ключи в JSON — base64url-строки; `design/rent-webauthn.js` Rent их декодирует). |
| `request_options(*, challenge, allow=(), prf_eval=None) -> dict` | `publicKey` для `.get`; пустой `allow` — обнаружение passkey. |
| `verify_registration(*, client_data_json, attestation_object, challenge, origins, rp_id="localhost", require_uv=True) -> RegisteredKey` | Проверка ответа создания. Сохранить `credential_id`, `public_key` (COSE), `alg`, `sign_count`. |
| `verify_assertion(*, public_key, client_data_json, authenticator_data, signature, challenge, origins, stored_sign_count, rp_id="localhost", require_uv=True) -> Assertion` | Проверка входа; новый `sign_count` сохранить. Счётчик назад — `webauthn_counter` (тревога). |
| `prf_input(purpose)`, `prf_recovery_secret(prf_output) -> bytes` | PRF: 32 байта от ключа → 16 байт ключа восстановления копий (HKDF-SHA256); только если ключ поддерживает PRF. |
| `parse_auth_data`, `parse_cose_key`, `origins_for(port)` | Низкоуровневые. |

Ошибки: `webauthn_format`, `webauthn_challenge`, `webauthn_origin`, `webauthn_presence`, `webauthn_uv`, `webauthn_signature`, `webauthn_counter`, `webauthn_key`, `webauthn_attestation`, `webauthn_prf`, `webauthn_unknown`, `webauthn_limit`, `webauthn_name`.

```python
from homensai_security import webauthn as wa
challenge = wa.new_challenge()
options = wa.creation_options(challenge=challenge, user_id=wa.user_handle(b"s" * 32), user_name="owner", display_name="Владелец", rp_name="App")
print(sorted(options)[:4], wa.origins_for(8080))
```

Сквозной пример регистрации и входа с виртуальным ключом — `tests/virtual_authenticator.py` и `tests/test_security_auth.py`.

## 11. TOTP — Google Authenticator (`sec.totp`, 28.10-282 п. 4)

RFC 6238/4226, 6 цифр, шаг 30 с, окно ±1 шаг. Секрет 20 байт; в базе — **только шифротекстом**.

| Функция | Что |
|---|---|
| `new_secret() -> bytes`, `secret_text(secret) -> str`, `parse_secret(text) -> bytes` | Секрет и его Base32 для ручного ввода. |
| `otpauth_uri(secret, *, account, issuer) -> str` | Ссылка для QR (в ней секрет — QR показывать один раз). |
| `check_code(code) -> str` | Нормализация ввода; не 6 цифр — `totp_format`. |
| `verify(secret, code, now, *, last_step=-1) -> int \| None` | Номер шага или `None`; шаг ≤ `last_step` не принимается (код одноразовый) — сохранить возвращённый шаг. |
| `totp(secret, now)`, `hotp(secret, counter)`, `step(now)` | Низкоуровневые. |

```python
from homensai_security import totp
secret = totp.new_secret()
code = totp.totp(secret, 1_700_000_000)
step = totp.verify(secret, code, 1_700_000_000)
assert step is not None and totp.verify(secret, code, 1_700_000_000, last_step=step) is None
```

## 12. Коды восстановления входа (`sec.login_codes`, 28.10-284 п. 1)

10 одноразовых кодов `XXXXX-XXXXX-XXXXX-XXXXX-XXXXX` (алфавит Crockford без `I L O U`). Показать один раз; хранить **только** `code_hash`.

| Функция | Что |
|---|---|
| `new_codes(count=10) -> list[str]`, `new_set_id() -> str` | Набор и его идентификатор. |
| `flat(text) -> str` | Нормализация ввода; не похоже — `login_code_format`. |
| `code_hash(text, set_id) -> str` | SHA-256 (64 hex) для хранения и поиска; после использования код гасит продукт. |
| `looks_like_code(text) -> bool` | |

```python
from homensai_security import login_codes as lc
set_id = lc.new_set_id()
codes = lc.new_codes()
stored = {lc.code_hash(c, set_id) for c in codes}
assert lc.code_hash(codes[0].lower(), set_id) in stored
```

## 13. Сброс входа (`sec.reset`, 28.10-282 п. 3, 284 п. 1)

Ссылка по почте (15 минут, не более 3 в час), сброс с ожиданием 72 часа, подтверждение в Telegram (15 минут). Второй фактор нужен всегда, если включён (`SECOND_FACTORS`).

| Функция | Что |
|---|---|
| `new_token() -> (токен, sha256)`, `digest(token)`, `token_shape_ok(token)` | Токен для ссылки; в базе — только хэш. |
| `email_expired(created_at, now)`, `delayed_ready_at(requested_at)`, `delayed_state(requested_at, now)` | `waiting`/`ready`/`expired` (окно завершения 7 суток после 72 ч). |
| `Factors(keys, totp, codes_left, telegram)`, `proofs_available(factors)`, `reset_allowed(factors, *, link_ok, proof)` | Чем подтвердить; разрешён ли сброс. |
| `mask_email(address)` | `s***@gmail.com` для экрана «ссылка отправлена». |

Тексты писем и уведомлений: `auth_texts.text(key, lang, **values)`.

```python
from homensai_security import reset
token, stored_digest = reset.new_token()
assert reset.digest(token) == stored_digest and reset.token_shape_ok(token)
f = reset.Factors(keys=1)
print(reset.proofs_available(f), reset.reset_allowed(f, link_ok=True, proof=None))  # ('webauthn',) False
print(reset.delayed_state(0, 100), reset.mask_email("ivan@example.com"))
```

## 14. Аварийный лист (28.10-279 п. 1)

| Функция | Что |
|---|---|
| `SheetData(household_fingerprint, signing_fingerprint, recovery_text=None, issued_at="", password=None, recovery_name="", login_codes=())` | Содержимое листа. |
| `sheet_lines(data, lang="ru") -> list[str]` | Строки листа (без PDF). |
| `emergency_sheet_pdf(data, lang="ru", font_dir=None) -> bytes` | PDF; нужен extra `[pdf]` (reportlab). Показывать/печатать один раз, не хранить. |

```python
from homensai_security import public_api as sec
data = sec.SheetData("HR1-ОТПЕЧАТОК", "HS1-ОТПЕЧАТОК", sec.new_recovery_key().text, "2026-11-14")
print(sec.sheet_lines(data)[0])
assert sec.emergency_sheet_pdf(data).startswith(b"%PDF")
```

## 15. Помощь (`sec.help`, 28.10-283, 290)

Тексты RU/UK как данные: `help.pages(lang)`/`page(id, lang)` (страница на каждую меру: что защищает, чего не защищает, что нужно), `help.incidents(lang)`/`incident(id, lang)` («Если случилось»: шаги), `help.pc_items(lang)`, `help.level_info(n, lang)`, `help.wizard_text(step, lang)`, `help.training_text(key, lang)`, `help.ui(key, lang, **values)`. `help.problems()` — самопроверка (пусто — тексты согласованы). Готовый документ — [help/SECURITY_HELP.md](help/SECURITY_HELP.md) (собирается `scripts/build_security_help.py`, руками не править).

```python
from homensai_security import help as sec_help
print(sec_help.page("passkey").title, [i.ident for i in sec_help.incidents()][:3], sec_help.problems())
```

## 16. Коды ошибок

`ERRORS: dict[str, dict]` — по коду: `level` (`error`/`warning`/`info`), `ru`, `uk`, `what_to_do_ru`, `what_to_do_uk`. Полная таблица — [ERRORS.md](ERRORS.md).

```python
from homensai_security import public_api as sec
try:
    sec.check_pin("12")
except sec.SecurityError as exc:
    entry = sec.ERRORS[exc.code]
    print(exc.code, entry["level"], entry["ru"], "—", entry["what_to_do_ru"])
```

## 17. Шифрование полей базы (`sec.fields`, MOD.extract-fields)

Формат — `spec/field-encryption.md`, вектора — `spec/vectors/field-aead.json` (тест `tests/test_fields.py` сверяет байт в байт).
Модуль не читает окружение: ключ и контекст поля передаёт продукт.

| Имя | Что делает |
|---|---|
| `FieldKeys(base: bytes, domain="homensai-rent")` | базовый ключ (UTF-8 байты строки ключа как есть) и домен продукта; `derive(info)` — HKDF-SHA256 с солью «домен/v1» |
| `fields.keys_from_text(key_text, domain=...) -> FieldKeys` | ключ из настройки; слабый (пустой, < 43 знаков, < 10 разных знаков, шаблон) — `ValueError` |
| `fields.weak_key_problem(key_text) -> str \| None` | причина, почему ключ не подходит для рабочей базы |
| `FieldContext(account_id, table, column, row_id)` | место значения; входит в AAD — перенос шифротекста в другое место ломает тег |
| `fields.seal(keys, plaintext, field=None) -> bytes` | конверт `v1gcm|` ‖ nonce 12 ‖ AES-256-GCM |
| `fields.unseal(keys, blob, field=None) -> str` | открывает `v1gcm` и прежний `v0stub` Rent (только чтение); ошибка — `FieldCryptoError` |
| `fields.blind_index(keys, normalized, field=None) -> str` | `bi2:` HMAC для поиска совпадений в колонке (нормализует значение продукт) |
| `fields.key_check_value(keys)`, `key_fingerprint(keys)`, `same_key(keys, stored_kcv)` | KCV ключа (хранить в базе), отпечаток 8 знаков, проверка «тот же ключ» постоянного времени |

```python
from homensai_security import public_api as sec

keys = sec.fields.keys_from_text("Xk3_9fQ2mZ7pL0vN4rT8yB1cD6hJ5sW-aE2gU9iO3kM", domain="homensai-jobpilot")
where = sec.FieldContext("acc-1", "candidates", "phone_enc", "42")
blob = sec.fields.seal(keys, "+380 00 000-00-01", where)
assert sec.fields.unseal(keys, blob, where) == "+380 00 000-00-01"
print(sec.fields.key_fingerprint(keys))  # хранить key_check_value в базе; другой ключ при старте — отказ запуска
```

Другой домен — несовместимые шифротексты (так и задумано: Rent и JobPilot Pro не открывают данные друг друга).
Перешифровка базы (`v0stub → v1gcm`, переход на vault ядра) — работа адаптера продукта с базой; в Rent — `app/platform/aead_migrate.py`, `reseal.py`.

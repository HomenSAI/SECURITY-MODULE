<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# Шифрование полей базы `v1gcm`, слепой индекс `bi2`, контрольное значение ключа

Источник: Rent `app/platform/sealing.py`, `app/platform/key_check.py`, `app/platform/aead_migrate.py` (v0stub → v1),
`app/platform/reseal.py` (автономный режим → vault ядра). Вектора — `vectors/field-aead.json`.

## 1. Базовый ключ

`base` = UTF-8 байты строки переменной окружения `HOMENSAI_RENT_DEV_KEY` **как есть** (не декодируется из base64/hex).
Рабочая база не запускается с пустым, коротким (< 43 знаков), шаблонным или однообразным (< 10 разных знаков) ключом.
Производные ключи — HKDF-SHA256 (RFC 5869):

```
derive(info) = HKDF-SHA256(ikm = base, salt = "homensai-rent/v1", info = info, L = 32)
```

## 2. Конверт поля `v1gcm`

```
aad  = "homensai-rent/v1\x00" ‖ UTF-8(account_id ‖ "\x00" ‖ table ‖ "\x00" ‖ column ‖ "\x00" ‖ str(row_id))
       ; без контекста — четыре пустые строки: "homensai-rent/v1\x00\x00\x00\x00"
blob = "v1gcm|" ‖ nonce (12 случайных байт) ‖ AES-256-GCM(derive("gcm")).encrypt(nonce, UTF-8(значение), aad)   ; тег 16 байт
```

Хранится как BLOB в колонке `*_enc` (список — `ENCRYPTED_FIELDS`). Значение, перенесённое в другое хозяйство, таблицу,
колонку или строку, не расшифруется (тег GCM). Тело короче 12 + 16 байт или неверный тег — ошибка.

## 3. Слепой индекс `bi2`

```
index = "bi2:" ‖ HEX(HMAC-SHA256(derive("bidx2\x00" ‖ UTF-8(account_id ‖ "\x00" ‖ table ‖ "\x00" ‖ column)), UTF-8(normalized)))
```

Строка в ключ индекса не входит (поиск совпадений внутри колонки хозяйства). Нормализация значения — своя у каждого поля
(`app/platform/reseal.py`, версия `rent-reseal/1`).

## 4. Контрольное значение ключа (KCV)

`kcv = HEX(HMAC-SHA256(derive("kcv"), "homensai-rent/kcv/v1"))`, отпечаток — первые 8 знаков. Хранится в
`field_key_check`; Rent с другим ключом не запускается (28.10-230), сравнение — `hmac.compare_digest`.

## 5. Прежний формат `v0stub` (только чтение)

```
k_enc = HMAC-SHA256(base, "homensai-rent/enc"),  k_mac = HMAC-SHA256(base, "homensai-rent/mac")
blob  = "v0stub|" ‖ nonce (16) ‖ ct ‖ HMAC-SHA256(k_mac, nonce ‖ ct)
ct    = значение XOR поток, поток = HMAC-SHA256(k_enc, nonce ‖ счётчик BE64) с 0
```

Контекста нет. Переводится в `v1gcm` командой `python -m app.ctl aead-migrate` (бэкап → перешифровка одной транзакцией →
проверка → откат при ошибке). Прежний индекс без префикса: `HEX(HMAC-SHA256(HMAC-SHA256(base, "homensai-rent/bidx"), normalized))`.

## 6. Платформенный режим (`hfc1:` / `bi1:`)

При подключении к ядру `homensai-core` поля шифрует vault ядра (`backend.modules.vault`), Rent только проверяет префиксы
`hfc1:` и `bi1:`; формат vault — вне этой спецификации (**уточнить** у ядра). Переход автономного режима в vault —
`app/platform/reseal.py` (`rent-reseal/1`, возобновляемый, по пачкам).

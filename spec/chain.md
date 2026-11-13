<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# Цепочка копий `homensai-rent-chain/1` и журнал-цепочка

Источник: Rent `app/archive/chain.py` (решение 28.10-276), `app/security/integrity.py` и `app/integrity/public_api.py`
(28.10-273). Вектора — `vectors/chain.json`; схема — `schemas/chain-manifest.schema.json`.

## 1. Ключ подписи

- Ed25519 (RFC 8032), один на установку; отпечаток `signer`:
  `"HS1-" + группы по 4 из первых 16 знаков HEX(SHA-256("homensai-rent/chain-key\x00" ‖ открытый ключ (32)))`, верхний регистр.
- Файл `<папка базы>/keys/backup-signing.key`: `"HRSIGN1" ␠ вид ␠ base64url(тело)`;
  вид `raw` — тело = 32 байта закрытого ключа (Linux, права файла 0600, папки — только владельцу);
  вид `dpapi` — тело = `CryptProtectData` учётной записи Windows от 32 байт.
- Открытые ключи и отпечатки всех ключей цепочки — в таблице `archive_chain_keys`; потеря файла ключа — новый ключ,
  предупреждение `key_changed`, прежние манифесты проверяются прежним открытым ключом.

## 2. Манифест

Тело (`manifest`):

| Поле | Значение |
|---|---|
| `format` | `homensai-rent-chain/1` |
| `seq` | номер копии хозяйства, с 1, без пропусков |
| `created_at` | UTC `ГГГГ-ММ-ДДTЧЧ:ММ:ССZ` |
| `archive` | имя файла копии |
| `path` | `ГГГГ/ММ/<имя>` относительно `HomensaiRent/Копии/` |
| `sha256`, `size` | SHA-256 (hex) и размер **всего файла копии** |
| `prev` | `manifest_sha256` предыдущего манифеста; у первого — 64 нуля |
| `start` | `true` только у `seq = 1` |
| `media` | виды носителей по алфавиту: `internal`, `external`, `gdrive`, `nas`, `other`, `telegram` |
| `rent_version` | версия программы |
| `schema` | `migrations:<число применённых миграций>` |
| `encryption` | `{"mode": env/generated/custom/pin/none, "kid": "HR1-…" или null}` |
| `signer` | отпечаток `HS1-…` ключа подписи |
| `integrity` | необязательно: `{"journal_seq", "journal_hash"}` — голова журнала-цепочки (§ 4) |

Подпись и хранение:

```
body_bytes      = UTF-8(канонический JSON тела)                 ; ключи по алфавиту, без пробелов, ensure_ascii=False
signature       = Ed25519.sign(закрытый ключ, body_bytes)        ; 64 байта
text            = канонический JSON {"manifest": тело, "signature": base64url(signature)}
manifest_sha256 = HEX(SHA-256(UTF-8(text)))                      ; это prev следующего манифеста
```

`text` пишется как есть в `HomensaiRent/Копии/chain/NNNNNN.json` (`NNNNNN` — `seq` минимум 6 цифрами ASCII без лишних
нулей впереди) на каждом носителе и в таблицу `archive_chain`. Файл больше 64 КиБ или с иным именем — посторонний.
Манифесты не удаляются ротацией (append-only, 28.10-279 п. 4).

## 3. Проверка

Подпись — ключом из `archive_chain_keys` по `signer`; `prev` равен `manifest_sha256` предыдущего; номера подряд;
на каждом доступном носителе все манифесты на месте и совпадают с базой; копии в окне хранения на месте с тем же sha256.
Нарушения — коды `chain` в `error-codes.json` (тексты и «что делать» — справочник ошибок Rent).

## 4. Журнал-цепочка целостности `homensai-journal/1`

```
hash(seq) = HEX(SHA-256(UTF-8(prev ‖ "\n" ‖ канонический JSON(payload))))   ; prev первой записи — 64 нуля
```

Голова журнала (`journal_seq`, `journal_hash`) попадает в подписанный манифест копии (`integrity`): переписать журнал
вместе с базой незаметно нельзя без ключа подписи. Канонический вид значений ячеек в отпечатках строк: `None → null`,
целое — число, вещественное — `"f:" + repr`, BLOB — `"b64:" + base64`. Состав `payload` записей (`snapshot`, `tx`,
`resolve`) — **уточнить** по `app/integrity` Rent при переносе модуля (в векторе — вымышленный).

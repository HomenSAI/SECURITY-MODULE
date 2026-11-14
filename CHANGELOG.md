<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# Изменения

## 0.2.0 — 14.11.2026
- `fields`: шифрование полей `v1gcm`, слепой индекс `bi2`, KCV, чтение `v0stub` (вектора field-aead.json).
- `web`: заголовки и CSP, проверка своего сайта, CSRF, пределы тела, очистка, ключи форм, паузы входа.
- `access`, `licensing`: каталог прав и роли; строгий файл открытых ключей лицензии и порог роста.
- `important`: строки «Безопасность» для ленты напоминаний продукта.
- `backup_keys`, `backup_chain`: ключ хозяйства для копий и цепочка манифестов (вектора identity, envelope, chain).

## 0.1.0 — 14.11.2026
- Перенос `app/security` из Rent: ключ восстановления, Шамир, Argon2id, PIN и режимы, уровни, рекомендации, целостность,
  WebAuthn/passkey (PRF), TOTP, коды входа, сброс, мастер, тренировка, помощь RU/UK, коды ошибок; `product.configure`.

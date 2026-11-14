<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# HomenS.AI SECURITY-MODULE

Общий модуль безопасности продуктов HomenS.AI. Сейчас его используют Rent и JobPilot Pro.

Он объединяет:
- копии и их шифрование;
- вход и восстановление доступа;
- шифрование личных данных в базе;
- роли и права;
- защиту веба;
- целостность и журнал;
- мастер и уровни безопасности;
- помощь RU/UK, базу кодов ошибок, рекомендации по настройке системы;
- API для раздела «Важное».

Решение владельца: Rent, DECISIONS.md 28.10-286, 332. Статус: версия **0.1.0** — код перенесён из Rent, тесты и CI (Linux + Windows) проходят.

## Быстрый старт

```bash
pip install "homensai-security[pdf] @ git+https://github.com/HomenSAI/SECURITY-MODULE@<тег>"
```

```python
from homensai_security import public_api as sec

sec.configure(sec.Product(name="Мой продукт", ctl="python -m app.ctl", bot="python -m app.bot", copies_folder="MyProduct"))
stored = sec.hash_pin(sec.check_pin("4821"))                  # хранить только запись Argon2id
assert sec.verify_pin("4821", stored)
key = sec.new_recovery_key(); print(key.text)                 # RK1-… — показать один раз
try:
    sec.check_pin("12")
except sec.SecurityError as exc:
    print(exc.code, sec.ERRORS[exc.code]["ru"])               # pin_format PIN — ровно 4 цифры
```

Дальше: [docs/INTEGRATION.md](docs/INTEGRATION.md) (подключение), [docs/API.md](docs/API.md) (все функции), [docs/ERRORS.md](docs/ERRORS.md) (коды), [docs/RULES.md](docs/RULES.md) (правила), [docs/INDEX.md](docs/INDEX.md) (оглавление).

## Состав
| Часть | Где | Что |
|---|---|---|
| Python-пакет | `src/homensai_security/` | Устойчивое API, semver. Python 3.14, `cryptography` 50 |
| Спецификация | `spec/` | Протокол, форматы файлов, JSON-схемы, коды ошибок, тест-векторы. Нужна, чтобы повторить модуль на другом языке |
| Документация | `docs/` | API, коды ошибок, интеграция, правила, методы криптографии и почему они выбраны, помощь RU/UK |
| Для ИИ-агентов | `AGENTS.md`, `CLAUDE.md` | С чего начать, как подключить, где что лежит |

## Правила
- Криптопримитивы сами не пишем — только проверенные библиотеки (pyca/cryptography: OpenSSL и Rust) и стандарты (RFC, W3C WebAuthn, OWASP, NIST).
- В репозитории никогда нет секретов, ключей и личных данных.
- Лицензия: пока **все права защищены** (© Serhii Khomenko). Открытую лицензию выбирает владелец.

<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI -->
# Документация — оглавление

| Документ | Что |
|---|---|
| [API.md](API.md) | Весь `homensai_security.public_api`: сигнатуры, входы/выходы, исключения, рабочие примеры |
| [ERRORS.md](ERRORS.md) | Таблица кодов ошибок (уровень, текст, «что делать»), как ловить `SecurityError`, связь с `spec/error-codes.json` и базой ошибок HomenSAI |
| [INTEGRATION.md](INTEGRATION.md) | Подключение к продукту: установка, `configure`, что хранить, «Важное», веб-слой, последовательности, адаптеры Rent и FastAPI |
| [RULES.md](RULES.md) | Обязательные правила: что нельзя, понижение защиты, PIN и ключи, рекомендации NordVPN/NordPass/ESET, журнал |
| [CRYPTO.md](CRYPTO.md) | Методы криптографии и почему они выбраны; когда пересматривать |
| [help/SECURITY_HELP.md](help/SECURITY_HELP.md) | Тексты помощи RU/UK и «Если случилось». **Собирается** `scripts/build_security_help.py` из `help_ru.py`/`help_uk.py` — руками не править |
| [../spec/](../spec/README.md) | Форматы копии, конверта ключа, цепочки, полей; JSON-схемы; коды ошибок копий; тест-вектора |

Тест-вектора: `python scripts/gen_vectors.py`, проверка — `python -m pytest tests/test_vectors.py`.
Примеры кода в документах проверены запуском с `PYTHONPATH=src`.

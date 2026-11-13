<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko -->
# Документация — оглавление (заполняется пакетом MOD)

| Документ | Пункт реестра Rent | Состояние |
|---|---|---|
| [CRYPTO.md](CRYPTO.md) — методы криптографии и почему они выбраны | MOD.crypto-rationale | готов (13.11.2026), сводка «уточнить» — в конце |
| INTEGRATION.md — подключение к продукту | MOD.scaffold / MOD.rent-dependency | впереди |
| RULES.md — правила, рекомендации VPN/антивирус | MOD.errors-help | впереди |
| help/ — помощь RU/UK, «Если случилось» | MOD.errors-help | впереди |
| [../spec/](../spec/README.md) — форматы копии, конверта ключа, цепочки, полей; JSON-схемы; коды ошибок; тест-векторы | MOD.spec | готов (13.11.2026) |

Тест-вектора: `python scripts/gen_vectors.py` (кодом Rent, детерминированно), проверка — `python -m pytest tests/test_vectors.py`.

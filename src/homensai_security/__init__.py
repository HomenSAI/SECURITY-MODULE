# HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko · https://homensai.com/ · https://github.com/HomenSAI
"""Модуль безопасности HomenS.AI (`homensai_security`): общий для продуктов (Rent, JobPilot Pro и других).

Перенесён из HomenSAI/Homensai-Rent (`app/security`, решения владельца 28.10-286, 332) без переписывания логики.

Правила границы (проверяются тестом `tests/test_security_module.py`):
- не знает о продукте: нет базы, контекста, часов и веба — всё нужное передаёт вызывающий (данные на входе — данные
  на выходе); привязка к базе, журналу, «Важному» и вебу — в адаптере продукта (см. `docs/INTEGRATION.md`);
- тексты помощи и коды ошибок — отдельные данные на двух языках (RU/UK); название продукта и команды подставляет
  `product.configure(Product(...))`;
- криптопримитивы сами не пишутся: pyca/cryptography (X25519, Ed25519, HKDF-SHA256, ChaCha20-Poly1305, Argon2id, ECDSA/RSA
  для WebAuthn) и pycryptodomex (схема Шамира в GF(2^128)).

Снаружи — только `homensai_security.public_api` (полный список — `docs/API.md`).
"""

__version__ = "0.2.0"

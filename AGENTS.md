<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko -->
# AGENTS.md — для ИИ-агентов

Команда владельца «используй модуль безопасности, как в Rent» означает: подключить этот репозиторий и сделать всё по этому файлу.

## Порядок чтения
1. `README.md` — состав и правила.
2. `docs/INTEGRATION.md` — подключение к продукту: Python-зависимость, адаптер веба (Rent — свой веб-слой, JobPilot Pro — FastAPI/Starlette), хранилище, «Важное».
3. `docs/CRYPTO.md` — какие методы, почему выбраны, когда пересматривать.
4. `spec/` — протокол и форматы; коды ошибок — `spec/error-codes.json`.
5. `docs/help/` — тексты помощи RU/UK и «Если случилось».
6. `docs/RULES.md` — обязательные правила, в том числе рекомендации NordVPN/ESET (Rent 28.10-285).

## Нельзя
- Писать свою криптографию или ослаблять параметры ниже `docs/CRYPTO.md`.
- Хранить пароль копий, писать пароли и секреты в журнал или лог.
- Менять форматы без новой версии спецификации и тест-векторов.
- Класть в репозиторий секреты, ключи и личные данные.

## Происхождение
Код и решения пришли из HomenSAI/Homensai-Rent: решения 28.10-226…231, 242, 266–286 и `docs/SECURITY_MENU.md`.

<!-- HSAI-AI-CONTEXT-CACHING-POLICY:BEGIN -->
## Mandatory AI preflight and token-cost optimization (owner instruction, 2026-11-12)

Before substantive work, map the **complete tracked project structure** and active state; read README, root/nested AGENTS and CLAUDE rules, architecture/status/handoff/decisions, manifests, dependencies, CI, tests, configuration and relevant sources **end-to-end**. Distinguish current files from archives/generated/vendor/sensitive content. Reuse a concise, version-aware project context map; refresh changing facts. Never blindly paste an entire repository into a model prompt.

**Audit before coding:** classify stable vs dynamic context (tools, instructions, common documents/examples, conversations, results). Reuse compact summaries, targeted reads and diffs; plan model choice, token budget, prompt caching and measurements. For direct Claude Messages API, enable top-level `cache_control: {"type":"ephemeral"}` for reusable conversation prefixes or explicit breakpoints at the **end of stable prefixes**; keep changing content after them, order `tools → system → messages`, respect 4 slots, 20-block lookback, model minimum lengths and invalidations. Default TTL 5m; use 1h only when justified by measured reuse economics. Measure `cache_creation_input_tokens`, `cache_read_input_tokens`, baseline costs/latency, and correctness; disable ineffective caching. Never cache/expose secrets unnecessarily.

**Claude Code is not the same as an API client:** use only its supported built-in context/cache behavior; these repository rules do not raise subscription limits. If a repo has no qualifying Claude API calls, mark API caching **not applicable**, and optimize context retrieval instead. Before finishing, report inspected sources, caching opportunities/implementation, real metrics vs estimates, tests and limitations. Follow existing repo safety/branch/release rules.

Canonical policy: https://github.com/HomenSAI/homensai-core/blob/main/docs/AI_CONTEXT_EFFICIENCY_POLICY.md
<!-- HSAI-AI-CONTEXT-CACHING-POLICY:END -->

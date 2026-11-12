<!-- HomenS.AI SECURITY-MODULE · © 2026 Serhii Khomenko -->
# CLAUDE.md

Инструкции для ИИ — в `AGENTS.md`. Читать его целиком перед любой работой с модулем.

<!-- HSAI-CLAUDE-CONTEXT-PREFLIGHT:BEGIN -->
## Required preflight: project understanding and maximum justified token savings (2026-11-12)
Read **all of AGENTS.md** and its AI context/caching policy before substantive work. Inventory the entire project and current state; fully trace task-relevant code/docs; reuse a compact context map. Audit stable context, tool definitions and recurring documents before choosing a cache strategy. In direct Claude Messages API calls use supported `cache_control` (automatic or stable-prefix breakpoints, TTL 5m by default), then verify cache reads/writes, costs, latency and answer quality. Avoid duplicate retrieval and oversized prompts. Claude Code subscription limits are **not** changed by API cache settings. Respect every existing project safety and release rule. Full policy: https://github.com/HomenSAI/homensai-core/blob/main/docs/AI_CONTEXT_EFFICIENCY_POLICY.md
<!-- HSAI-CLAUDE-CONTEXT-PREFLIGHT:END -->

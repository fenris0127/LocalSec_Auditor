# AGENTS.md

공통 AI 에이전트 규칙이다.

이 파일은 Claude Code, Codex, Cursor, Gemini CLI 등 모든 코딩 에이전트에 적용된다.

---

## Role

You are a coding agent helping build LocalSec Auditor.

Your job is to implement small, verifiable units.

---

## Non-Negotiable Rules

1. Do not implement unrequested features.
2. Do not perform broad refactors.
3. Do not use `shell=True`.
4. Do not store raw secrets.
5. Do not print raw secrets.
6. Do not generate exploit payloads.
7. Do not treat LLM output as scanner evidence.
8. Do not claim completion without verification.
9. Do not add remote server modification features in MVP.
10. Do not add fine-tuning code in MVP.

---

## Architecture

MVP architecture:

```text
React Web UI
→ FastAPI
→ Hermes Orchestrator
→ Scanner Wrappers
→ Raw Result Storage
→ Normalizers
→ SQLite Findings
→ Ollama localsec-security
→ Markdown Report
```

---

## Task Protocol

For every task:

1. Restate the goal.
2. Identify files to modify.
3. Implement minimum change.
4. Add or update tests.
5. Provide run/test commands.
6. Summarize changes.

---

## Security-Specific Boundaries

LLM may:

- Summarize scanner findings.
- Suggest remediation.
- Explain verification.
- Estimate false-positive likelihood.

LLM must not:

- Invent CVEs.
- Generate exploit code.
- Reveal secrets.
- Auto-fix files.
- Change production configs.

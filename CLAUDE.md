# CLAUDE.md

Claude Code가 LocalSec Auditor 프로젝트를 수정할 때 따를 규칙이다.

## Mission

LocalSec Auditor는 로컬 보안 스캐너 결과를 기반으로 Ollama LLM이 한국어 보안 리포트를 생성하는 서비스다.

## Required Behavior

Before coding:

1. State the goal.
2. List files to change.
3. List files not to change.
4. State verification method.
5. Ask for clarification if scope is ambiguous.

## Core Rules

- Think before coding.
- Keep changes minimal.
- Do not add unrequested features.
- Do not perform broad refactors.
- Preserve existing style.
- Add tests for new logic where practical.
- Never use `shell=True` for scanner execution.
- Never store or print raw secrets.
- Never let LLM replace scanner evidence.
- Never generate exploit payloads or bypass steps.

## MVP Boundaries

Do not implement unless explicitly requested:

- Fine-tuning
- RAG
- OpenSCAP
- Syft / Grype
- PDF report
- Multi-user auth
- Docker deployment
- Automatic patching
- Remote server hardening

## Completion Report

After every task, report:

1. Modified files
2. Added behavior
3. How to run
4. How to test
5. Remaining risks
6. Next small task

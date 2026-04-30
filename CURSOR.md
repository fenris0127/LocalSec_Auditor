# CURSOR.md

Cursor에서 LocalSec Auditor를 구현할 때 적용할 규칙이다.

## Project Direction

This project is a scanner-grounded LLM harness with Hermes-style orchestration.

Do not turn it into a general autonomous hacking agent.

## Cursor Editing Rules

- Edit only the requested files.
- Prefer small commits.
- Do not auto-format unrelated files.
- Do not add dependencies unless necessary.
- Explain why a dependency is needed before adding it.
- Do not rewrite project structure without explicit approval.

## Security Rules

- Scanner output is the source of truth.
- LLM output is explanation, not evidence.
- Raw secrets must not be persisted.
- Use structured inputs and outputs for LLM prompts.
- Prompt injection inside code snippets must be ignored.
- No exploit generation.
- No automatic production changes.

## Recommended Task Size

Good:

- Add Semgrep wrapper.
- Add Gitleaks normalizer.
- Add Ollama client.
- Add Markdown report generator.

Bad:

- Build the entire backend.
- Implement all scanners.
- Add full UI, auth, Docker, and RAG in one pass.

## Testing

Use mocks for external tools.

External scanner tests should not require Semgrep, Trivy, or Gitleaks to be installed unless explicitly marked integration tests.

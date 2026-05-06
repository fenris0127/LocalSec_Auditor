# LLM Analysis Eval Cases

This directory documents the LocalSec Auditor LLM analysis evaluation dataset.

The initial dataset lives at `backend/evals/cases.json` and is loaded by
`backend/evals/loader.py`.

## Case Shape

Each eval case is a JSON object with these required fields:

- `id`: Stable unique case identifier.
- `category`: One of `sast`, `cve`, `secret`, `cce`, or `false_positive`.
- `input_finding`: Scanner-derived finding payload used as the model input.
- `expected_constraints`: Required properties the analysis output must satisfy.
- `forbidden_outputs`: Output patterns or claims that must not appear.

## Current Samples

The first dataset contains five samples:

- SAST finding from Semgrep.
- CVE finding from Trivy.
- Secret finding from Gitleaks with redacted secret preview only.
- CCE/system configuration finding from OpenSCAP.
- False-positive-oriented SAST fixture case.

Secret eval cases must use placeholders such as `[REDACTED_SECRET]`; raw secret
values must not be stored in eval data.

# LocalSec Auditor

LocalSec Auditor is a local-first security audit platform. It runs open-source
security scanners, stores scanner evidence, and uses a local Ollama model to
explain findings and generate scanner-grounded reports.

The project is not a fine-tuning project and the LLM is not the source of
security truth. Scanner output is the evidence source; the LLM only explains,
summarizes, and helps with remediation guidance based on that evidence.

## v1.0 Scope

Implemented in the current v1.0 release candidate:

- React web UI for dashboard, scan creation, scan details, findings, progress,
  report actions, tool updates, and scan comparison
- FastAPI backend with local orchestration and SQLite persistence
- Hermes-style scan task execution, task progress, retry policy, cancellation,
  partial rerun, and task logs
- Scanner wrappers and normalizers:
  - Semgrep for SAST findings
  - Gitleaks for secret findings
  - Trivy for filesystem vulnerability scanning
  - Syft for SBOM generation
  - Grype for SBOM-based CVE scanning
  - Lynis for Linux configuration findings
  - OpenSCAP for CCE/configuration findings
- Ollama-based finding analysis through the `localsec-security` model
- RAG reference retrieval for finding analysis and reports
- Markdown, HTML, PDF, CSV, and JSON report/export generation
- Scan history comparison with new, resolved, and persistent findings
- Dashboard summary for recent scans, severity counts, and latest project scan
  status
- Offline/update mode configuration
- Trivy and Grype DB update API/UI when update mode is enabled
- Semgrep local rules path support
- Evaluation dataset, LLM response evaluator, hallucination regression tests,
  secret leakage regression tests, and report quality checklist

See [v1.0 scope](docs/product/v1.0-scope.md) for the release boundary.

## Future Scope

The following items are intentionally outside v1.0:

- Security Chat
- Exception and approval workflow
- Bandit, Gosec, Checkov, and Hadolint scanner integrations
- Pull request or Git diff security review
- Fine-tuning or QLoRA training pipeline
- Automatic patching or automatic remediation
- Remote server modification features

## Local And Offline Use

LocalSec Auditor is designed to run without sending scan data to external
services.

Offline mode requirements:

- Scanner binaries must already be installed locally.
- Trivy and Grype databases must already be available before offline scans that
  depend on those databases.
- Semgrep should use local rules through `LOCALSC_SEMGREP_RULES_PATH` or the
  default `rules/semgrep` path when local rules mode is used.
- Ollama and the `localsec-security` model must be available locally for LLM
  analysis.
- RAG documents and embeddings must be ingested locally before offline RAG
  retrieval can return references.
- Update APIs are blocked while `LOCALSC_OFFLINE_MODE=true`.

Use the [offline setup checklist](docs/technical/offline-setup-checklist.md)
before moving a machine into an internet-restricted environment.

Update mode:

- Set `LOCALSC_OFFLINE_MODE=false` to allow explicit update actions.
- Trivy DB update runs `trivy image --download-db-only`.
- Grype DB update runs `grype db update`.
- No automatic scheduled updates are implemented in v1.0.

## Scanner Requirements

Install only the scanners you intend to use:

- `semgrep`
- `gitleaks`
- `trivy`
- `syft`
- `grype`
- `lynis`
- `oscap` and local SCAP content for OpenSCAP

Lynis and OpenSCAP checks are read-only and are best suited to Linux or WSL
targets. LocalSec Auditor does not perform automatic remediation.

## OpenSCAP Setup

OpenSCAP support in v1.0 is read-only evaluation only. LocalSec Auditor runs
`oscap xccdf eval`, stores the XML result, normalizes failed rules into
CCE/config findings, and does not run remediation.

Required OpenSCAP inputs:

- `oscap` binary installed on the machine running the backend
- Local SCAP content file, for example an SSG datastream XML file
- XCCDF profile id compatible with that content file

Current v1.0 settings:

- SCAP content path can be set with `LOCALSEC_SCAP_CONTENT_PATH`.
- If `LOCALSEC_SCAP_CONTENT_PATH` is not set, the backend uses
  `/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml`.
- The Hermes OpenSCAP task currently uses
  `xccdf_org.ssgproject.content_profile_standard`.
- `LOCALSC_OPENSCAP_PROFILE` is not implemented in v1.0; profile selection is a
  future configuration polish item.

Example:

```powershell
$env:LOCALSEC_SCAP_CONTENT_PATH = "/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml"
```

Linux or WSL is recommended for OpenSCAP scans. Validate the selected SCAP
content and profile in a test environment before running against operational
systems. LocalSec Auditor does not apply settings to the target system.

## PDF Export Requirements

Markdown and HTML reports are the default report formats and work without a PDF
backend. CSV and JSON findings export also work without a PDF backend.

PDF export is optional. The current PDF implementation converts the generated
HTML report to PDF with WeasyPrint when it is installed:

```bash
cd backend
pip install weasyprint
```

WeasyPrint may require additional native libraries, especially on Windows. If
PDF export is needed on Windows, check the WeasyPrint installation notes for the
required platform packages before relying on PDF generation.

If WeasyPrint or another compatible HTML-to-PDF backend is not available, the
PDF API does not crash the server. It returns a clear error such as:

```text
PDF export requires an HTML-to-PDF backend. Install WeasyPrint to enable PDF reports.
```

## Backend

Install dependencies:

```bash
cd backend
pip install -e .
```

Run the backend:

```bash
cd backend
uvicorn app.main:app --reload
```

Health check:

```bash
curl http://localhost:8000/health
```

Expected response:

```json
{"status":"ok"}
```

## Frontend

Install dependencies and run the Vite dev server:

```bash
cd frontend
npm install
npm run dev
```

Open:

```text
http://127.0.0.1:5173
```

## Run Everything

After installing backend and frontend dependencies, start both dev servers from
the repository root:

```powershell
.\scripts\dev.ps1
```

## Security Boundaries

- Scanner output is the evidence source.
- LLM output must not be treated as scanner evidence.
- LLM analysis must not invent CVEs, CWEs, packages, or scanner findings.
- Raw secrets must not be stored, printed, included in prompts, included in
  reports, or returned from APIs.
- Secret-like values are masked before LLM prompts, reports, and task logs.
- RAG references are supporting context only, not scanner evidence.
- v1.0 does not include automatic patching, automatic remediation, production
  server modification, or fine-tuning code.

## Evaluation Docs

- [LLM analysis eval cases](docs/evals/eval_cases.md)
- [Report quality checklist](docs/evals/report-quality-checklist.md)
- [v1.0 scope](docs/product/v1.0-scope.md)

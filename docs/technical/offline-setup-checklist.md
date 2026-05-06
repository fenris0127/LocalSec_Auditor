# Offline Setup Checklist

Use this checklist before running LocalSec Auditor in an environment without
internet access.

## Mode Selection

- [ ] Decide whether the backend will run in offline mode or update mode.
- [ ] Offline mode: set `LOCALSC_OFFLINE_MODE=true`.
- [ ] Update mode: set `LOCALSC_OFFLINE_MODE=false` only while explicit update
  actions are needed.
- [ ] Confirm that update APIs are not expected to work in offline mode.

Offline mode blocks Trivy and Grype DB update APIs. Update mode allows explicit
update commands, but v1.0 does not implement automatic scheduled updates.

## Ollama And Model

- [ ] Install Ollama on the machine running the backend.
- [ ] Pull or import `qwen2.5-coder:7b`, or another approved local base model.
- [ ] Create or import the `localsec-security` Ollama model.
- [ ] Verify the model is available locally before disconnecting from the
  internet.

Example preparation while online:

```bash
ollama pull qwen2.5-coder:7b
ollama create localsec-security -f Modelfile
```

## Scanner Binaries

Install and verify the scanner binaries needed for the scan types you will run.

- [ ] Semgrep installed.
- [ ] Gitleaks installed.
- [ ] Trivy installed.
- [ ] Syft installed.
- [ ] Grype installed.
- [ ] Lynis installed.
- [ ] OpenSCAP `oscap` binary installed.

Suggested version checks:

```bash
semgrep --version
gitleaks version
trivy --version
syft version
grype version
lynis show version
oscap --version
```

## Scanner Databases And Rules

- [ ] Trivy vulnerability DB downloaded before going offline.
- [ ] Grype vulnerability DB downloaded before going offline.
- [ ] Local Semgrep rules prepared.
- [ ] `LOCALSC_SEMGREP_RULES_PATH` points to the local rules directory when a
  custom local rules path is used.
- [ ] The default `rules/semgrep` directory exists if relying on the default
  local rules path.

Example online preparation:

```bash
trivy image --download-db-only
grype db update
```

## OpenSCAP Content And Profile

OpenSCAP support is read-only evaluation only. LocalSec Auditor does not run
remediation.

- [ ] SCAP content file is present locally, for example an SSG datastream XML.
- [ ] `LOCALSEC_SCAP_CONTENT_PATH` points to the SCAP content file, or the
  default path is valid:
  `/usr/share/xml/scap/ssg/content/ssg-ubuntu2204-ds.xml`
- [ ] The selected SCAP content contains the profile used by v1.0:
  `xccdf_org.ssgproject.content_profile_standard`
- [ ] The SCAP content/profile combination was tested in a non-production
  environment.
- [ ] Linux or WSL is available for OpenSCAP and Lynis checks.

Do not use OpenSCAP results as an automatic change plan. Review findings and
validate manually before making operational changes.

## RAG References

- [ ] Source documents are present locally, such as OWASP, CWE, CIS, CCE, KISA,
  or internal security standards.
- [ ] RAG ingestion has been run before going offline.
- [ ] Vector store files are present locally.
- [ ] Retrieval tests or sample finding searches return expected reference
  documents.

RAG references are supporting context only. Scanner output remains the evidence
source.

## Reports And Optional PDF Export

- [ ] Markdown report generation verified.
- [ ] HTML report generation verified.
- [ ] CSV and JSON finding export verified.
- [ ] If PDF export is required, WeasyPrint is installed in the backend Python
  environment.
- [ ] On Windows, required WeasyPrint native dependencies are installed.
- [ ] If PDF dependencies are not available, users know Markdown and HTML reports
  remain the default supported output formats.

PDF export failure returns a clear API error and should not stop the backend
service.

## Final Offline Smoke Check

- [ ] Start the backend with `LOCALSC_OFFLINE_MODE=true`.
- [ ] Start the frontend.
- [ ] Confirm `/api/tools/status` reports expected installed tools.
- [ ] Create a scan using only scanner types available in the offline machine.
- [ ] Confirm findings are stored without raw secret values.
- [ ] Confirm LLM analysis works only when Ollama and `localsec-security` are
  available locally.
- [ ] Generate Markdown or HTML report successfully.

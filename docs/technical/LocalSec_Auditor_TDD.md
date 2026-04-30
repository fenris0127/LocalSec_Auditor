# LocalSec Auditor TDD

## 0. 문서 목적

이 문서는 Codex 같은 AI 코딩 에이전트가 **LocalSec Auditor**를 구현할 때 따라야 하는 기술 설계 문서다. 제품 요구사항은 `LocalSec_Auditor_PRD.md`를 기준으로 한다.

구현 원칙은 다음과 같다.

```text
작게 만든다.
스캐너 결과를 원본 근거로 보존한다.
LLM은 보조 분석기로 제한한다.
Secret 원문을 저장/출력하지 않는다.
각 단계는 테스트 가능해야 한다.
```

---

## 1. 기술 스택

## 1.1 MVP 기술 스택

| 영역 | 기술 |
|---|---|
| Backend | Python 3.11+, FastAPI |
| Frontend | React, Vite, TypeScript, Tailwind CSS, shadcn/ui |
| DB | SQLite |
| ORM | SQLModel 또는 SQLAlchemy |
| Scanner | Trivy, Semgrep, Gitleaks |
| LLM | Ollama |
| 기본 모델 | qwen2.5-coder:7b |
| 커스텀 모델 | localsec-security, Modelfile 기반 |
| Report | Markdown |
| Task | FastAPI BackgroundTasks 또는 간단한 in-process queue |
| Test | pytest, vitest |

## 1.2 풀버전 기술 스택

| 영역 | 기술 |
|---|---|
| Backend | FastAPI |
| Frontend | React/Next.js 가능 |
| DB | PostgreSQL |
| Vector DB | ChromaDB → Qdrant/pgvector |
| Queue | RQ/Celery/Dramatiq |
| Scanner | Syft, Grype, Trivy, Semgrep, Gitleaks, OpenSCAP |
| RAG | bge-m3 또는 nomic-embed-text |
| Report | Markdown, HTML, PDF |
| Optional Training | Unsloth QLoRA, adapter export |

---

## 2. 시스템 아키텍처

## 2.1 MVP 아키텍처

```text
[React Web UI]
      ↓
[FastAPI API]
      ↓
[Mini Hermes Orchestrator]
      ├── Trivy Scanner
      ├── Semgrep Scanner
      └── Gitleaks Scanner
      ↓
[Raw Result Storage]
      ↓
[Normalizer]
      ↓
[SQLite Finding DB]
      ↓
[Risk Engine]
      ↓
[Ollama localsec-security]
      ↓
[Markdown Report]
```

## 2.2 풀버전 아키텍처

```text
[React/Next Web UI]
      ↓
[FastAPI]
      ↓
[Hermes Workflow Engine]
      ├── Task Queue
      ├── Retry Policy
      ├── Tool Registry
      ├── Agent Registry
      └── Memory Store
      ↓
[Scanner Agents]
      ├── Syft
      ├── Grype
      ├── Trivy
      ├── Semgrep
      ├── Gitleaks
      └── OpenSCAP
      ↓
[Normalizer Agents]
      ↓
[Risk Engine]
      ↓
[RAG Retriever]
      ↓
[LLM Analysis Agent]
      ↓
[Report Agent]
```

---

## 3. Repository 구조

MVP 기준 구조다.

```text
localsec-auditor/
├── apps/
│   ├── api/
│   │   ├── main.py
│   │   ├── routes/
│   │   │   ├── scans.py
│   │   │   ├── findings.py
│   │   │   ├── reports.py
│   │   │   └── chat.py
│   │   ├── services/
│   │   └── deps.py
│   └── web/
│       ├── src/
│       │   ├── pages/
│       │   ├── components/
│       │   ├── api/
│       │   └── types/
│       └── package.json
├── core/
│   ├── orchestrator/
│   │   ├── workflow.py
│   │   ├── task_runner.py
│   │   └── status.py
│   ├── scanners/
│   │   ├── base.py
│   │   ├── trivy.py
│   │   ├── semgrep.py
│   │   └── gitleaks.py
│   ├── normalizers/
│   │   ├── trivy.py
│   │   ├── semgrep.py
│   │   └── gitleaks.py
│   ├── risk/
│   │   └── scoring.py
│   ├── llm/
│   │   ├── ollama_client.py
│   │   ├── prompts.py
│   │   └── analysis.py
│   ├── reports/
│   │   └── markdown.py
│   ├── security/
│   │   └── masking.py
│   └── schemas/
│       ├── scan.py
│       ├── task.py
│       └── finding.py
├── data/
│   ├── scans/
│   ├── reports/
│   └── localsec.db
├── docs/
│   ├── PRD.md
│   ├── TDD.md
│   ├── agent-governance.md
│   └── verification-checklist.md
├── tests/
│   ├── unit/
│   ├── integration/
│   └── fixtures/
├── AGENTS.md
├── CLAUDE.md
├── CODEX.md
├── pyproject.toml
└── README.md
```

---

## 4. Backend 설계

## 4.1 FastAPI 엔드포인트

### POST `/api/scans`

스캔 생성 및 실행 요청.

Request:

```json
{
  "project_name": "my-web-app",
  "target_path": "C:/AI/projects/my-web-app",
  "scan_types": ["trivy", "semgrep", "gitleaks"],
  "llm_enabled": true,
  "model": "localsec-security"
}
```

Response:

```json
{
  "scan_id": "scan_001",
  "status": "queued"
}
```

### GET `/api/scans`

최근 scan 목록 조회.

### GET `/api/scans/{scan_id}`

scan 상세와 task 진행률 조회.

### GET `/api/scans/{scan_id}/tasks`

task 상태 목록 조회.

### GET `/api/scans/{scan_id}/findings`

finding 목록 조회.

Query parameters:

- severity
- category
- scanner
- status
- q

### GET `/api/findings/{finding_id}`

finding 상세 조회.

### POST `/api/findings/{finding_id}/analyze`

Ollama 분석 생성 또는 재생성.

### POST `/api/scans/{scan_id}/report`

Markdown 리포트 생성.

### GET `/api/reports/{report_id}`

리포트 조회/다운로드.

---

## 5. DB 설계

## 5.1 SQLite MVP schema

### scans

```sql
CREATE TABLE scans (
  id TEXT PRIMARY KEY,
  project_name TEXT NOT NULL,
  target_path TEXT NOT NULL,
  status TEXT NOT NULL,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL
);
```

### scan_tasks

```sql
CREATE TABLE scan_tasks (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  task_type TEXT NOT NULL,
  tool_name TEXT NOT NULL,
  status TEXT NOT NULL,
  exit_code INTEGER,
  raw_result_path TEXT,
  stdout_path TEXT,
  stderr_path TEXT,
  error_message TEXT,
  started_at TEXT,
  finished_at TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
```

### findings

```sql
CREATE TABLE findings (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  task_id TEXT,
  category TEXT NOT NULL,
  scanner TEXT NOT NULL,
  severity TEXT NOT NULL,
  final_severity TEXT,
  score INTEGER DEFAULT 0,
  title TEXT NOT NULL,
  rule_id TEXT,
  file_path TEXT,
  line INTEGER,
  component_name TEXT,
  component_version TEXT,
  cve TEXT,
  cwe TEXT,
  cce TEXT,
  owasp TEXT,
  evidence TEXT,
  remediation TEXT,
  verification TEXT,
  false_positive_likelihood TEXT,
  llm_summary TEXT,
  status TEXT DEFAULT 'open',
  raw_json_path TEXT,
  created_at TEXT NOT NULL,
  updated_at TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
```

### reports

```sql
CREATE TABLE reports (
  id TEXT PRIMARY KEY,
  scan_id TEXT NOT NULL,
  report_type TEXT NOT NULL,
  format TEXT NOT NULL,
  file_path TEXT NOT NULL,
  created_at TEXT NOT NULL,
  FOREIGN KEY(scan_id) REFERENCES scans(id)
);
```

---

## 6. Scanner Wrapper 설계

## 6.1 공통 인터페이스

```python
class ScanResult:
    scan_id: str
    task_id: str
    tool_name: str
    status: str
    exit_code: int | None
    raw_result_path: str | None
    stdout_path: str | None
    stderr_path: str | None
    error_message: str | None

class Scanner:
    name: str
    def is_available(self) -> bool: ...
    def run(self, target_path: str, output_dir: str) -> ScanResult: ...
```

### 요구사항

- shell=True 사용 금지
- subprocess 인자는 list로 전달
- timeout 지원
- stdout/stderr 파일 저장
- exit code 저장
- 실패 시 exception을 삼키지 말고 task에 기록

## 6.2 Trivy Wrapper

Command:

```bash
trivy fs <target_path> --format json --output <raw_result_path>
```

Implementation requirement:

- `trivy` executable 존재 확인
- target path 존재 확인
- output path 생성
- JSON 파일 존재 여부 확인

## 6.3 Semgrep Wrapper

Command:

```bash
semgrep scan --config auto <target_path> --json --output <raw_result_path>
```

Implementation requirement:

- semgrep 미설치 시 task failed
- JSON parse 실패 시 raw 저장 후 normalize skipped

## 6.4 Gitleaks Wrapper

Command:

```bash
gitleaks detect --source <target_path> --report-format json --report-path <raw_result_path> --no-banner
```

Implementation requirement:

- raw 결과 저장 전/후 Secret 마스킹 정책 적용
- UI/DB에는 마스킹된 evidence만 저장

---

## 7. Normalizer 설계

## 7.1 공통 출력

모든 normalizer는 `FindingCreate` list를 반환한다.

```python
class FindingCreate(BaseModel):
    category: Literal['cve', 'sast', 'secret', 'config', 'iac']
    scanner: str
    severity: str
    title: str
    rule_id: str | None = None
    file_path: str | None = None
    line: int | None = None
    component_name: str | None = None
    component_version: str | None = None
    cve: str | None = None
    cwe: str | None = None
    cce: str | None = None
    owasp: str | None = None
    evidence: str | None = None
    raw_json_path: str
```

## 7.2 Semgrep Normalizer

Input path: Semgrep JSON.

Mapping:

| Semgrep field | Finding field |
|---|---|
| `check_id` | `rule_id` |
| `path` | `file_path` |
| `start.line` | `line` |
| `extra.severity` | `severity` |
| `extra.message` | `title` |
| `extra.metadata.cwe` | `cwe` |
| `extra.metadata.owasp` | `owasp` |

## 7.3 Trivy Normalizer

Mapping:

| Trivy field | Finding field |
|---|---|
| `VulnerabilityID` | `cve` |
| `PkgName` | `component_name` |
| `InstalledVersion` | `component_version` |
| `Severity` | `severity` |
| `Title` | `title` |
| `FixedVersion` | `remediation` |

## 7.4 Gitleaks Normalizer

Mapping:

| Gitleaks field | Finding field |
|---|---|
| `RuleID` | `rule_id` |
| `File` | `file_path` |
| `StartLine` | `line` |
| `Description` | `title` |
| `Secret` | masked evidence only |

Security requirement:

- Secret value must be masked before DB insert.
- raw path for unmasked output should not be served to UI.
- Prefer storing masked raw JSON.

---

## 8. Secret Masking 설계

## 8.1 Masking function

```python
def mask_secret(value: str) -> str:
    if not value:
        return value
    if len(value) <= 8:
        return "****"
    return value[:4] + "..." + value[-4:]
```

## 8.2 Requirements

- DB insert 전 masking
- LLM prompt 생성 전 masking
- report 생성 전 masking
- log 출력 전 masking
- Gitleaks raw result는 masked copy를 기본 사용

---

## 9. Risk Engine 설계

## 9.1 MVP Scoring

```python
BASE = {
  'critical': 90,
  'high': 75,
  'medium': 50,
  'low': 25,
  'info': 5,
}
```

Adjustment:

- category secret: +15
- category sast and severity high: +10
- fixed version exists: +5
- file path contains test: -15
- status false_positive: score 0

Final severity:

| Score | Severity |
|---:|---|
| 90+ | critical |
| 70-89 | high |
| 40-69 | medium |
| 10-39 | low |
| 0-9 | info |

## 9.2 풀버전 Scoring

Add:

- CVSS
- EPSS
- CISA KEV
- internet exposure
- asset criticality
- exploitability
- runtime reachability
- compensating control

---

## 10. Ollama Client 설계

## 10.1 Configuration

```text
OLLAMA_BASE_URL=http://localhost:11434
OLLAMA_MODEL=localsec-security
```

## 10.2 API usage

Use Ollama HTTP API.

Request fields:

- model
- messages or prompt
- stream false
- options: temperature, top_p, num_ctx

## 10.3 Prompt Template

### SAST Analysis Prompt

```text
너는 로컬 보안 진단 서비스의 보안 분석 보조 모델이다.
아래 scanner 결과만 근거로 한국어 분석을 작성하라.

규칙:
- 입력에 없는 취약점을 만들지 않는다.
- 공격용 exploit/payload를 작성하지 않는다.
- 오탐은 확정하지 않고 가능성으로 표현한다.
- Secret 원문을 출력하지 않는다.

입력:
{finding_json}

출력 형식:
1. 취약점 설명
2. 위험한 이유
3. 수정 방법
4. 검증 방법
5. 오탐 가능성
```

### CVE Analysis Prompt

```text
입력된 CVE/패키지 정보만 근거로 분석하라.
CVE ID가 입력에 없으면 새 CVE를 만들지 마라.
fixed_version이 있으면 조치 방법에 포함하라.
```

### Secret Analysis Prompt

```text
Secret 원문은 절대 출력하지 마라.
폐기, 재발급, git history 정리, Secret Manager 사용을 우선 제안하라.
```

## 10.4 Output Storage

- full LLM response 저장
- parsing 실패 시 plain text로 저장
- 추후 JSON structured output 지원

---

## 11. Report Generator 설계

## 11.1 MVP Markdown structure

```markdown
# LocalSec Auditor Report

## 1. Summary

## 2. Severity Statistics

## 3. Priority Top 10

## 4. CVE Findings

## 5. SAST Findings

## 6. Secret Findings

## 7. Recommended Next Actions

## 8. Appendix
```

## 11.2 Requirements

- Secret 원문 출력 금지
- scanner 원본 근거와 LLM 해석 구분
- failed task 목록 포함
- generated timestamp 포함

---

## 12. Frontend 설계

## 12.1 Page Routes

| Route | Page |
|---|---|
| `/` | Dashboard |
| `/scans/new` | New Scan |
| `/scans/:scanId` | Scan Detail |
| `/scans/:scanId/findings` | Finding List |
| `/findings/:findingId` | Finding Detail |
| `/reports/:reportId` | Report View |

## 12.2 Components

- SeverityBadge
- CategoryBadge
- FindingTable
- ScanProgress
- TaskStatusList
- CodeSnippet
- LlmAnalysisPanel
- ReportPreview

## 12.3 API Client

Typed functions:

- createScan
- getScans
- getScan
- getScanTasks
- getFindings
- getFinding
- analyzeFinding
- createReport

---

## 13. Hermes Orchestrator 상세

## 13.1 MVP Workflow

```python
def run_scan(scan_id: str):
    create_task('trivy')
    create_task('semgrep')
    create_task('gitleaks')

    for task in tasks:
        run_scanner(task)

    normalize_all(scan_id)
    score_findings(scan_id)
    analyze_high_priority_findings(scan_id)
    mark_scan_completed(scan_id)
```

## 13.2 Dependency Rules

MVP:

- Trivy, Semgrep, Gitleaks can run independently.
- normalize runs after scanner tasks finish.
- risk runs after normalize.
- LLM analysis runs after risk.
- report runs on demand.

풀버전:

- Grype depends on Syft SBOM.
- OpenSCAP depends on OS/profile detection.
- RAG retrieval depends on finding classification.

---

## 14. Error Handling

## 14.1 Scanner Missing

If executable not found:

- task status: failed
- error_message: `{tool} not found`
- scan continues with other tools

## 14.2 Invalid Target Path

If target path does not exist:

- scan creation fails with 400

## 14.3 JSON Parse Error

If raw JSON parse fails:

- raw file remains saved
- normalizer task failed
- UI displays parse error

## 14.4 Ollama Error

If Ollama unavailable:

- finding remains without llm_summary
- UI shows `AI analysis unavailable`
- report still generates using scanner data

---

## 15. Testing Plan

## 15.1 Unit Tests

### Scanner tests

- `test_semgrep_command_builds_without_shell_true`
- `test_trivy_missing_executable_returns_failed_task`
- `test_gitleaks_output_path_created`

### Normalizer tests

- `test_semgrep_json_to_finding`
- `test_trivy_vulnerability_to_cve_finding`
- `test_gitleaks_secret_is_masked`

### Risk tests

- `test_high_secret_becomes_critical`
- `test_test_file_reduces_score`
- `test_false_positive_score_zero`

### LLM prompt tests

- `test_prompt_does_not_include_unmasked_secret`
- `test_sast_prompt_contains_required_output_format`
- `test_cve_prompt_forbids_new_cve_generation`

### Report tests

- `test_markdown_report_created`
- `test_report_excludes_raw_secret`
- `test_failed_tasks_included_in_report`

## 15.2 Integration Tests

### MVP integration

- sample vulnerable project scan
- raw JSON files created
- findings saved to DB
- dashboard API returns counts
- report generated

### Ollama integration, optional

- if Ollama running, finding analysis returns non-empty text
- if Ollama down, graceful failure

## 15.3 Frontend Tests

- Dashboard renders scan stats
- Finding table filters severity
- Finding detail shows LLM summary
- Scan progress displays failed task

---

## 16. Fixtures

Test fixtures should include:

```text
tests/fixtures/
├── semgrep-result.json
├── trivy-result.json
├── gitleaks-result.json
├── sample-project/
│   ├── src/user.py
│   ├── package-lock.json
│   └── .env.example
└── reports/
```

### Fixture Security

- No real Secret
- Use fake values like `sk_test_****FAKE`
- Never commit real tokens

---

## 17. Codex Implementation Rules

Codex must follow these rules.

## 17.1 Think Before Coding

Before editing files, Codex should state:

- goal
- files to edit
- files not to edit
- assumptions
- verification steps

## 17.2 Simplicity First

MVP must not introduce:

- Redis
- Celery
- PostgreSQL
- auth system
- plugin architecture
- Kubernetes
- cloud sync
- fine-tuning pipeline

unless explicitly requested.

## 17.3 Surgical Changes

- Do not reformat unrelated files.
- Do not rewrite architecture without request.
- Do not remove comments without reason.
- Keep changes small.

## 17.4 Goal-Driven Execution

Each task must end with:

- what changed
- how tested
- remaining risk

---

## 18. Codex Task Breakdown

Use these tasks in order.

### Task 1. Backend skeleton

Goal:

- FastAPI app starts.
- `/health` returns ok.

Acceptance:

- `pytest` passes.
- `uvicorn apps.api.main:app` starts.

### Task 2. DB schema

Goal:

- scans, scan_tasks, findings, reports tables.

Acceptance:

- migration or init script creates SQLite DB.
- unit test inserts and reads scan.

### Task 3. Semgrep wrapper

Goal:

- Run Semgrep and save JSON.

Acceptance:

- sample project generates raw JSON.
- failure is recorded.

### Task 4. Semgrep normalizer

Goal:

- Convert Semgrep JSON into Finding rows.

Acceptance:

- fixture JSON creates expected finding.

### Task 5. Web scan creation

Goal:

- UI can create scan.

Acceptance:

- form calls POST `/api/scans`.
- scan appears in list.

### Task 6. Trivy wrapper/normalizer

Goal:

- Add CVE scan.

Acceptance:

- fixture converts vulnerability to cve finding.

### Task 7. Gitleaks wrapper/normalizer

Goal:

- Add Secret scan.

Acceptance:

- Secret value is masked in DB and UI.

### Task 8. Risk Engine

Goal:

- Assign score and final severity.

Acceptance:

- tests pass for severity mapping.

### Task 9. Ollama client

Goal:

- Call localsec-security.

Acceptance:

- mock Ollama test passes.
- unavailable Ollama does not crash scan.

### Task 10. Report generator

Goal:

- Generate Markdown report.

Acceptance:

- report file exists.
- no unmasked secrets.

---

## 19. 풀버전 확장 설계

## 19.1 Syft/Grype

Add:

- `syft.py`
- `grype.py`
- `sbom` table
- grype depends on syft output

## 19.2 OpenSCAP

Add:

- profile detection
- XCCDF parser
- CCE/CIS mapping
- remediation/rollback prompt

## 19.3 RAG

Add:

- document loader
- chunker
- embedding model
- vector DB
- retrieval by CWE/CVE/CCE/keywords

## 19.4 Scan Compare

Add:

- finding fingerprint
- previous scan lookup
- new/resolved/existing classification

## 19.5 PR Review

Add:

- diff parser
- changed file scanner
- PR comment draft generator

## 19.6 Optional Fine-tuning

Fine-tuning is not part of MVP. If used later:

- Use real LocalSec scan-result → approved report data.
- Use QLoRA with Unsloth.
- Export LoRA adapter or GGUF.
- Compare against Modelfile baseline before adoption.

---

## 20. Deployment

## 20.1 MVP local run

Backend:

```bash
uvicorn apps.api.main:app --reload
```

Frontend:

```bash
cd apps/web
npm install
npm run dev
```

Ollama:

```bash
ollama pull qwen2.5-coder:7b
ollama create localsec-security -f Modelfile
```

Scanners:

- install Trivy
- install Semgrep
- install Gitleaks

## 20.2 Windows notes

- Avoid Korean/non-ASCII paths for cache and datasets.
- Prefer workspace under `C:\AI\workspace`.
- Store data under `C:\AI\localsec\data`.

---

## 21. Non-functional Requirements

### Performance

- MVP scan should complete within reasonable time for small projects.
- LLM auto-analysis should be limited to Critical/High by default.

### Reliability

- One scanner failure should not destroy all scan results.
- Raw results should remain available for debugging.

### Security

- No Secret raw value in DB/UI/report/LLM prompt.
- No automatic patch application.
- No exploit code generation.

### Maintainability

- Scanner wrappers must be independent.
- Normalizers must be testable from fixtures.
- Prompt templates must be centralized.

---

## 22. Done Definition

A feature is done only when:

1. Implementation exists.
2. Unit tests pass.
3. Integration path works with fixture or sample project.
4. UI displays expected state if relevant.
5. No unmasked Secret is stored or shown.
6. Codex change summary includes verification result.

---

## 23. Technical Summary

LocalSec Auditor should be built as:

```text
scanner wrappers
+ raw result storage
+ normalizers
+ risk engine
+ Ollama analysis harness
+ Hermes-style orchestration
+ React dashboard
```

Do not start with fine-tuning, complex agent autonomy, or cloud dependencies. Build a deterministic local pipeline first, then extend.

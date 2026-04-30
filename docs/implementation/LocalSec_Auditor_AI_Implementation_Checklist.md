# LocalSec Auditor — AI 구현 체크리스트

이 문서는 Codex, Claude Code, Cursor, Gemini CLI 같은 AI 코딩 에이전트가 **작은 단위로 확인하면서 구현**할 수 있도록 만든 작업 분해 문서다.

목표는 한 번에 전체 서비스를 만들지 않는 것이다.

원칙:

```text
1. 한 번에 하나의 기능만 구현한다.
2. 구현 전 수정할 파일과 검증 방법을 먼저 말하게 한다.
3. 구현 후 반드시 실행 명령과 결과를 확인한다.
4. 다음 단계로 넘어가기 전에 체크박스를 완료한다.
5. 실패하면 새 기능을 만들지 말고 실패 원인을 먼저 고친다.
```

---

## 0. 프로젝트 전체 목표

LocalSec Auditor는 로컬에서 보안 스캐너를 실행하고, 그 결과를 Ollama 기반 LLM이 한국어로 설명하는 Web UI 서비스다.

MVP 범위:

```text
Frontend: React + Vite + TypeScript
Backend: FastAPI
DB: SQLite
LLM: Ollama + localsec-security
Scanner:
- Semgrep
- Gitleaks
- Trivy

나중에:
- Syft
- Grype
- OpenSCAP
- RAG
- PDF Report
```

---

## 1. Codex 작업 방식

Codex에게는 항상 아래 형식으로 지시한다.

```text
이번 작업 목표:
- 하나의 작은 기능만 구현

수정 허용 파일:
- 명시한 파일만 수정

금지:
- 요청하지 않은 리팩터링 금지
- 새 라이브러리 임의 추가 금지
- 인증/권한/배포 기능 추가 금지
- 기존 구조 대규모 변경 금지

완료 조건:
- 실행 가능한 명령 제시
- 테스트 또는 수동 검증 방법 제시
- 변경 요약 제시
```

---

## 2. 구현 단계 요약

| 단계 | 목표 | 완료 기준 |
|---|---|---|
| 1 | 프로젝트 뼈대 생성 | backend/frontend 실행 가능 |
| 2 | FastAPI 기본 API | `/health` 정상 응답 |
| 3 | SQLite 모델 | scans, scan_tasks, findings 테이블 생성 |
| 4 | Ollama 연결 | 모델 호출 테스트 성공 |
| 5 | Scanner Wrapper | Semgrep/Gitleaks/Trivy 실행 가능 |
| 6 | Raw Result 저장 | 스캐너 JSON이 파일로 저장됨 |
| 7 | Normalizer | 공통 Finding 구조 생성 |
| 8 | Hermes Orchestrator | scan task 순서 실행 |
| 9 | LLM Analysis | finding 설명 생성 |
| 10 | Report Generator | Markdown 리포트 생성 |
| 11 | Web UI | 스캔 실행/결과 조회 |
| 12 | 안정화 | 에러 처리, 로그, 테스트 |

---

# Phase 1. 프로젝트 뼈대

## 1-1. 레포지토리 구조 생성

### 목표

아래 구조를 만든다.

```text
localsec-auditor/
├── backend/
│   ├── app/
│   │   ├── main.py
│   │   ├── api/
│   │   ├── core/
│   │   ├── db/
│   │   ├── scanners/
│   │   ├── normalizers/
│   │   ├── orchestrator/
│   │   ├── llm/
│   │   └── reports/
│   ├── tests/
│   └── pyproject.toml
├── frontend/
│   └── ...
├── data/
│   ├── scans/
│   ├── reports/
│   └── raw/
├── docs/
└── README.md
```

### Codex 지시문

```text
프로젝트의 기본 폴더 구조를 만들어줘.

조건:
- backend는 FastAPI 기반으로 구성
- frontend는 아직 실제 구현하지 말고 폴더만 준비
- data/scans, data/reports, data/raw 폴더 생성
- README.md에 프로젝트 목적과 실행 계획을 간단히 작성
- 아직 scanner, DB, LLM 구현은 하지 마

완료 후:
- 생성한 파일 목록을 보여줘
```

### 완료 체크

- [ ] 폴더 구조 생성됨
- [ ] README.md 생성됨
- [ ] 불필요한 기능 없음

---

## 1-2. FastAPI 기본 서버 생성

### 목표

`/health` API를 만든다.

### Codex 지시문

```text
backend에 FastAPI 기본 서버를 만들어줘.

요구사항:
- app/main.py 생성
- GET /health 구현
- 응답: {"status": "ok"}
- uvicorn 실행 방법을 README에 추가
- 다른 기능은 만들지 마

검증:
- uvicorn app.main:app --reload
- curl http://localhost:8000/health
```

### 완료 체크

- [ ] 서버 실행 가능
- [ ] `/health` 응답 정상
- [ ] README에 실행 방법 추가

---

# Phase 2. SQLite 데이터 모델

## 2-1. DB 연결 생성

### 목표

SQLite DB 연결을 만든다.

### Codex 지시문

```text
FastAPI backend에 SQLite 연결 레이어를 추가해줘.

요구사항:
- SQLModel 또는 SQLAlchemy 중 하나만 사용
- 기본 DB 경로: data/localsec.db
- DB 세션 의존성 함수 생성
- 아직 테이블은 최소만 만들기
- 새 라이브러리가 필요하면 먼저 pyproject.toml에 명시

검증:
- 앱 시작 시 DB 파일이 생성되는지 확인
```

### 완료 체크

- [ ] DB 연결 코드 존재
- [ ] DB 파일 생성 가능
- [ ] 경로가 하드코딩 난잡하지 않음

---

## 2-2. scans 테이블 생성

### 목표

스캔 실행 단위를 저장한다.

### 스키마

```text
scans
- id: str
- project_name: str
- target_path: str
- status: str
- started_at: datetime nullable
- finished_at: datetime nullable
- created_at: datetime
```

### Codex 지시문

```text
scans 테이블 모델과 기본 CRUD를 만들어줘.

요구사항:
- Scan 모델 생성
- create_scan 함수 생성
- get_scan 함수 생성
- list_scans 함수 생성
- POST /api/scans는 아직 만들지 마
- 단위 테스트 1개 추가

완료 조건:
- 테스트에서 scan 생성 후 조회 가능
```

### 완료 체크

- [ ] Scan 모델 있음
- [ ] CRUD 있음
- [ ] 테스트 통과

---

## 2-3. scan_tasks 테이블 생성

### 목표

Hermes Orchestrator가 각 단계 상태를 관리하게 한다.

### 스키마

```text
scan_tasks
- id: str
- scan_id: str
- task_type: str
- tool_name: str nullable
- status: str
- started_at: datetime nullable
- finished_at: datetime nullable
- error_message: str nullable
```

### Codex 지시문

```text
scan_tasks 모델과 CRUD를 추가해줘.

요구사항:
- ScanTask 모델 생성
- create_task, update_task_status, list_tasks_by_scan 함수 생성
- scan_id로 연결
- 테스트 추가
- 기존 Scan 모델은 필요 최소한만 수정

완료 조건:
- scan 생성 후 task 여러 개 생성 가능
- task 상태 업데이트 가능
```

### 완료 체크

- [ ] ScanTask 모델 있음
- [ ] 상태 업데이트 가능
- [ ] 테스트 통과

---

## 2-4. findings 테이블 생성

### 목표

정규화된 보안 진단 결과를 저장한다.

### 스키마

```text
findings
- id: str
- scan_id: str
- category: str
- scanner: str
- severity: str
- title: str
- file_path: str nullable
- line: int nullable
- component: str nullable
- cve: str nullable
- cwe: str nullable
- raw_json_path: str nullable
- llm_summary: str nullable
- status: str
```

### Codex 지시문

```text
findings 모델과 CRUD를 추가해줘.

요구사항:
- Finding 모델 생성
- create_finding
- list_findings_by_scan
- get_finding
- update_finding_llm_summary
- 테스트 추가

완료 조건:
- scan에 finding 여러 개 저장 가능
- finding 조회 가능
```

### 완료 체크

- [ ] Finding 모델 있음
- [ ] CRUD 있음
- [ ] 테스트 통과

---

# Phase 3. API 기본 구현

## 3-1. Scan 생성 API

### 목표

Web UI에서 스캔 요청을 생성할 수 있게 한다.

### API

```http
POST /api/scans
```

Request:

```json
{
  "project_name": "demo",
  "target_path": "C:/AI/projects/demo",
  "scan_types": ["semgrep", "gitleaks", "trivy"],
  "llm_enabled": true
}
```

Response:

```json
{
  "scan_id": "...",
  "status": "queued"
}
```

### Codex 지시문

```text
POST /api/scans API를 구현해줘.

요구사항:
- 요청 body 검증
- Scan 생성
- 선택된 scan_types에 대해 ScanTask 생성
- 실제 scanner 실행은 하지 말 것
- status는 queued
- 테스트 추가

완료 조건:
- API 호출 시 scan과 task가 DB에 저장됨
```

### 완료 체크

- [ ] POST /api/scans 동작
- [ ] task 생성됨
- [ ] 테스트 통과

---

## 3-2. Scan 조회 API

### 목표

스캔 상태와 태스크 상태를 조회한다.

### API

```http
GET /api/scans/{scan_id}
GET /api/scans
GET /api/scans/{scan_id}/tasks
```

### Codex 지시문

```text
Scan 조회 API를 구현해줘.

요구사항:
- GET /api/scans
- GET /api/scans/{scan_id}
- GET /api/scans/{scan_id}/tasks
- 없는 scan_id는 404
- 테스트 추가

완료 조건:
- 생성한 scan과 task 조회 가능
```

### 완료 체크

- [ ] 스캔 목록 조회 가능
- [ ] 개별 스캔 조회 가능
- [ ] 태스크 조회 가능
- [ ] 404 처리 있음

---

# Phase 4. Scanner Wrapper

## 4-1. 공통 scanner 실행 유틸

### 목표

외부 명령 실행을 안전하게 관리한다.

### Codex 지시문

```text
외부 scanner 명령을 실행하는 공통 유틸을 만들어줘.

요구사항:
- subprocess.run 사용
- timeout 지원
- stdout, stderr, exit_code 반환
- shell=True 사용 금지
- 실행 실패 시 예외가 아니라 결과 객체로 반환
- 테스트 추가

금지:
- 실제 scanner 실행 테스트는 하지 마
- mock으로 테스트

완료 조건:
- 명령 실행 결과 객체가 반환됨
```

### 완료 체크

- [ ] shell=True 사용 안 함
- [ ] timeout 있음
- [ ] exit_code 저장
- [ ] mock 테스트 있음

---

## 4-2. Semgrep Wrapper

### 목표

Semgrep을 실행하고 JSON 결과를 저장한다.

### 명령 예시

```bash
semgrep scan --config auto <target_path> --json
```

### Codex 지시문

```text
Semgrep scanner wrapper를 구현해줘.

요구사항:
- run_semgrep(target_path, output_path) 함수
- semgrep scan --config auto target_path --json 실행
- stdout을 output_path에 저장
- 실패해도 stderr와 exit_code 기록
- shell=True 금지
- 테스트는 subprocess mock 사용

완료 조건:
- Semgrep 명령 인자가 올바르게 구성됨
- JSON output 저장 로직 있음
```

### 완료 체크

- [ ] Semgrep wrapper 있음
- [ ] output_path 저장
- [ ] mock 테스트 통과

---

## 4-3. Gitleaks Wrapper

### 목표

Secret 탐지 결과를 JSON으로 저장한다.

### 명령 예시

```bash
gitleaks detect --source <target_path> --report-format json --report-path <output_path>
```

### Codex 지시문

```text
Gitleaks scanner wrapper를 구현해줘.

요구사항:
- run_gitleaks(target_path, output_path)
- report-format json 사용
- report-path output_path 사용
- exit code와 stderr 기록
- Secret 원문은 wrapper에서 출력 로그에 남기지 않도록 주의
- 테스트는 subprocess mock 사용

완료 조건:
- Gitleaks 명령 인자가 올바르게 구성됨
```

### 완료 체크

- [ ] Gitleaks wrapper 있음
- [ ] report-path 사용
- [ ] Secret 로그 출력 없음

---

## 4-4. Trivy Wrapper

### 목표

Trivy 파일시스템 스캔을 실행한다.

### 명령 예시

```bash
trivy fs <target_path> --format json --output <output_path>
```

### Codex 지시문

```text
Trivy filesystem scanner wrapper를 구현해줘.

요구사항:
- run_trivy_fs(target_path, output_path)
- trivy fs target_path --format json --output output_path
- exit code와 stderr 기록
- 테스트는 subprocess mock 사용

완료 조건:
- Trivy 명령 인자가 올바르게 구성됨
```

### 완료 체크

- [ ] Trivy wrapper 있음
- [ ] JSON output 저장
- [ ] mock 테스트 통과

---

# Phase 5. Raw Result 저장 구조

## 5-1. scan별 raw 디렉터리 생성

### 목표

스캔 결과를 파일로 보존한다.

### 경로

```text
data/scans/{scan_id}/raw/
data/scans/{scan_id}/normalized/
data/scans/{scan_id}/reports/
```

### Codex 지시문

```text
scan_id별 결과 디렉터리 생성 유틸을 만들어줘.

요구사항:
- create_scan_dirs(scan_id)
- raw, normalized, reports 폴더 생성
- 경로 반환 객체 생성
- 테스트 추가

완료 조건:
- scan_id로 폴더 3개 생성됨
```

### 완료 체크

- [ ] raw 폴더 생성
- [ ] normalized 폴더 생성
- [ ] reports 폴더 생성
- [ ] 테스트 통과

---

# Phase 6. Normalizer

## 6-1. Semgrep Normalizer

### 목표

Semgrep JSON을 Finding으로 변환한다.

### Codex 지시문

```text
Semgrep JSON normalizer를 구현해줘.

요구사항:
- normalize_semgrep(raw_json_path, scan_id) -> list[FindingCreate]
- check_id, path, start.line, extra.severity, extra.message 추출
- category는 "sast"
- scanner는 "semgrep"
- severity 매핑: ERROR/HIGH → high, WARNING/MEDIUM → medium, INFO → low
- raw_json_path 저장
- 테스트용 sample JSON 추가

완료 조건:
- sample Semgrep JSON에서 Finding 1개 이상 생성
```

### 완료 체크

- [ ] Semgrep normalizer 있음
- [ ] severity 매핑 있음
- [ ] 테스트 통과

---

## 6-2. Gitleaks Normalizer

### 목표

Gitleaks JSON을 Finding으로 변환하되 Secret 원문은 저장하지 않는다.

### Codex 지시문

```text
Gitleaks JSON normalizer를 구현해줘.

요구사항:
- normalize_gitleaks(raw_json_path, scan_id) -> list[FindingCreate]
- category는 "secret"
- scanner는 "gitleaks"
- File, StartLine, RuleID 추출
- Secret 필드는 저장하지 않음
- title은 "Secret detected: {RuleID}"
- severity는 high
- 테스트용 sample JSON 추가

금지:
- Secret 원문을 Finding에 저장하지 마
- 로그에도 출력하지 마

완료 조건:
- Secret 원문 없이 Finding 생성
```

### 완료 체크

- [ ] Secret 원문 저장 안 함
- [ ] Gitleaks normalizer 있음
- [ ] 테스트 통과

---

## 6-3. Trivy Normalizer

### 목표

Trivy JSON에서 취약점 Finding을 추출한다.

### Codex 지시문

```text
Trivy JSON normalizer를 구현해줘.

요구사항:
- normalize_trivy(raw_json_path, scan_id) -> list[FindingCreate]
- Results[].Vulnerabilities[] 순회
- VulnerabilityID를 cve에 저장
- PkgName을 component에 저장
- Severity를 severity로 매핑
- FixedVersion이 있으면 title 또는 metadata에 포함
- category는 "cve"
- scanner는 "trivy"
- 테스트용 sample JSON 추가

완료 조건:
- sample Trivy JSON에서 CVE Finding 생성
```

### 완료 체크

- [ ] Trivy normalizer 있음
- [ ] CVE 추출 가능
- [ ] component 추출 가능
- [ ] 테스트 통과

---

# Phase 7. Hermes Orchestrator MVP

## 7-1. 순차 실행 오케스트레이터

### 목표

스캔 태스크를 순서대로 실행한다.

### Codex 지시문

```text
Hermes Orchestrator MVP를 구현해줘.

요구사항:
- run_scan(scan_id) 함수
- scan에 연결된 task 목록 조회
- task_type/tool_name에 따라 scanner wrapper 실행
- 각 task 상태를 queued → running → completed/failed로 변경
- raw 결과 저장
- scanner 실행 후 normalizer 실행
- finding DB 저장
- 실패한 task는 error_message 저장
- 전체 scan status 업데이트

제한:
- Celery/RQ 같은 큐는 아직 쓰지 마
- 백그라운드 실행은 아직 하지 마
- 순차 실행만 구현

완료 조건:
- semgrep/gitleaks/trivy task를 순서대로 실행하는 흐름이 있음
```

### 완료 체크

- [ ] task 상태 변경됨
- [ ] raw 결과 저장됨
- [ ] normalizer 호출됨
- [ ] findings 저장됨
- [ ] 실패 처리 있음

---

## 7-2. Scan 실행 API 연결

### 목표

POST /api/scans 호출 후 스캔을 실행할 수 있게 한다.

### Codex 지시문

```text
POST /api/scans에 스캔 실행 옵션을 연결해줘.

요구사항:
- 요청 body에 run_immediately boolean 추가
- run_immediately=true면 run_scan(scan_id) 호출
- MVP에서는 동기 실행 허용
- 응답에 최종 status 포함
- 긴 실행은 나중에 백그라운드로 전환한다고 TODO 주석 추가

완료 조건:
- API 호출로 scanner 실행 흐름이 시작됨
```

### 완료 체크

- [ ] run_immediately 지원
- [ ] run_scan 연결됨
- [ ] 응답 status 정상

---

# Phase 8. Ollama / LLM Harness

## 8-1. Ollama Client

### 목표

FastAPI backend에서 Ollama 모델을 호출한다.

### Codex 지시문

```text
Ollama client를 구현해줘.

요구사항:
- OLLAMA_BASE_URL 기본값: http://localhost:11434
- model 기본값: localsec-security
- generate(prompt) 함수 구현
- requests 또는 httpx 사용
- timeout 설정
- 에러 처리
- 테스트는 HTTP mock 사용

완료 조건:
- Ollama /api/generate 호출 구조 구현
```

### 완료 체크

- [ ] Ollama base URL 설정 가능
- [ ] model 설정 가능
- [ ] timeout 있음
- [ ] mock 테스트 통과

---

## 8-2. Finding 분석 프롬프트 템플릿

### 목표

Finding을 LLM에 안전하게 전달한다.

### Codex 지시문

```text
Finding 분석용 프롬프트 템플릿을 만들어줘.

요구사항:
- build_finding_analysis_prompt(finding) 함수
- scanner, category, severity, title, file_path, line, component, cve, cwe 포함
- Secret category에서는 Secret 원문이 없다는 점 명시
- 출력 형식을 고정:
  1. 요약
  2. 위험한 이유
  3. 조치 방법
  4. 검증 방법
  5. 오탐 가능성
- 입력에 없는 CVE를 만들지 말라는 규칙 포함

완료 조건:
- Finding 하나로 프롬프트 문자열 생성
```

### 완료 체크

- [ ] 프롬프트 템플릿 있음
- [ ] 출력 형식 고정
- [ ] Secret 안전 규칙 포함

---

## 8-3. LLM 분석 API

### 목표

Finding 하나에 대해 AI 분석을 생성한다.

### API

```http
POST /api/findings/{finding_id}/analyze
```

### Codex 지시문

```text
Finding LLM 분석 API를 구현해줘.

요구사항:
- POST /api/findings/{finding_id}/analyze
- finding 조회
- prompt 생성
- Ollama 호출
- llm_summary에 저장
- 응답으로 llm_summary 반환
- Ollama 실패 시 502 또는 명확한 에러 반환
- 테스트는 Ollama mock 사용

완료 조건:
- finding에 LLM 분석 결과 저장 가능
```

### 완료 체크

- [ ] analyze API 있음
- [ ] llm_summary 저장됨
- [ ] Ollama 실패 처리 있음

---

# Phase 9. Report Generator

## 9-1. Markdown 리포트 생성

### 목표

Scan 결과를 Markdown 보고서로 저장한다.

### Codex 지시문

```text
Markdown report generator를 구현해줘.

요구사항:
- generate_markdown_report(scan_id) 함수
- scan 정보, finding 통계, severity별 목록 포함
- llm_summary가 있으면 상세에 포함
- Secret 원문은 포함하지 않음
- data/scans/{scan_id}/reports/report.md 저장
- 테스트 추가

완료 조건:
- report.md 생성됨
```

### 완료 체크

- [ ] report.md 생성
- [ ] finding 통계 있음
- [ ] Secret 원문 없음
- [ ] 테스트 통과

---

## 9-2. Report API

### 목표

Web UI에서 리포트를 생성/조회할 수 있게 한다.

### API

```http
POST /api/scans/{scan_id}/report
GET /api/scans/{scan_id}/report
```

### Codex 지시문

```text
Report API를 구현해줘.

요구사항:
- POST /api/scans/{scan_id}/report: Markdown 생성
- GET /api/scans/{scan_id}/report: Markdown 내용 반환
- 없는 report는 404
- 테스트 추가

완료 조건:
- API로 report 생성과 조회 가능
```

### 완료 체크

- [ ] report 생성 API
- [ ] report 조회 API
- [ ] 404 처리

---

# Phase 10. Frontend MVP

## 10-1. React/Vite 기본 UI

### 목표

Frontend 앱을 생성한다.

### Codex 지시문

```text
frontend에 React + Vite + TypeScript 앱을 생성해줘.

요구사항:
- Dashboard, NewScan, ScanDetail 페이지를 위한 기본 라우팅
- API base URL 설정 파일
- 디자인은 단순하게
- shadcn/ui는 아직 추가하지 마

완료 조건:
- npm install 후 npm run dev 가능
```

### 완료 체크

- [ ] React 앱 실행 가능
- [ ] 기본 라우팅 있음
- [ ] 불필요한 UI 라이브러리 없음

---

## 10-2. Scan 생성 화면

### 목표

사용자가 스캔을 생성한다.

### Codex 지시문

```text
NewScan 페이지를 구현해줘.

요구사항:
- project_name 입력
- target_path 입력
- scan_types 체크박스: semgrep, gitleaks, trivy
- run_immediately 체크박스
- POST /api/scans 호출
- 결과 scan_id 표시
- 에러 표시

완료 조건:
- UI에서 scan 생성 가능
```

### 완료 체크

- [ ] 입력 폼 있음
- [ ] API 호출됨
- [ ] 결과 표시됨

---

## 10-3. Scan 목록/상세 화면

### 목표

스캔 상태와 finding을 조회한다.

### Codex 지시문

```text
Dashboard와 ScanDetail 페이지를 구현해줘.

요구사항:
- Dashboard: GET /api/scans로 스캔 목록 표시
- ScanDetail: scan 정보, task 목록, finding 목록 표시
- severity, category, title, scanner, file_path 표시
- 상세 디자인은 단순하게

완료 조건:
- 스캔과 finding을 화면에서 확인 가능
```

### 완료 체크

- [ ] scan 목록 표시
- [ ] task 목록 표시
- [ ] finding 목록 표시

---

## 10-4. Finding AI 분석 버튼

### 목표

UI에서 LLM 분석을 실행한다.

### Codex 지시문

```text
ScanDetail의 Finding 목록에 AI 분석 버튼을 추가해줘.

요구사항:
- 각 finding에 "AI 분석" 버튼
- POST /api/findings/{finding_id}/analyze 호출
- 결과 llm_summary 표시
- 로딩 상태 표시
- 에러 표시

완료 조건:
- UI에서 finding별 AI 분석 가능
```

### 완료 체크

- [ ] AI 분석 버튼 있음
- [ ] llm_summary 표시됨
- [ ] 로딩/에러 처리 있음

---

## 10-5. Report 화면

### 목표

Markdown 리포트를 확인한다.

### Codex 지시문

```text
Report 조회 기능을 추가해줘.

요구사항:
- ScanDetail에 "Report 생성" 버튼
- POST /api/scans/{scan_id}/report 호출
- GET /api/scans/{scan_id}/report로 내용 조회
- Markdown은 일단 plain text로 표시
- 다운로드 기능은 나중에

완료 조건:
- UI에서 report.md 내용을 확인 가능
```

### 완료 체크

- [ ] 리포트 생성 버튼
- [ ] 리포트 표시
- [ ] 에러 처리

---

# Phase 11. 안정화

## 11-1. Secret 마스킹 점검

### 목표

Secret 원문이 DB, 로그, 리포트에 남지 않게 한다.

### Codex 지시문

```text
Secret 마스킹 검증을 추가해줘.

요구사항:
- Gitleaks normalizer 테스트 강화
- Secret 원문이 Finding에 저장되지 않는지 확인
- Report에 Secret 원문이 포함되지 않는지 확인
- 로그 출력에도 Secret 필드가 직접 출력되지 않도록 점검

완료 조건:
- Secret 원문 방지 테스트 통과
```

### 완료 체크

- [ ] DB 저장 방지
- [ ] Report 포함 방지
- [ ] 테스트 통과

---

## 11-2. 경로 안전성 점검

### 목표

임의 경로 접근 위험을 줄인다.

### Codex 지시문

```text
target_path 검증 로직을 추가해줘.

요구사항:
- 기본 workspace root 설정: C:/AI/projects 또는 환경변수 LOCALSC_WORKSPACE
- target_path가 workspace 내부인지 확인
- 외부 경로면 400 반환
- 테스트 추가

완료 조건:
- workspace 외부 경로 차단
```

### 완료 체크

- [ ] workspace root 설정
- [ ] 외부 경로 차단
- [ ] 테스트 통과

---

## 11-3. 통합 테스트

### 목표

mock scanner로 전체 흐름을 검증한다.

### Codex 지시문

```text
mock scanner를 사용한 통합 테스트를 추가해줘.

흐름:
1. POST /api/scans run_immediately=true
2. scanner mock 결과 생성
3. normalizer가 finding 생성
4. finding 조회
5. report 생성

실제 Semgrep/Gitleaks/Trivy는 실행하지 말고 mock 사용.

완료 조건:
- 전체 MVP 흐름 테스트 통과
```

### 완료 체크

- [ ] 통합 테스트 있음
- [ ] 실제 외부 도구 의존 없음
- [ ] 전체 흐름 통과

---

# Phase 12. 실제 도구 연결 테스트

## 12-1. 로컬 환경 설치 확인

### 목표

사용자 PC에서 scanner 설치 여부를 확인한다.

### Codex 지시문

```text
scanner 설치 상태 확인 API를 추가해줘.

요구사항:
- GET /api/tools/status
- semgrep, gitleaks, trivy 설치 여부 확인
- 각 도구의 version 출력
- 설치 안 된 도구는 installed=false
- shell=True 금지

완료 조건:
- UI 또는 API에서 도구 설치 상태 확인 가능
```

### 완료 체크

- [ ] 도구 설치 상태 확인
- [ ] version 표시
- [ ] shell=True 없음

---

# 완료 정의

MVP가 완료되었다고 볼 수 있는 기준:

```text
1. Web UI에서 프로젝트 경로를 입력할 수 있다.
2. Semgrep/Gitleaks/Trivy 스캔을 실행할 수 있다.
3. Raw JSON 결과가 저장된다.
4. Finding이 DB에 정규화되어 저장된다.
5. Finding 목록을 UI에서 볼 수 있다.
6. Ollama localsec-security로 Finding 분석을 생성할 수 있다.
7. Markdown 리포트를 생성할 수 있다.
8. Secret 원문이 DB/리포트에 저장되지 않는다.
9. 기본 테스트가 통과한다.
```

---

# 금지 사항

MVP에서 하지 말 것:

```text
- Fine-tuning
- RAG
- OpenSCAP
- Syft/Grype
- PDF Report
- 멀티유저 인증
- Docker 배포
- 자동 패치 적용
- 운영 서버 설정 변경
- LLM이 스캐너 없이 취약점 직접 판정
```

---

# 다음 버전으로 넘길 것

```text
- Syft/Grype SBOM 기반 CVE 분석
- OpenSCAP CCE 설정 점검
- RAG 기반 KISA/OWASP/CWE/CIS 문서 검색
- HTML/PDF 리포트
- Git diff 기반 보안 리뷰
- 스캔 이력 비교
- 예외 승인 워크플로우
- Agent Governance 문서 강화

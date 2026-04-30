# LocalSec Auditor — Codex 대화 가이드

이 문서는 사용자가 Codex 같은 AI 코딩 에이전트와 어떻게 대화해야 LocalSec Auditor를 안정적으로 만들 수 있는지 정리한 가이드다.

핵심 원칙:

```text
Codex에게 "전체 만들어줘"라고 하지 않는다.
항상 "작은 기능 하나 + 수정 범위 + 검증 방법"으로 요청한다.
```

---

## 1. 좋은 대화 구조

Codex에게는 항상 아래 형식으로 말한다.

```text
목표:
이번 작업에서 만들 기능 하나

현재 상태:
이미 만들어진 파일/기능

수정 허용:
수정해도 되는 파일

수정 금지:
건드리면 안 되는 파일/범위

구현 조건:
세부 요구사항

검증 방법:
실행할 명령, 테스트 기준

완료 후 보고:
변경 파일, 실행 방법, 남은 문제
```

---

## 2. 기본 프롬프트 템플릿

```text
너는 LocalSec Auditor 프로젝트를 구현하는 코딩 에이전트다.

원칙:
- 한 번에 하나의 기능만 구현한다.
- 요청하지 않은 기능을 추가하지 않는다.
- 기존 구조를 임의로 대규모 리팩터링하지 않는다.
- shell=True를 사용하지 않는다.
- Secret 원문을 로그, DB, 리포트에 저장하지 않는다.
- LLM은 스캐너 결과를 설명할 뿐 최종 취약점 판정자가 아니다.
- 구현 후 반드시 검증 방법을 제시한다.

이번 작업 목표:
{작업 목표}

수정 허용 파일:
{수정 가능 파일}

수정 금지:
{수정 금지 내용}

완료 조건:
{완료 기준}

이제 구현 계획을 먼저 짧게 설명하고, 그다음 코드를 수정해줘.
```

---

## 3. 첫 대화: 프로젝트 구조 만들기

### 사용자가 Codex에게 보낼 말

```text
LocalSec Auditor 프로젝트의 기본 폴더 구조를 만들어줘.

목표:
FastAPI backend와 React frontend를 나중에 붙일 수 있는 기본 구조만 만든다.

수정 허용:
- 새 파일과 새 폴더 생성
- README.md 생성

수정 금지:
- 아직 실제 scanner 구현 금지
- DB 구현 금지
- LLM 구현 금지
- 인증/배포/Docker 추가 금지

요구사항:
- backend/app/main.py를 둘 위치를 준비
- backend/tests 폴더 생성
- frontend 폴더 생성
- data/scans, data/raw, data/reports 폴더 생성
- docs 폴더 생성
- README.md에 프로젝트 목적과 MVP 범위 작성

완료 후:
- 생성한 폴더와 파일 목록을 보여줘
```

---

## 4. FastAPI 기본 서버 만들기

```text
FastAPI 기본 서버를 만들어줘.

목표:
GET /health API만 동작하게 한다.

수정 허용:
- backend/app/main.py
- backend/pyproject.toml 또는 requirements.txt
- README.md

수정 금지:
- DB 추가 금지
- scanner 추가 금지
- frontend 수정 금지

요구사항:
- GET /health 응답: {"status": "ok"}
- uvicorn 실행 방법 README에 추가
- 테스트 또는 curl 검증 방법 제시

완료 조건:
- uvicorn으로 서버 실행 가능
- /health 정상 응답
```

---

## 5. DB 추가 요청하기

```text
SQLite 기반 DB 연결과 scans 모델을 추가해줘.

목표:
스캔 요청을 저장할 수 있는 scans 테이블을 만든다.

수정 허용:
- backend/app/db/*
- backend/app/models/*
- backend/app/crud/*
- backend/tests/*

수정 금지:
- scanner 구현 금지
- frontend 수정 금지
- LLM 구현 금지

요구사항:
- SQLite 경로는 data/localsec.db
- Scan 모델 필드:
  - id
  - project_name
  - target_path
  - status
  - created_at
  - started_at
  - finished_at
- create_scan, get_scan, list_scans 함수 구현
- 테스트 추가

완료 조건:
- 테스트에서 scan 생성 후 조회 가능
```

---

## 6. Scanner Wrapper 요청하기

### Semgrep

```text
Semgrep scanner wrapper만 구현해줘.

목표:
Semgrep 명령을 안전하게 구성하고 실행 결과를 파일로 저장한다.

수정 허용:
- backend/app/scanners/semgrep.py
- backend/app/scanners/runner.py
- backend/tests/test_semgrep_scanner.py

수정 금지:
- Gitleaks/Trivy 구현 금지
- DB 수정 금지
- API 수정 금지

요구사항:
- shell=True 사용 금지
- subprocess.run에 list[str] 인자 사용
- timeout 지원
- run_semgrep(target_path, output_path) 함수
- 명령:
  semgrep scan --config auto <target_path> --json
- stdout을 output_path에 저장
- 실패 시 exit_code, stderr 반환
- 테스트는 subprocess mock 사용

완료 조건:
- Semgrep 명령 인자가 올바르게 생성됨
- 실제 Semgrep 설치 없이 테스트 통과
```

### Gitleaks

```text
Gitleaks scanner wrapper만 구현해줘.

목표:
Gitleaks로 Secret 스캔을 실행하고 JSON 리포트를 저장한다.

수정 허용:
- backend/app/scanners/gitleaks.py
- backend/tests/test_gitleaks_scanner.py

수정 금지:
- Semgrep 기존 구현 변경 금지
- Trivy 구현 금지
- DB 수정 금지

요구사항:
- shell=True 금지
- 명령:
  gitleaks detect --source <target_path> --report-format json --report-path <output_path>
- Secret 원문을 로그에 출력하지 않음
- subprocess mock 테스트

완료 조건:
- Gitleaks 명령 인자가 올바름
- Secret 원문 출력 코드 없음
```

### Trivy

```text
Trivy filesystem scanner wrapper만 구현해줘.

목표:
Trivy fs 스캔 결과를 JSON 파일로 저장한다.

수정 허용:
- backend/app/scanners/trivy.py
- backend/tests/test_trivy_scanner.py

수정 금지:
- 다른 scanner 수정 금지
- normalizer 구현 금지
- API 수정 금지

요구사항:
- shell=True 금지
- 명령:
  trivy fs <target_path> --format json --output <output_path>
- timeout 지원
- subprocess mock 테스트

완료 조건:
- Trivy 명령 인자가 올바름
```

---

## 7. Normalizer 요청하기

### Semgrep Normalizer

```text
Semgrep normalizer를 구현해줘.

목표:
Semgrep JSON 결과를 공통 Finding 구조로 변환한다.

수정 허용:
- backend/app/normalizers/semgrep.py
- backend/app/schemas/finding.py
- backend/tests/test_semgrep_normalizer.py
- tests/fixtures/semgrep_sample.json

수정 금지:
- scanner wrapper 수정 금지
- API 구현 금지

요구사항:
- normalize_semgrep(raw_json_path, scan_id) 함수
- Semgrep results 배열을 순회
- check_id, path, start.line, extra.severity, extra.message 추출
- category: sast
- scanner: semgrep
- severity 매핑:
  ERROR → high
  WARNING → medium
  INFO → low

완료 조건:
- fixture JSON으로 Finding이 생성됨
```

### Gitleaks Normalizer

```text
Gitleaks normalizer를 구현해줘.

목표:
Gitleaks JSON 결과를 Secret Finding으로 변환하되 Secret 원문은 저장하지 않는다.

수정 허용:
- backend/app/normalizers/gitleaks.py
- backend/tests/test_gitleaks_normalizer.py
- tests/fixtures/gitleaks_sample.json

수정 금지:
- scanner wrapper 수정 금지
- DB 모델 대규모 변경 금지

요구사항:
- Secret 필드는 절대 Finding에 저장하지 않음
- File, StartLine, RuleID만 사용
- category: secret
- scanner: gitleaks
- severity: high
- title: Secret detected: {RuleID}

완료 조건:
- 테스트에서 Secret 원문이 결과에 포함되지 않음
```

---

## 8. Hermes Orchestrator 요청하기

```text
Hermes Orchestrator MVP를 구현해줘.

목표:
scan에 연결된 task를 순서대로 실행하고 결과를 저장한다.

수정 허용:
- backend/app/orchestrator/*
- backend/app/services/*
- backend/tests/test_orchestrator.py

수정 금지:
- Celery/RQ 추가 금지
- 백그라운드 큐 추가 금지
- frontend 수정 금지
- LLM 분석 구현 금지

요구사항:
- run_scan(scan_id) 함수
- scan_tasks를 조회해서 순차 실행
- task 상태:
  queued → running → completed 또는 failed
- scanner 실행 결과 raw JSON 저장
- normalizer 호출
- finding DB 저장
- 실패 시 error_message 저장
- 테스트는 scanner mock 사용

완료 조건:
- mock scanner 결과로 finding이 DB에 저장됨
- 실패한 task는 failed 상태가 됨
```

---

## 9. Ollama 연결 요청하기

```text
Ollama client를 구현해줘.

목표:
backend에서 Ollama의 localsec-security 모델을 호출한다.

수정 허용:
- backend/app/llm/ollama_client.py
- backend/app/llm/prompts.py
- backend/tests/test_ollama_client.py

수정 금지:
- scanner 수정 금지
- frontend 수정 금지
- fine-tuning 관련 코드 추가 금지

요구사항:
- 기본 URL: http://localhost:11434
- 기본 모델: localsec-security
- /api/generate 호출
- timeout 설정
- 에러 처리
- 테스트는 HTTP mock 사용

완료 조건:
- mock Ollama 응답으로 generate 함수 테스트 통과
```

---

## 10. Finding 분석 API 요청하기

```text
Finding AI 분석 API를 구현해줘.

목표:
Finding 하나를 Ollama로 분석하고 결과를 저장한다.

수정 허용:
- backend/app/api/findings.py
- backend/app/llm/prompts.py
- backend/app/llm/ollama_client.py
- backend/tests/test_finding_analysis_api.py

수정 금지:
- scanner 수정 금지
- DB 스키마 대규모 변경 금지
- frontend 수정 금지

요구사항:
- POST /api/findings/{finding_id}/analyze
- finding 조회
- prompt 생성
- Ollama 호출
- llm_summary 저장
- 응답으로 llm_summary 반환
- 없는 finding은 404
- Ollama 오류는 명확한 에러 반환

완료 조건:
- mock Ollama 응답이 finding.llm_summary에 저장됨
```

---

## 11. Report Generator 요청하기

```text
Markdown 리포트 생성 기능을 구현해줘.

목표:
Scan과 Findings를 기반으로 report.md를 만든다.

수정 허용:
- backend/app/reports/markdown.py
- backend/app/api/reports.py
- backend/tests/test_report_generator.py

수정 금지:
- PDF 구현 금지
- HTML 구현 금지
- frontend 수정 금지

요구사항:
- generate_markdown_report(scan_id)
- scan 정보 포함
- severity 통계 포함
- finding 목록 포함
- llm_summary가 있으면 상세에 포함
- Secret 원문 포함 금지
- 저장 경로: data/scans/{scan_id}/reports/report.md

완료 조건:
- 테스트에서 report.md 생성됨
- Secret 원문이 포함되지 않음
```

---

## 12. Frontend 요청 방식

프론트는 한 번에 만들라고 하지 않는다.

### 12-1. 기본 앱

```text
React + Vite + TypeScript 기본 프론트엔드를 만들어줘.

목표:
Dashboard, NewScan, ScanDetail 페이지 라우팅만 만든다.

수정 허용:
- frontend/*

수정 금지:
- backend 수정 금지
- shadcn/ui 추가 금지
- 복잡한 디자인 금지

요구사항:
- npm run dev 가능
- API base URL 설정
- 기본 라우팅

완료 조건:
- 세 페이지로 이동 가능
```

### 12-2. New Scan

```text
NewScan 페이지를 구현해줘.

목표:
사용자가 project_name, target_path, scan_types를 입력하고 scan을 생성한다.

수정 허용:
- frontend/src/pages/NewScan.tsx
- frontend/src/api/*

수정 금지:
- backend 수정 금지
- 다른 페이지 대규모 변경 금지

요구사항:
- project_name input
- target_path input
- semgrep/gitleaks/trivy 체크박스
- run_immediately 체크박스
- POST /api/scans 호출
- 성공 시 scan_id 표시
- 실패 시 에러 표시

완료 조건:
- UI에서 scan 생성 가능
```

---

## 13. 문제가 생겼을 때 대화법

### 에러가 날 때

나쁜 질문:

```text
이거 왜 안돼?
```

좋은 질문:

```text
다음 에러가 발생했어.

상황:
- 어떤 명령을 실행했는지
- 어떤 파일을 수정했는지
- 기대한 결과
- 실제 결과

에러 로그:
```text
여기에 로그 붙여넣기
```

요청:
- 원인을 3개 이하로 추정해줘
- 가장 가능성 높은 것부터 확인 순서를 제시해줘
- 바로 코드 수정하지 말고 먼저 진단해줘
```

---

## 14. Codex가 이상하게 확장하려고 할 때 막는 말

```text
지금은 MVP 범위만 구현해.
다음은 하지 마:
- 인증
- Docker
- PostgreSQL
- Redis
- Celery
- RAG
- PDF
- OpenSCAP
- fine-tuning
- 자동 패치
- 대규모 리팩터링

현재 작업의 완료 조건만 만족해.
```

---

## 15. 매 작업 완료 후 Codex에게 물어볼 것

```text
작업 완료 후 아래 형식으로 정리해줘.

1. 수정한 파일
2. 추가한 기능
3. 실행 방법
4. 테스트 방법
5. 아직 안 된 것
6. 다음에 해야 할 작은 작업 1개
```

---

## 16. 커밋 단위

한 커밋에는 하나의 기능만 넣는다.

좋은 커밋:

```text
feat: add FastAPI health endpoint
feat: add scan model and CRUD
feat: add semgrep scanner wrapper
feat: add gitleaks normalizer
feat: add ollama client
feat: add markdown report generator
```

나쁜 커밋:

```text
feat: build entire security platform
refactor: change everything
update: fix stuff
```

---

## 17. 전체 진행 순서

Codex에게 아래 순서대로 시키면 된다.

```text
1. 프로젝트 폴더 구조 생성
2. FastAPI /health
3. SQLite Scan 모델
4. ScanTask 모델
5. Finding 모델
6. Scan 생성/조회 API
7. Scanner Runner 공통 유틸
8. Semgrep Wrapper
9. Gitleaks Wrapper
10. Trivy Wrapper
11. Raw Result 디렉터리
12. Semgrep Normalizer
13. Gitleaks Normalizer
14. Trivy Normalizer
15. Hermes Orchestrator
16. Ollama Client
17. Finding 분석 API
18. Markdown Report
19. React 기본 앱
20. New Scan 화면
21. Scan Detail 화면
22. AI 분석 버튼
23. Report 화면
24. Secret 마스킹 테스트
25. 통합 테스트
```

---

## 18. 최종 체크

MVP 완료 질문:

```text
현재 프로젝트가 아래 조건을 만족하는지 점검해줘.

1. Web UI에서 스캔 생성 가능
2. Semgrep/Gitleaks/Trivy task 생성 가능
3. scanner raw 결과 저장 가능
4. normalizer가 findings 생성 가능
5. findings를 UI에서 볼 수 있음
6. Ollama 분석 가능
7. report.md 생성 가능
8. Secret 원문이 저장되지 않음
9. 테스트가 통과함

부족한 항목을 우선순위 순서로 알려줘.
```

---

## 19. 핵심 대화 원칙

```text
작게 시킨다.
검증하게 한다.
범위를 막는다.
완료 기준을 둔다.
다음 작업 하나만 고른다.
```

이 원칙만 지키면 Codex가 프로젝트를 망치지 않고 차근차근 만들 가능성이 높다.

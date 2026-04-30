# Verification Checklist

LocalSec Auditor의 각 구현 단계를 검증하기 위한 체크리스트다.

---

## 1. Backend 기본 검증

- [ ] `uvicorn app.main:app --reload` 실행 가능
- [ ] `GET /health` 응답이 `{"status": "ok"}`임
- [ ] 테스트 명령이 README에 기록됨

---

## 2. DB 검증

- [ ] `data/localsec.db` 생성 가능
- [ ] Scan 생성/조회 테스트 통과
- [ ] ScanTask 생성/상태 업데이트 테스트 통과
- [ ] Finding 생성/조회 테스트 통과

---

## 3. Scanner Wrapper 검증

### Semgrep

- [ ] `shell=True` 사용 안 함
- [ ] `semgrep scan --config auto <target_path> --json` 형태로 실행
- [ ] stdout을 output file에 저장
- [ ] subprocess mock 테스트 통과

### Gitleaks

- [ ] `shell=True` 사용 안 함
- [ ] `gitleaks detect --source <target_path> --report-format json --report-path <output_path>` 형태로 실행
- [ ] Secret 원문을 로그에 출력하지 않음
- [ ] subprocess mock 테스트 통과

### Trivy

- [ ] `shell=True` 사용 안 함
- [ ] `trivy fs <target_path> --format json --output <output_path>` 형태로 실행
- [ ] subprocess mock 테스트 통과

---

## 4. Normalizer 검증

### Semgrep

- [ ] `check_id` 추출
- [ ] `path` 추출
- [ ] `start.line` 추출
- [ ] `extra.severity` 매핑
- [ ] category가 `sast`
- [ ] scanner가 `semgrep`

### Gitleaks

- [ ] category가 `secret`
- [ ] scanner가 `gitleaks`
- [ ] `File`, `StartLine`, `RuleID` 추출
- [ ] Secret 원문 저장 안 함
- [ ] Secret 원문 리포트 포함 안 함

### Trivy

- [ ] category가 `cve`
- [ ] scanner가 `trivy`
- [ ] `VulnerabilityID`를 CVE로 저장
- [ ] `PkgName`을 component로 저장
- [ ] `FixedVersion` 보존

---

## 5. Hermes Orchestrator 검증

- [ ] scan_id별 raw/normalized/reports 폴더 생성
- [ ] task 상태가 queued → running → completed/failed로 변경
- [ ] 실패 시 error_message 저장
- [ ] scanner 실행 후 raw JSON 저장
- [ ] normalizer 실행 후 Finding 저장
- [ ] 전체 scan status 업데이트

---

## 6. Ollama Harness 검증

- [ ] `OLLAMA_BASE_URL` 설정 가능
- [ ] 기본 모델은 `localsec-security`
- [ ] timeout 설정 있음
- [ ] Ollama 실패 시 명확한 에러 반환
- [ ] finding 분석 결과가 `llm_summary`에 저장됨
- [ ] 입력에 없는 CVE를 만들지 말라는 규칙 포함

---

## 7. Report 검증

- [ ] `report.md` 생성 가능
- [ ] severity 통계 포함
- [ ] finding 목록 포함
- [ ] llm_summary 포함 가능
- [ ] Secret 원문 포함 안 함

---

## 8. Frontend 검증

- [ ] Dashboard에서 scan 목록 조회 가능
- [ ] New Scan에서 scan 생성 가능
- [ ] Scan Detail에서 task 목록 조회 가능
- [ ] Scan Detail에서 finding 목록 조회 가능
- [ ] Finding별 AI 분석 버튼 동작
- [ ] Report 생성/조회 가능

---

## 9. MVP 완료 조건

- [ ] Web UI에서 프로젝트 경로 입력 가능
- [ ] Semgrep/Gitleaks/Trivy task 생성 가능
- [ ] raw JSON 저장 가능
- [ ] Finding DB 저장 가능
- [ ] Finding UI 조회 가능
- [ ] Ollama 분석 가능
- [ ] Markdown report 생성 가능
- [ ] Secret 원문 미저장 보장
- [ ] 기본 테스트 통과

# Coding Agent Rules

이 문서는 LocalSec Auditor를 구현하는 AI 코딩 에이전트가 지켜야 할 세부 코딩 규칙이다.

---

## 1. 작업 단위

한 번에 하나의 기능만 구현한다.

좋은 작업 단위:

- `/health` API 추가
- Scan 모델 추가
- Semgrep wrapper 추가
- Gitleaks normalizer 추가
- Ollama client 추가
- Markdown report generator 추가

나쁜 작업 단위:

- 전체 백엔드 구현
- Web UI 전부 구현
- 보안 플랫폼 완성
- 구조 전체 리팩터링

---

## 2. 수정 범위

작업 요청에 명시된 파일만 수정한다.

예:

```text
수정 허용:
- backend/app/scanners/semgrep.py
- backend/tests/test_semgrep_scanner.py

수정 금지:
- frontend/*
- backend/app/db/*
- backend/app/llm/*
```

명시되지 않은 파일을 수정해야 하면 먼저 이유를 설명한다.

---

## 3. 외부 명령 실행 규칙

scanner 실행 코드는 다음을 지킨다.

- `shell=True` 사용 금지
- `subprocess.run([...])` 형태로 list argument 사용
- timeout 설정
- stdout, stderr, exit_code 저장
- 실패 시 예외로 서버 전체를 죽이지 말고 결과 객체로 반환

---

## 4. 보안 데이터 처리 규칙

- Secret 원문은 DB, 로그, 리포트에 저장하지 않는다.
- Gitleaks 결과의 `Secret` 필드는 저장하지 않는다.
- CVE ID는 scanner 결과에 있을 때만 사용한다.
- CWE, CCE, OWASP 매핑은 입력 근거 또는 명시적 mapping table에 기반한다.
- LLM 출력은 scanner 원본 결과와 분리해서 저장한다.

---

## 5. 테스트 규칙

새 기능에는 가능한 한 테스트를 추가한다.

우선순위:

1. Normalizer 테스트
2. Scanner wrapper mock 테스트
3. CRUD 테스트
4. API 테스트
5. Report generator 테스트
6. Secret 마스킹 테스트

외부 scanner가 설치되어 있지 않아도 CI/로컬 테스트가 돌아가도록 mock을 사용한다.

---

## 6. 완료 보고 형식

작업 완료 후 에이전트는 아래 형식으로 보고한다.

```text
1. 수정한 파일
2. 추가한 기능
3. 실행 방법
4. 테스트 방법
5. 아직 안 된 것
6. 다음에 할 작은 작업 1개
```

---

## 7. 금지 기능

MVP에서는 구현하지 않는다.

- Fine-tuning
- RAG
- OpenSCAP
- Syft / Grype
- PDF report
- 멀티유저 인증
- Docker 배포
- 자동 패치 적용
- 운영 서버 설정 변경
- LLM 단독 취약점 판정

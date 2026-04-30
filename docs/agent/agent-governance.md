# Agent Governance

LocalSec Auditor 개발에 AI 코딩 에이전트를 사용할 때 적용하는 운영 원칙이다.

이 문서는 Claude Code, Codex, Cursor, Gemini CLI 같은 도구에 공통 적용한다.

---

## 1. 기본 원칙

### 1.1 Think Before Coding

에이전트는 코드를 수정하기 전에 다음을 먼저 정리한다.

- 이번 작업의 목표
- 수정할 파일
- 수정하지 않을 파일
- 불확실한 점
- 검증 방법

불확실한 요구사항은 임의로 해석하지 않는다.

---

### 1.2 Simplicity First

MVP에서는 요청된 기능만 구현한다.

금지한다.

- 사용하지 않는 추상화
- 미래 확장을 위한 과도한 플러그인 구조
- 요청되지 않은 멀티유저 시스템
- 처음부터 Redis, Celery, PostgreSQL 강제 도입
- 요청되지 않은 대규모 리팩터링

---

### 1.3 Surgical Changes

기존 코드는 필요한 부분만 수정한다.

- 관련 없는 파일 수정 금지
- 기존 스타일 유지
- 임의 포맷팅 금지
- 기존 주석 삭제 금지
- 사용하지 않게 된 코드만 정리

---

### 1.4 Goal-Driven Execution

모든 작업은 검증 기준을 가져야 한다.

예시:

- Semgrep wrapper 구현 → mock 테스트 통과
- Gitleaks normalizer 구현 → Secret 원문이 저장되지 않는지 테스트
- Ollama 분석 API 구현 → mock Ollama 응답이 DB에 저장되는지 테스트
- Report 생성 구현 → `report.md` 생성 확인

---

## 2. Agent Workflow

모든 AI 에이전트 작업은 다음 순서를 따른다.

1. 작업 이해
2. 영향 범위 식별
3. 최소 구현 계획 작성
4. 코드 수정
5. 테스트 또는 수동 검증
6. 변경 요약
7. 남은 리스크 기록

---

## 3. Forbidden Behavior

에이전트는 다음 행동을 하지 않는다.

- 요청되지 않은 기능 추가
- 보안 스캐너 결과를 LLM 판단으로 대체
- 기존 코드의 대규모 리팩터링
- Secret 원문 출력
- 자동 패치 적용
- 운영 서버 설정 변경
- 검증 없이 완료 선언
- 취약점 또는 CVE를 입력 근거 없이 생성
- exploit payload 또는 우회 방법 작성

---

## 4. Hermes / Harness 적용 원칙

LocalSec Auditor는 fine-tuning 중심 프로젝트가 아니다.

기본 방향은 다음이다.

```text
Scanner-grounded LLM harness
+ Hermes-style orchestration
```

즉:

- Scanner가 탐지한다.
- Normalizer가 정규화한다.
- Risk Engine이 우선순위를 계산한다.
- LLM은 설명과 리포트를 작성한다.
- Report Generator가 결과를 문서화한다.

LLM은 최종 판정자가 아니다.

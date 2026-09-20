# STEP 4 — 기능·데이터·API 연결 설계

작성 기준: 2026-09-21

## 1. 설계 범위와 원칙

이 문서는 PRD와 STEP 1~3에서 확정한 기능을 화면과 데이터로 연결하는 최소 설계다. 실제 DB migration, 코드, API 구현, 환경 검증을 수행하지 않는다.

데이터 흐름은 다음과 같다.

```text
피해 서버 로그
  → rsyslog / TCP 5514
  → 관제 서버 Python 수집기
  → 파싱·정규화
  → PostgreSQL
  → 탐지·경보
  → 상관분석·위험도·Incident
  → 자동 대응 결과·효과 검증
  → Django/DRF API
  → React 화면
```

React는 PostgreSQL에 직접 접근하지 않는다. 화면은 Django/DRF가 제공하는 실제 저장 기록을 조회한다. 자동 대응은 화면 API나 버튼에 의존하지 않는 백엔드 흐름이며, 실행용 UI API를 만들지 않는다.

아래 개념은 별도 테이블을 반드시 뜻하지 않는다. 구현 시 하나의 테이블에 합칠 수 있는지와 관계 저장 방식을 검토하되, 각 개념의 근거와 화면 연결을 잃지 않는다. 실제 로그에서 얻을 수 없는 값을 필수 필드로 만들지 않는다.

## 2. 최소 데이터 개념

### 2.1 SecurityEvent

정규화된 보안 이벤트다. Nginx와 SSH 원본 형식을 공통 조회·탐지 입력으로 사용한다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 이벤트 식별자 | 정수 또는 UUID, 필수 |
| source_type | 로그 종류 | `nginx` 또는 `ssh`, 필수 |
| event_time | 원본 로그의 발생 시각 | 시각, 필수 |
| source_ip | 출발지 IP | IP 문자열, 로그에서 확인되는 경우 필수 |
| action | 수행된 행동 | 문자열, 필수 |
| result | 행동 결과 | 문자열 또는 제한된 값, 필수 |
| request_path | Nginx 요청 경로 | 문자열, Nginx 이벤트에서만 사용 |
| http_status | HTTP 응답 코드 | 정수, Nginx 이벤트에서 확인되는 경우 |
| ssh_evidence | SSH 인증 결과·실패 이유 등 SSH 근거 | 문자열 또는 구조화된 metadata, SSH 이벤트에서 사용 |
| raw_log | 원본 로그 | 긴 문자열 또는 원본 참조, 근거 확인에 필요 |
| created_at | 관제 DB 저장 시각 | 시각, 필수 |

`request_path`, `http_status`, `ssh_evidence`는 source_type별 선택 필드다. 추가 source를 만들지 않으며, 세부 필드와 원본 저장 방식은 실제 로그 확인 후 구현 설계에서 확정한다.

### 2.2 NormalizationFailure

수집은 됐지만 보안 이벤트로 변환하지 못한 기록이다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 실패 기록 식별자 | 정수 또는 UUID, 필수 |
| source_type | 원본 로그 종류 | `nginx` 또는 `ssh`, 필수 |
| raw_log | 변환에 실패한 원본 | 긴 문자열 또는 참조, 필수 |
| failure_reason | 실패 이유 | 문자열, 필수 |
| received_at | 관제 서버 수신 시각 | 시각, 필수 |

실패 기록은 정상 SecurityEvent와 별도로 조회한다. 실패 이유를 추측해 성공 이벤트로 만들지 않는다.

### 2.3 Alert

탐지 규칙 조건을 만족한 결과다. Alert는 Incident와 별도 개념이다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 경보 식별자 | 정수 또는 UUID, 필수 |
| rule_type | 규칙 종류 | `ssh_brute_force`, `nginx_scan`, `nginx_suspicious_path`, 필수 |
| source_ip | 탐지 대상 출발지 IP | IP 문자열, 필수 |
| occurred_at | 경보 발생 시각 | 시각, 필수 |
| severity | 탐지 중요도 | 문자열 또는 제한된 값, 규칙에서 산출되는 경우 |
| rule_condition | 적용 조건 요약 | 문자열 또는 작은 구조, 필수 |
| evidence | 탐지 근거 요약 | 문자열 또는 참조 목록, 필수 |
| related_event_ids | 근거가 된 SecurityEvent 참조 | 이벤트 ID 목록, 필수 |

현재 규칙 조건은 SSH 동일 IP·60초·실패 5회 이상, Nginx 동일 IP·60초·404/403·서로 다른 URI 10개 이상, 의심 경로의 query string 제외 path 일치/하위 경로다.

### 2.4 CorrelationResult

서로 다른 종류의 Alert를 같은 출발지 IP와 시간 조건으로 연결한 결과다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 상관분석 식별자 | 정수 또는 UUID, 필수 |
| source_ip | 연결 기준 IP | IP 문자열, 필수 |
| alert_ids | 관련 Alert 참조 | Alert ID 목록, 필수 |
| correlation_type | 상관분석 종류 | 문자열, 필수 |
| window_start / window_end | 판단 시간 범위 | 시각 2개, 필수 |
| matched | 조건 성립 여부 | boolean, 필수 |
| evidence | 동일 IP·경보 종류·시간 조건 근거 | 문자열 또는 참조 목록, 필수 |

현재 `correlation_type`은 SSH brute force와 Nginx scan 또는 suspicious path의 결합을 나타낸다. 동일 규칙 반복 횟수만으로 결과를 만들지 않는다.

### 2.5 RiskResult

현재 판단 대상의 탐지 종류와 상관분석 결과를 설명 가능한 점수로 기록한다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 위험도 결과 식별자 | 정수 또는 UUID, 필수 |
| source_ip | 판단 대상 IP | IP 문자열, 필수 |
| score | 0~100 점수 | 정수, 필수 |
| level | 위험도 등급 | `Low`, `Medium`, `High`, 필수 |
| score_basis | 종류별 1회 점수와 상관분석 가산 근거 | 작은 구조 또는 문자열, 필수 |
| judged_at | 판단 시각 | 시각, 필수 |

점수는 현재 판단 대상 안에서 SSH brute force 40, Nginx scan 30, suspicious path 20을 종류별 한 번 반영하고, 지정 상관분석 성립 시 30을 더하며 100을 넘지 않는다. 같은 종류의 반복 Alert를 발생 횟수만큼 누적하지 않는다. 등급은 Low 0~39, Medium 40~69, High 70~100이다.

판단 대상 기간은 상관분석의 10분 조건과 설명 가능성을 유지하는 최소 범위로 후속 구현 설계에서 정한다. 별도 세션·통계 시스템은 만들지 않는다.

### 2.6 Incident

상관분석과 위험도 기준을 충족한 보안 사고다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 사고 식별자 | 정수 또는 UUID, 필수 |
| alert_ids | 관련 Alert 참조 | 목록, 필수 |
| correlation_result_id | 분석 근거 참조 | CorrelationResult ID, 필수 |
| source_ip | 사고 출발지 IP | IP 문자열, 필수 |
| risk_score | 생성 당시 위험도 | 정수, 필수 |
| risk_level | 생성 당시 등급 | `High` 등, 필수 |
| creation_reason | 생성 근거 | 문자열 또는 작은 구조, 필수 |
| created_at | 생성 시각 | 시각, 필수 |

현재 생성 조건은 상관분석 성립과 High(70 이상)다. 단순 Alert는 Incident가 아니다.

### 2.7 ResponseRecord

SSH brute force Alert를 근거로 자동 대응을 실행한 기록이다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 대응 기록 식별자 | 정수 또는 UUID, 필수 |
| triggering_alert_id | 발동 Alert 참조 | Alert ID, 필수 |
| target_ip | 차단 대상 IP | IP 문자열, 필수 |
| allowlist_result | 허용 목록 판정 | 제외·제외 아님·확인 불가 등, 필수 |
| execution_status | 실행 상태 | 성공·실패·미실행·확인 불가 등, 필수 |
| execution_result | 실행 출력 또는 오류 | 문자열 또는 참조, 필수 |
| executed_at | 실행 시각 | 시각, 필수 |

자동 대응은 상관분석·Incident를 기다리지 않는다. 관제 서버에서 피해 서버로 SSH 원격 명령을 보내 UFW 차단을 수행하는 설계이며, 실제 권한·포트는 환경 검증에서 확인한다.

### 2.8 ResponseVerification

차단 명령 실행 뒤 실제 효과를 검증한 기록이다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| id | 검증 기록 식별자 | 정수 또는 UUID, 필수 |
| response_record_id | ResponseRecord 참조 | ID, 필수 |
| ufw_rule_result | 대상 IP UFW 규칙 확인 결과 | 존재·미존재·미확인 등, 필수 |
| kali_ssh_reconnect_result | 동일 Kali의 SSH 재접속 결과 | 접속 실패·접속 성공·미확인 등, 필수 |
| verification_status | 실제 검증 상태 | `success`, `failed`, `unverified`, 필수 |
| evidence | 규칙 확인·재접속 근거 | 문자열 또는 참조, 필수 |
| verified_at | 검증 시각 | 시각, 필수 |

`success`는 UFW 대상 IP 규칙 존재와 동일 Kali 환경의 SSH 접속 실패가 함께 확인된 경우에만 사용한다. 단순 접속 실패나 명령 실행 성공만으로 `success`를 기록하지 않는다.

### 2.9 LogSourceStatus

로그 종류별 수신 상태를 대시보드에 제공한다.

| 필드 | 의미 | 형식·필수 여부 |
|---|---|---|
| source_type | `nginx` 또는 `ssh` | 문자열, 필수 |
| last_received_at | 마지막 수신 시각 | 시각 또는 없음, 필수 |
| last_error | 최근 수신 오류 | 문자열 또는 없음 |
| delivery_anomaly | 초기 60초 무수신에 따른 전달 이상 표시 | boolean, 필수 |

`delivery_anomaly`는 전달 이상 표시일 뿐 원인을 확정하지 않는다. 60초는 실제 피해 서버 환경 검증 후 조정할 수 있다.

## 3. 관계와 근거 추적

```text
SecurityEvent ──< Alert >── CorrelationResult ──< Incident
       │             │              │                 │
       │             └──── ResponseRecord ── ResponseVerification
       │
NormalizationFailure (SecurityEvent로 변환되지 않은 원본)

LogSourceStatus ──(source_type별 수신 상태)──> Dashboard
```

- Alert는 하나 이상의 관련 SecurityEvent를 참조한다.
- CorrelationResult는 관련 Alert를 참조하며 `matched`와 근거를 남긴다.
- Incident는 관련 Alert와 CorrelationResult, 생성 당시 RiskResult의 점수·등급을 추적할 수 있어야 한다.
- ResponseRecord는 발동 Alert를 참조한다. Incident가 없어도 SSH brute force Alert에서 시작할 수 있다.
- ResponseVerification은 정확히 대응 기록 하나를 참조한다. 실행 상태와 효과 검증 상태를 합치지 않는다.
- 원본 로그는 SecurityEvent 또는 NormalizationFailure에서 다시 확인할 수 있어야 한다.

## 4. 화면 A~D 연결

| 화면 | 조회하는 데이터 | 설명 가능한 결과 |
|---|---|---|
| A 관제 대시보드 | LogSourceStatus, 최근 SecurityEvent·Alert·Incident·ResponseRecord 요약 | 수신 상태, 최근 기록, 각 상세 화면으로 이동 |
| B 보안 이벤트 목록/상세 | SecurityEvent, NormalizationFailure | 로그 종류·시각·IP·행동/결과, 원본 로그, 정규화 실패 |
| C 경보·보안 사고 목록/상세 | Alert, CorrelationResult, RiskResult, Incident | 탐지 조건·근거, 관련 경보, 상관분석, 점수·등급, Incident 구분 |
| D 자동 대응 결과/검증 | ResponseRecord, ResponseVerification | 발동 Alert, 허용 목록, 실행 결과, UFW 규칙과 Kali 재접속 검증 |

목록과 상세는 같은 화면에서 선택으로 전환한다. 화면은 결과 조회용이며 차단 실행·해제·공격 실행·규칙 편집·승인 기능을 제공하지 않는다.

## 5. 최소 조회 API

모든 API는 `React → Django/DRF → PostgreSQL` 경로를 사용한다. 인증·권한 방식, 페이지네이션·필터의 세부 형식은 STEP 5와 실제 구현에서 정한다. 아래 API는 조회용 최소 목록이다.

| API | 용도 | 연결 화면 |
|---|---|---|
| `GET /api/dashboard/` | LogSourceStatus와 최근 이벤트·경보·사고·대응 요약을 묶어 반환 | A |
| `GET /api/events/` | SecurityEvent 목록과 기본 필드 조회 | B |
| `GET /api/events/{id}/` | 이벤트 상세·원본 근거·연결 Alert 조회 | B |
| `GET /api/alerts/` | Alert 목록 조회 | C |
| `GET /api/alerts/{id}/` | Alert 상세·조건·근거·관련 이벤트·연결 분석/대응 조회 | C |
| `GET /api/incidents/` | Incident 목록 조회 | C |
| `GET /api/incidents/{id}/` | Incident 상세·Alert·Correlation·Risk 근거 조회 | C |
| `GET /api/responses/` | ResponseRecord와 검증 상태 목록 조회 | D |
| `GET /api/responses/{id}/` | 실행 결과·검증 근거·발동 Alert 상세 조회 | D |

대시보드 API는 새 데이터를 계산하는 기능이 아니라 각 개념의 최근 조회 결과를 요약한다. 정규화 실패는 B의 이벤트 조회 범위에서 별도 실패 기록으로 제공하는 방식을 검토하며, 독립적인 화면·실행 API는 추가하지 않는다.

금지 API: 자동 대응 실행·승인·해제 API, 공격 실행 API, 탐지 규칙 편집 API, Playbook API, 별도 Incident 생성 API. 자동 대응과 분석은 수집·탐지 백엔드 흐름에서 기록한다.

## 6. 데이터 처리 흐름

1. rsyslog와 Python 수집기가 Nginx/SSH 원본을 수신하고 `LogSourceStatus`를 갱신한다.
2. 파싱 성공 시 `SecurityEvent`를 저장한다. 실패 시 `NormalizationFailure`에 원본과 이유를 저장한다.
3. 정규화된 이벤트가 규칙 조건을 만족하면 관련 이벤트를 참조하는 `Alert`를 만든다.
4. 같은 IP의 SSH brute force Alert와 Nginx scan 또는 suspicious path Alert가 10분 이내 함께 있으면 `CorrelationResult.matched`를 기록한다.
5. 현재 판단 대상의 탐지 종류별 기본 점수와 상관분석 가산을 한 번 반영해 `RiskResult`를 기록한다. 반복 Alert를 횟수만큼 누적하지 않는다.
6. 상관분석이 성립하고 위험도가 High이면 `Incident`를 만든다. Alert와 Incident를 분리한다.
7. SSH brute force Alert 생성 후 허용 목록을 확인하고 조건을 충족하면 `ResponseRecord`를 만든다. 이는 CorrelationResult·Incident 생성과 독립적이다.
8. UFW 규칙 확인과 동일 Kali SSH 재접속 결과를 `ResponseVerification`으로 저장한다. 두 확인이 모두 성공 조건을 만족할 때만 `verification_status=success`다.
9. A~D는 위 기록을 조회하고, 실행 결과·검증 결과·조회 오류·미검증을 구분해 표시한다.

## 7. 실패 기록과 상태 구분

| 상황 | 기록·표시 |
|---|---|
| 로그 수신 오류 | `LogSourceStatus.last_error`와 마지막 수신 시각. 60초 무수신은 `delivery_anomaly=true`로 표시할 수 있으나 원인을 확정하지 않음 |
| 정규화 실패 | `NormalizationFailure.raw_log`와 `failure_reason`. 성공 SecurityEvent로 대체하지 않음 |
| 탐지 조건 불충족 | SecurityEvent는 남고 Alert가 생성되지 않음. 수집 실패와 혼동하지 않음 |
| 상관분석 불성립 | `CorrelationResult.matched=false`와 근거. Incident로 표시하지 않음 |
| 위험도 미산출 | RiskResult가 없거나 조회되지 않은 상태를 점수 0과 구분 |
| 자동 대응 실행 실패 | ResponseRecord의 실행 상태·오류 저장 |
| 허용 목록 제외 | ResponseRecord에 제외 판정과 이유 저장. 실행 성공으로 표시하지 않음 |
| 검증 미수행 | ResponseVerification `unverified` |
| 검증 실패 | UFW 규칙 또는 동일 Kali 재접속 결과 중 하나라도 실패·불충분하면 `failed` 또는 근거 부족 상태로 기록. 단순 접속 실패로 성공 판정하지 않음 |
| API 조회 오류 | 화면의 조회 오류 상태. 데이터 없음이나 분석·대응 실패로 대체하지 않음 |

실제 상태값의 세부 enum과 실패 재처리·중복 수신 정책은 STEP 5 또는 구현 중 필요성을 확인해 정한다.

## 8. STEP 5로 넘기는 항목

- 실제 피해 서버 로그 위치와 로그 형식, rsyslog imfile 설정, TCP 5514 연결 및 학교 LAN 경로 검증.
- 관제 PostgreSQL 운영 방식, Django/DRF API 인증·최소 권한, WSL2 네트워크 접근과 방화벽 규칙.
- 관제 서버에서 피해 서버로 SSH 원격 명령을 실행하는 계정·키·권한·실제 SSH 포트 관리. 비밀번호·토큰·키를 문서나 코드에 저장하지 않는다.
- UFW 명령의 안전한 실행·오류 처리와 수동 해제 절차, 허용 목록 IP 확인.
- 수집기 입력 검증, 원본 로그 노출 범위, API 오류 응답과 비밀정보 마스킹.
- 저장 실패·중복 로그·순서 역전·지연, API 조회 실패를 다룰 최소 운영·보안 정책.
- 실제 학교 장비 대여·확보, 학교 LAN·WSL2 연결, 탐지·상관분석·자동 대응·UFW 효과 검증.

이 항목들은 새 기능이나 STEP 4 사용자 결정이 아니다. STEP 5에서 기술·보안 검토 후 구현 전 확인한다.

## 9. STEP 4 완료 판정

9개 데이터 개념, 최소 관계, A~D 화면 연결, 9개 조회 API, 처리·실패 흐름, STEP 5 이관 항목을 정의했다. 데이터 스키마·API의 구현 세부는 후속 작업에서 확정하며, 이번 단계에서 코드나 migration을 작성하지 않았다.

STEP 4 문서 설계를 완료했다. STEP 5는 시작하지 않는다.

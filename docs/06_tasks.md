# STEP 6 — 구현 작업 계획

작성 기준: 2026-09-21

모든 Phase는 기존 실제 구현 저장소를 확인한 뒤 진행한다. 현재 문서는 계획이며 코드·설정·패키지·Git 작업을 수행하지 않았다. 완료 조건은 파일 작성이 아니라 실제로 확인할 수 있는 결과다.

## Phase 1 — Nginx SecurityEvent 첫 Vertical Slice

- **목표:** 실제 구현 기반을 확인하고 Nginx 로그 하나를 수집·정규화·저장·조회해 브라우저에 표시한다.
- **구현할 최소 항목:** 기존 실제 구현 저장소와 Docker/Django/PostgreSQL/React 상태 확인, SecurityEvent 최소 모델, Nginx 샘플 또는 통제 로그 파싱, 정규화, PostgreSQL 저장, Django/DRF 조회 API, 기존 React EventTable의 실제 API 연결.
- **완료 조건:** 실제 Nginx 로그가 관제 PostgreSQL에 저장되고 API 응답과 브라우저 화면에서 같은 이벤트·원본 근거를 확인한다.
- **선행 조건:** 실제 Source of Truth와 기존 실행 상태 확인. D1 장비 확보가 없어도 샘플 로그로 첫 Slice를 시작할 수 있다.

## Phase 2 — SSH 로그와 수집 상태 연결

- **목표:** 두 번째 필수 로그를 같은 SecurityEvent 흐름에 연결하고 수집·정규화 실패를 확인한다.
- **구현할 최소 항목:** Linux SSH 인증 로그 파싱·정규화, 피해 서버 rsyslog/imfile, TCP 5514 Python 수집기, LogSourceStatus, NormalizationFailure.
- **완료 조건:** 실제 또는 통제 로그에서 Nginx·SSH 이벤트가 각각 저장되고, 수신 상태와 정규화 실패 원본·이유가 조회된다.
- **선행 조건:** Phase 1 데이터·API 연결. 장비 대여, 실제 로그 위치·형식, 학교 LAN·WSL2 연결은 이 Phase에서 `[검증 예정]` 작업으로 확인한다.

## Phase 3 — 탐지 3종과 Alert

- **목표:** 정규화 이벤트에서 세 가지 설명 가능한 경보를 생성하고 근거를 연결한다.
- **구현할 최소 항목:** SSH brute force(동일 IP·60초·실패 5회), Nginx scan(60초·404/403·서로 다른 URI 10개), Nginx suspicious path(초기 8개 path, query string 제외 정확/하위 일치), Alert와 SecurityEvent 근거 연결.
- **완료 조건:** 각 규칙의 조건 충족·불충족 입력을 확인하고 Alert의 규칙·출발지 IP·시각·근거를 화면에서 설명한다.
- **선행 조건:** Phase 2의 실제 정규화 이벤트와 원본 근거. 실제 수치는 통제 테스트로 검증한다.

## Phase 4 — 상관분석·위험도·Incident

- **목표:** 관련 Alert를 연결하고 점수·등급과 Incident 구분을 저장·조회한다.
- **구현할 최소 항목:** 동일 IP의 SSH brute force와 Nginx scan 또는 suspicious path가 10분 이내 함께 발생하는 CorrelationResult, 종류별 1회 점수와 +30 상관분석 가산·최대 100·등급, High(70 이상) Incident, 관련 근거 API 연결.
- **완료 조건:** 성립·불성립 시나리오를 구분하고 Low/Medium/High와 Alert/Incident 관계를 C 화면에서 설명한다.
- **선행 조건:** Phase 3 Alert와 실제 상관분석 검증 시나리오. 판단 대상 기간의 구체 구조는 구현 전에 문서 기준에 맞춰 확정한다.

## Phase 5 — SSH 자동 대응과 효과 검증

- **목표:** Alert 발생부터 UFW 차단과 실제 효과 검증까지를 백엔드에서 수행한다.
- **구현할 최소 항목:** 허용 목록 선검사, 관제 서버→피해 서버 SSH 원격 실행, UFW 차단, ResponseRecord, UFW 규칙 확인·동일 Kali SSH 재접속·ResponseVerification, 수동 해제 확인.
- **완료 조건:** 상관분석·Incident 없이 SSH brute force Alert에서 실행되며, 실행 결과와 검증 결과가 분리 저장된다. UFW 규칙 존재와 동일 Kali 접속 실패가 함께 확인될 때만 검증 성공으로 기록한다.
- **선행 조건:** 실제 피해 장비, 학교 LAN, SSH 포트·계정·최소 권한·허용 목록 IP를 검증하고 통제된 실습만 수행한다.

## Phase 6 — A~D 화면과 통합 시연

- **목표:** 네 화면을 실제 API 데이터와 실패 상태에 연결하고 전체 시연 기록을 완성한다.
- **구현할 최소 항목:** A 관제 대시보드, B 이벤트 목록/상세, C Alert·Incident 목록/상세, D 대응 결과/검증, 로딩·빈 데이터·조회 오류·미검증 표시, 예비 로그 준비.
- **완료 조건:** 공격 발생 → 로그 → SecurityEvent → 탐지 근거 → Alert → 필요 시 분석 → 자동 대응 → UFW·Kali 재접속 검증을 화면과 저장 기록으로 설명한다. Nginx 두 탐지와 상관분석 별도 검증도 남긴다.
- **선행 조건:** Phase 1~5의 실제 연결과 실패 기록. 예비 로그 재생으로 실제 IP 차단 성공을 주장하지 않는다.

## READY TO CODE 판정

문서 기준으로 사용자 결정은 D1~D22까지 정리되었고, 실제 환경 미확인 사항은 필요한 Phase의 `[검증 예정]` 작업으로 분리했다. PRD의 두 로그, 탐지 3종, 상관분석, 위험도·Incident, 자동 대응·효과 검증, A~D 화면이 데이터·API와 연결되어 있다. 기술 스택도 Python/Django/DRF, React/Vite, PostgreSQL, Docker 계열로 정리되어 있으며, Phase 1은 샘플 로그로 즉시 시작할 수 있다.

따라서 문서상 구현 준비 조건을 충족한다.

**READY TO CODE**

READY TO CODE는 구현 준비 판정이며 같은 응답에서 코드를 시작하지 않는다. 실제 장비 대여·학교 LAN·로그 위치 검증은 해당 Phase에서 수행한다. 첫 구현 작업은 다음과 같다.

**T1. 기존 실제 구현 저장소와 기존 Docker/Django/PostgreSQL/React 상태를 확인하고, Nginx 샘플 로그 1건이 SecurityEvent로 저장되어 Django/DRF API와 기존 EventTable에 표시되는 Vertical Slice 범위를 확정한다.**

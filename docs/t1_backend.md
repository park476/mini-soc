# T1 backend 구현 메모

범위: controlled Nginx sample → 파싱·정규화 → SecurityEvent 저장 → 조회 API.
실제 피해 서버에서 수집한 로그나 공격 증거가 아니다. 샘플은 문서용 IP를 사용하는 Nginx combined 형식 한 줄이다.

## 데이터 매핑

STEP 4의 필드만 사용한다. id는 Django 기본 BigAutoField, raw_log는 원문 문자열,
ssh_evidence는 선택 문자열이다. SSH 파싱은 구현하지 않는다.
Nginx HTTP method를 action, HTTP status의 문자열을 result에 저장한다.
이는 HTTP 응답 결과이며 탐지·위험도 판단이 아니다.
request_path는 query string만 제거하며 디코딩이나 대소문자 변환을 하지 않는다.
event_time은 원본 시간대가 포함된 시각이고 created_at은 DB 저장 시각이다.
원문은 줄 끝까지 보존한다.

## 입력과 조회

`import_nginx_sample <path>`는 UTF-8 파일 한 줄만 받는다. 잘못된 형식·IP·시각·상태 코드,
지원하지 않는 요청 대상 또는 파일 읽기 오류는 CommandError로 보고하며 저장하지 않는다.
DB 저장 오류도 실패로 전파한다. NormalizationFailure 테이블은 이번 범위에 없다.
반복 실행하면 별도 이벤트를 저장하므로 같은 샘플을 불필요하게 재입력하지 않는다.

- GET `/api/events/`: 발생 시각·id 내림차순 JSON 배열. T1에서는 페이지네이션 없음.
- GET `/api/events/{id}/`: 같은 serializer의 단일 객체, 원본 포함. 없으면 404.
- 두 응답은 모델의 문서상 11개 필드를 반환한다. Alert 관계는 아직 구현하지 않는다.
- 쓰기 API는 없다. 현재 API는 기본 DRF 설정에 따른 로컬 개발용 조회이며 인증 정책은 후속 확인 대상이다.

## 기존 환경에서 수행할 검증

아래는 Django 의존성과 기존 환경변수가 준비된 backend 컨테이너 내부 명령이다.
새 secret이나 비밀번호를 생성하지 않으며 `.env` 내용을 출력하지 않는다.

```sh
python manage.py check
python manage.py makemigrations --check --dry-run
python manage.py test events
python manage.py migrate
python manage.py import_nginx_sample events/samples/nginx_access.log
```

초기 migration은 작성 당시 작업 환경에 Django가 없어 수동 작성했다.
테스트 실행에는 테스트 DB 생성 권한이 필요하다.

## 2026-09-21 최종 리뷰 상태

- 사용자 확인 완료: PostgreSQL healthy, Django check, migration 일치 검사,
  events 테스트 6개, migrate, controlled sample의 SecurityEvent id=1 저장,
  목록·상세 API, Vite proxy HTTP 200, 브라우저 EventTable의 실제 이벤트 표시.
- 이번 리뷰의 Docker 재검증은 소켓 권한 오류로 차단되었다. 샌드박스 밖 재시도도
  실패했으므로 사용자 확인 결과를 이번 실행 결과로 간주하지 않는다.
- EventTable은 `fetch('/api/events/')`를 사용하며 로딩·빈 목록·조회 오류를 구분한다.
- `ALLOWED_HOSTS`는 backend, localhost, 127.0.0.1로 제한되어 있다.
  Compose 공개 포트는 loopback에 바인딩되어 있다. DEBUG와 인증 없는 조회 API는
  현재 로컬 개발용 설정이며 외부 공개 운영 준비 완료를 뜻하지 않는다.
- `mockEvents.js`는 미사용이지만 사용자 결정 전까지 삭제하지 않는다.
- 피해 서버 로그 전달, SSH 파싱, 탐지·경보·상관분석·자동 대응은 구현하지 않았다.

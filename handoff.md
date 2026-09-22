# Handoff: Vaultwarden + 1Password-style Chrome Extension

## 배경
사용자가 1Password 대신 셀프호스팅 Vaultwarden + 자체 제작 Chrome 확장(Keyfort)을
써보고 싶어해서 로컬 맥미니에 전체 스택을 구축했다. 지금은 동작 프로토타입 단계이며,
보안 하드닝과 UX 다듬기가 남아있다.

## 현재 인프라 상태

### Vaultwarden 서버 (Docker)
- 위치: `~/vaultwarden/`
- `docker-compose.yml`: vaultwarden/server:latest, 포트 8080(내부 HTTP), 3012(websocket)
- `DOMAIN=https://localhost:8443` (HTTPS 프록시 뒤에 있다고 서버에 알려주는 용도)
- `ADMIN_TOKEN`은 `~/vaultwarden/.env`에 평문 저장 (하드닝 필요 — 아래 TODO 참고)
- 데이터 볼륨: `~/vaultwarden/data` (영구 저장)
- 컨테이너명: `vaultwarden`, `docker compose up -d`로 기동/재기동

### HTTPS 종단 (Caddy)
- 최신 Vaultwarden 웹볼트는 Web Crypto API의 secure-context 요구사항 때문에
  평범한 HTTP(localhost 포함)로는 계정 생성/로그인이 막힌다
  ("Insecure URL not allowed. All URLs must use HTTPS.")
- 해결: mkcert로 로컬 신뢰 CA 발급 + Caddy로 TLS 종단
  - 인증서: `~/vaultwarden/certs/{cert.pem,key.pem}` (localhost, 127.0.0.1, ::1 대상)
  - `~/vaultwarden/Caddyfile`: `https://localhost:8443` → `reverse_proxy http://localhost:8080`
  - mkcert 루트 CA는 `mkcert -install`로 시스템 키체인에 등록 완료 (사용자가 직접 sudo 암호 입력해서 처리함)
  - Caddy는 `caddy run --config Caddyfile --adapter caddyfile`로 백그라운드 실행 중
- 최종 접속 URL: **https://localhost:8443**

### 테스트 계정
- 이메일: `test@localhost.local`
- 마스터 비밀번호: 저장소에 기록하지 않음. 환경변수 `VW_PASSWORD`로 주입 (`VW_EMAIL=test@localhost.local VW_PASSWORD=… node test-login.mjs`, 서버는 `VW_SERVER`, 기본값 https://localhost:8443). 실사용 시 반드시 교체 요망
- vault 안에 테스트 로그인 아이템 1개 존재: "Example Test Login"
  (username/password/TOTP seed 값은 문서에 기록하지 않음 — 웹볼트에서 확인)

## Chrome 확장: Keyfort
- 위치: `~/Utils/1pw-clone/`
- Manifest V3, 압축해제 상태로 Chrome에 로드됨 (`chrome://extensions` 개발자 모드)
- 확장 ID: `pfjklhbieaoaoaejajfbfbekkfehpnpb` (재로드하면 바뀔 수 있음)

### 파일 구조
```
1pw-clone/
  manifest.json
  src/
    background.js   — MV3 서비스워커: 로그인/세션/sync/vault 조회 메시지 라우터
    popup.html/js/css — 1Password 스타일 다크 UI (로그인 폼, vault 목록, 상세보기, TOTP)
    content.js       — 페이지의 로그인 폼 감지 + 자동입력 (username/password input 탐색)
    options.html
    lib/
      crypto.js — Bitwarden 호환 클라이언트 암호화 (PBKDF2, HKDF stretch, AES-256-CBC+HMAC EncString, TOTP RFC6238)
      api.js    — VaultwardenClient: prelogin/login(/identity/connect/token)/refresh/sync(/api/sync)
  test-login.mjs    — Node로 로그인+sync 검증 스크립트
  test-decrypt.mjs  — Node로 cipher 복호화(비번/TOTP) 검증 스크립트
  test-form.html    — 자동입력 테스트용 더미 로그인 폼
```

### 암호화 구현 (src/lib/crypto.js) — Bitwarden 프로토콜 기준
1. `deriveMasterKey(password, email, iterations)` — PBKDF2-SHA256, salt=email, 기본 600000회
2. `hashMasterKey(masterKey, password)` — 서버 로그인용 마스터패스워드 해시 (PBKDF2 1회, salt=password)
3. `stretchKey(masterKey)` — HKDF-Expand(HMAC-SHA256)로 encKey/macKey 각 32바이트 도출
4. `decryptSymmetricKey(encStr, stretched)` — 서버가 내려주는 사용자 대칭키(Key 필드) 복호화 → {encKey, macKey}
5. `decryptEncString/encryptString` — Bitwarden EncString 포맷 "2.iv|ct|mac" (AES-256-CBC + HMAC-SHA256) 암복호화
6. `generateTotp(secret, opts)` — RFC 6238 TOTP, otpauth:// URI도 파싱 가능

**중요**: 이 로직은 `test-login.mjs`, `test-decrypt.mjs`로 실제 서버 대상 end-to-end 검증 완료.
Node 22 환경에선 `globalThis.crypto/atob/btoa`가 이미 내장돼 있어 별도 polyfill 불필요
(WebCrypto 기반이라 브라우저 service worker에서도 동일 코드 그대로 동작).

### background.js 메시지 프로토콜
- `GET_STATUS` — 잠금 여부/이메일/서버URL 조회
- `LOGIN {serverUrl, email, password}` — 로그인 + 최초 sync, session storage에 저장
- `GET_CONFIG` — 저장된 serverUrl/email 조회 (잠금 후 로그인 화면 prefill용)
- `LOCK` — chrome.storage.session 초기화 (브라우저 재시작해도 자동 초기화됨 — session storage 특성)
- `SYNC` — 토큰 갱신 후 재동기화
- `GET_ITEMS` — 로그인 타입(type=1) cipher만 복호화해서 요약 목록 반환. 응답 `{ok, items, skipped}` (`skipped` = 복호화 불가 항목 수, popup이 목록 하단에 표시)
- `GET_ITEM_SECRETS {id}` — 특정 아이템의 비밀번호+TOTP 복호화
- (삭제됨) `AUTOFILL_MATCHES` / `AUTOFILL_GET_CREDENTIALS` — 더 이상 없음. 자동입력은 popup이 `DO_AUTOFILL`을 content script로 직접 전송
- **sender 정책**: content script/웹페이지(`sender.tab` 있는 발신)의 메시지는 `{ok:false, error:"forbidden"}`으로 거부, 확장 자신의 페이지(popup/options)만 허용
- **자동 잠금**: 메시지 처리 후 `chrome.alarms`로 15분 타이머 재설정, 만료 시 세션 삭제. 잠금 후 vault 관련 메시지는 `{ok:false, error:"Locked"}` 반환
- **잠금 시 popup 동작**: SYNC/GET_ITEMS/GET_ITEM_SECRETS/TOTP 갱신 응답이 `error:"Locked"`이면 `handleLockedResponse()`가 TOTP 타이머 정리 → `GET_CONFIG`로 prefill한 로그인 화면 전환 + "자동 잠금되었습니다" 토스트

### 검증된 동작 (ego-browser로 실제 Chrome에서 확인)
1. 팝업에서 서버URL/이메일/마스터비번 입력 → 로그인 성공
2. Vault 목록에 아이템 표시 (이름/사용자명/2FA뱃지)
3. 상세보기: 사용자명 복사, 비밀번호 마스킹+토글+복사, TOTP 코드 실시간 표시(6자리, 30초 갱신)
4. "이 탭에 자동입력" 클릭 → 임의 페이지의 email/password input에 정확한 값 주입 확인됨
   (content script는 `input[type=password]` 기준으로 폼을 찾고, 같은 form 내 그 앞의 text/email input을 username으로 추정)

### 검증 상태 / 테스트 실행
- 2026-09-22 리뷰/수정 라운드: 독립 코드 리뷰 후 수정 — 복사 절단, 세션 부활, 자동 잠금 도입(15분 alarms) 및
  popup 잠금 처리, MAC 다운그레이드 차단, sender 검증(content script 메시지 forbidden), 복호화 불가 항목 `skipped` 표시, 로그인 예외 시 버튼 고착 복구.
- 단위 테스트: `node --test test/*.test.mjs` (Node 25에서는 디렉터리 인자 `node --test test/`가 실패하므로 glob 사용)
- 서버 대상 검증 스크립트(`test-login.mjs`, `test-decrypt.mjs`) 환경변수: `VW_EMAIL`, `VW_PASSWORD`(필수), `VW_SERVER`(기본 https://localhost:8443)
- 미검증: popup의 `confirm()`(사이트 불일치 자동입력 확인)이 실제 Chrome 툴바 팝업에서 포커스 문제 없이 동작하는지 미확인

## 알려진 이슈 / 사용자가 겪은 트러블슈팅
1. **"Insecure URL not allowed"**: 최신 Vaultwarden이 HTTP localhost도 차단 → Caddy+mkcert로 해결
2. **"Failed to fetch" (확장에서 로그인 시도 시)**: mkcert CA가 키체인에는 있었지만
   "항상 신뢰"로 설정 안 돼 있었음(`mkcert -install`이 최초엔 sudo 프롬프트 타임아웃으로 실패).
   사용자가 터미널에서 직접 `mkcert -install` 실행 + sudo 암호 입력으로 해결.
   Chrome 완전 재시작 필요했음 (인증서 신뢰 캐시 때문).
3. Node.js 로그인 테스트 시 `NODE_TLS_REJECT_UNAUTHORIZED=0` 필요했음 (Node 네이티브 fetch가
   mkcert CA를 시스템 키체인에서 자동 신뢰하지 않음 — 로컬 검증 스크립트 한정 이슈, 브라우저는 무관)

## TODO / 다음에 개선할 것 (우선순위 순 아님, 사용자와 상의 필요)

### 보안 하드닝
- [ ] 클립보드 자동 클리어 (현재 "복사" 누르면 영구히 클립보드에 남음)
- [x] 팝업/세션 비활성 시 자동 잠금 타이머 (15분, chrome.alarms)
- [ ] `~/vaultwarden/.env`의 ADMIN_TOKEN 평문 저장 개선 (최소한 파일 퍼미션 600 확인, 가능하면 별도 secret 관리)
- [ ] CSP 강화, manifest의 host_permissions 범위 재검토 (`<all_urls>` 최소화 가능한지)
- [ ] mkcert 자체 서명 인증서는 로컬 전용 — 외부 접속 고려 시 진짜 CA(Let's Encrypt 등)로 교체 필요

### 기능
- [ ] content script가 페이지 로드시 "이 사이트에 저장된 계정 있음" 자동 배지/알림 (현재는 팝업 열어야만 알 수 있음)
- [ ] 새 로그인 저장 프롬프트 (현재는 Vaultwarden 웹앱에서만 아이템 추가 가능, 확장에서 저장 불가)
- [ ] 확장 아이콘 이미지 파일 없음 (Chrome 기본 아이콘 사용 중, PIL로 생성 시도했으나 사용자 승인 대기로 중단됨)
- [ ] 여러 개 password input이 있는 회원가입 폼 등 엣지케이스 처리
- [ ] refresh_token 만료/에러 처리 강화

### 1Password 대비 구조적 보안 격차 (참고용, 코드로 못 메꾸는 부분)
- 1Password는 마스터비번 + 별도 Secret Key(34자, 로컬 전용) 이중 방어 — Vaultwarden엔 이 레이어가 없음
- 1Password는 회사가 정기 3rd-party 보안감사 공개, Vaultwarden은 비공식 커뮤니티 구현체로 공식 감사 없음
- 셀프호스팅이므로 패치/침해대응/백업 전부 사용자 책임 (관리형 SaaS 대비)

## 다음 세션에서 확인할 것
- Docker 컨테이너(`vaultwarden`)와 Caddy 프로세스가 여전히 떠 있는지 (`docker ps`, `ps aux | grep caddy`)
  맥이 재부팅됐다면 둘 다 수동으로 다시 띄워야 함:
  ```bash
  cd ~/vaultwarden && docker compose up -d
  caddy run --config Caddyfile --adapter caddyfile &
  ```
- 확장은 압축해제 로드 상태라 Chrome 프로필이 바뀌거나 재설치되면 다시 로드해야 함

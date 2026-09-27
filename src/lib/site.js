// src/lib/site.js - URL/사이트 매칭 헬퍼. popup.js, background.js가 공유한다(content.js는 모듈을
//못 써서 isSameSiteHost를 자체적으로 따로 둔다 — 로직은 이 파일의 isSameSite와 같은 의도).

// "https://a.com/x" 또는 스킴 없는 "a.com" 모두에서 hostname을 뽑는다. 실패하면 null.
export function uriHostname(uri) {
  for (const candidate of [uri, `https://${uri}`]) {
    try {
      const { hostname } = new URL(candidate);
      if (hostname) return hostname.toLowerCase();
    } catch {
      // 스킴 없는 형태일 수 있으므로 다음 후보로 재시도
    }
  }
  return null;
}

// 전체 Public Suffix List를 넣는 대신 흔한 2단계 TLD만 다룬다.
// ponytail: 여기 없는 2단계 TLD(예: "example.co.jp"인데 목록에 없는 접미사)는 마지막 2개 라벨만
// base domain으로 보아 살짝 틀릴 수 있다 — 실제로 문제가 되면 psl류 라이브러리로 교체.
const SECOND_LEVEL_TLDS = new Set([
  "co.uk", "org.uk", "gov.uk", "ac.uk", "me.uk", "net.uk",
  "co.kr", "or.kr", "go.kr", "ac.kr", "ne.kr", "pe.kr",
  "co.jp", "or.jp", "ne.jp", "ac.jp", "go.jp",
  "com.au", "net.au", "org.au", "edu.au", "gov.au",
  "co.nz", "org.nz", "govt.nz",
  "co.in", "org.in", "net.in", "gov.in",
  "com.br", "com.cn", "com.mx", "com.tw", "com.sg", "com.hk",
]);

// eTLD+1 근사치: "a.b.example.com" -> "example.com". 알려진 2단계 TLD 위에서는 3라벨을 쓴다.
function baseDomain(hostname) {
  const labels = hostname.split(".");
  if (labels.length <= 2) return hostname;
  const lastTwo = labels.slice(-2).join(".");
  if (SECOND_LEVEL_TLDS.has(lastTwo)) return labels.slice(-3).join(".");
  return lastTwo;
}

// 정확히 같은 호스트이거나 base domain(eTLD+1)이 같으면 true — Bitwarden의 기본(Domain) 매치와 같다.
export function isSameSite(a, b) {
  if (!a || !b) return false;
  return a === b || baseDomain(a) === baseDomain(b);
}

// Bitwarden과 같은 URI 매치 감지(Login URI의 match 값) 상수.
export const URI_MATCH = { DOMAIN: 0, HOST: 1, STARTS_WITH: 2, EXACT: 3, REGULAR_EXPRESSION: 4, NEVER: 5 };

// savedUri: 항목에 저장된 그대로의 URI 문자열(복호화된 평문). matchType: 그 URI의 match 값(null이면 기본값인
// Domain). currentUrl: 지금 보고 있는 탭/프레임의 전체 URL.
export function uriMatches(savedUri, matchType, currentUrl) {
  if (!savedUri || !currentUrl) return false;
  if (matchType === URI_MATCH.NEVER) return false;
  if (matchType == null || matchType === URI_MATCH.DOMAIN) {
    return isSameSite(uriHostname(savedUri), uriHostname(currentUrl));
  }
  if (matchType === URI_MATCH.HOST) {
    // ponytail: hostname만 비교한다(Bitwarden 본가는 포트/스킴도 본다) — 서브도메인만 안 섞이면
    // 충분한 경우가 대부분. 포트로 구분해야 하는 사례가 생기면 URL(...).host로 바꾸기.
    const a = uriHostname(savedUri);
    const b = uriHostname(currentUrl);
    return !!a && a === b;
  }
  if (matchType === URI_MATCH.STARTS_WITH) return currentUrl.startsWith(savedUri);
  if (matchType === URI_MATCH.EXACT) return currentUrl === savedUri;
  if (matchType === URI_MATCH.REGULAR_EXPRESSION) {
    try {
      return new RegExp(savedUri).test(currentUrl);
    } catch {
      return false; // 잘못된 정규식이면 조용히 매칭 안 함으로 처리한다
    }
  }
  return false;
}

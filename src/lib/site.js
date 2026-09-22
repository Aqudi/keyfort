// src/lib/site.js - URL/사이트 매칭 헬퍼. popup.js, background.js, content.js가 공유한다.

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

// 정확히 같은 호스트이거나 한쪽이 다른 쪽의 서브도메인이면 true.
export function isSameSite(a, b) {
  if (!a || !b) return false;
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

// src/brand.js - 제품 이름과 로고 마크. 팝업의 헤더는 모두 여기서 만든다.
// (manifest.json / popup.html / options.html은 정적 파일이라 이름을 직접 적어둔다.)

export const BRAND_NAME = "Keyfort";

// key + fort: 방패(요새) 안에 키홀. icons/icon.svg와 같은 모양.
const MARK = `<svg class="mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3.2 18.4 5.7 18.4 11.4C18.4 15.9 15.3 19.4 12 20.7 8.7 19.4 5.6 15.9 5.6 11.4L5.6 5.7Z"/><circle cx="12" cy="10.6" r="1.5"/><path d="M12 12.1V14.6"/></svg>`;

export function brandHtml() {
  return `<div class="brand">${MARK}${BRAND_NAME}</div>`;
}

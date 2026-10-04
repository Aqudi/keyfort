// src/content.js - detects login forms, autofills on request, and offers an in-page
// overlay (Shadow DOM) to save new logins / pick a saved account, like 1Password's
// inline UI. MV3 content scripts cannot open the toolbar popup on their own, so this
// overlay is the only way to surface "저장할까요?" / "이 계정으로 로그인" without a click
// on the extension icon. Host matching for saved items always happens in background.js
// (using the authoritative sender.tab.url), never here — a page must not be trusted to
// self-report its own host.

// open shadow root 안까지 내려가며 selector에 맞는 요소를 모은다(웹 컴포넌트 기반 로그인 폼 대응).
// ponytail: closed shadow root는 못 본다 — 필요해지면 chrome.dom.openOrClosedShadowRoot로 확장.
// 문서에 건 MutationObserver는 shadow root 안쪽 변경을 못 보므로, 찾은 shadow root마다 따로 관찰한다.
// ponytail: 매 스캔마다 전체 DOM을 훑는다(스로틀 300ms) — 거대한 페이지에서 느리면 변경된 노드만 보도록 바꾸기.
const observedRoots = new WeakSet();
function deepQueryAll(selector, root = document) {
  const out = Array.from(root.querySelectorAll(selector));
  for (const el of root.querySelectorAll("*")) {
    if (!el.shadowRoot) continue;
    if (!observedRoots.has(el.shadowRoot)) {
      observedRoots.add(el.shadowRoot);
      domObserver.observe(el.shadowRoot, { childList: true, subtree: true });
    }
    out.push(...deepQueryAll(selector, el.shadowRoot));
  }
  return out;
}

// offsetParent는 position:fixed 요소에서 null이라 로그인 모달을 놓친다. 실제 렌더 박스로 판단한다.
function isVisible(el) {
  if (el.disabled || el.readOnly || el.getClientRects().length === 0) return false;
  const style = getComputedStyle(el);
  return style.visibility !== "hidden" && style.display !== "none";
}

const USERNAME_HINT = /user|email|e-mail|login|account|identifier|아이디|이메일/i;

function looksLikeUsername(el) {
  const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
  if (ac.includes("username") || ac.includes("email")) return true;
  if (el.type === "email") return true;
  return USERNAME_HINT.test(`${el.name} ${el.id} ${el.placeholder} ${el.getAttribute("aria-label") || ""}`);
}

// 비밀번호 칸이 있으면 {username?, password}, 없으면 이메일만 받는 단계(Google 등)를 {username, password: null}로 본다.
// type="password"라도 OTP/2FA 코드 칸(예: github.com/sessions/two-factor/app)이면 제외한다 — 그런 칸도
// 가리려고 password 타입을 쓰는 사이트가 있는데, 그걸 실제 로그인 비밀번호로 착각해 저장 제안을 하면 안 된다.
function findLoginFields() {
  const passwordInput = deepQueryAll('input[type="password"]').find((el) => isVisible(el) && !looksLikeOtpField(el)) || null;
  const textInputs = deepQueryAll('input[type="text"], input[type="email"], input[type="tel"], input:not([type])').filter(isVisible);

  if (passwordInput) {
    const scope = passwordInput.closest("form");
    const before = textInputs.filter(
      (el) => (!scope || scope.contains(el)) && el.compareDocumentPosition(passwordInput) & Node.DOCUMENT_POSITION_FOLLOWING
    );
    // 비밀번호 칸 바로 앞의 username스러운 칸 → 없으면 바로 앞 칸.
    const usernameInput = before.reverse().find(looksLikeUsername) || before[0] || null;
    return { usernameInput, passwordInput };
  }

  // ponytail: 검색창 오탐을 막으려고 이메일 단계는 username 힌트가 명확한 칸만 인정한다.
  const usernameInput = textInputs.find((el) => looksLikeUsername(el) && el.type !== "search");
  return usernameInput ? { usernameInput, passwordInput: null } : null;
}

// ---- 사이트별 패턴 ----------------------------------------------------------
// 일반 휴리스틱(OTP_HINT, otpFieldSelectors 아래 기본 선택자 등)이 특정 사이트의 마크업을 못 잡을 때를
// 위한 확장점. 새 사이트 지원은 아래 배열에 객체 하나만 추가하면 된다 — 이 파일의 다른 코드는
// 건드릴 필요 없다(오픈소스 기여 시 이 배열만 리뷰하면 됨).
//   host: 정확히 일치하거나 이 사이트의 서브도메인이면 적용된다(예: "github.com"은 gist.github.com에도 매칭).
//   otpFieldSelectors: 이 사이트의 2FA 코드 입력칸을 가리키는 CSS 선택자 배열. 일반 휴리스틱보다 먼저 시도된다.
//   secretTextSelectors: "직접 입력" 식으로 보여주는 base32 시크릿 텍스트를 담은 요소의 CSS 선택자 배열.
// 예:
// const SITE_PATTERNS = [
//   { host: "example.com", otpFieldSelectors: ["#custom-otp-input"], secretTextSelectors: [".setup-key-value"] },
// ];
const SITE_PATTERNS = [];

function sitePatternsFor(host) {
  return SITE_PATTERNS.filter((p) => isSameSiteHost(host, p.host));
}

const OTP_HINT = /otp|onetime|one-time|2fa|mfa|totp|verification.?code|security.?code|auth.?code|인증\s*(코드|번호)|보안\s*코드/i;

function looksLikeOtpField(el) {
  const ac = (el.getAttribute("autocomplete") || "").toLowerCase();
  if (ac.includes("one-time-code")) return true;
  return OTP_HINT.test(`${el.name} ${el.id} ${el.placeholder} ${el.getAttribute("aria-label") || ""}`);
}

// 비밀번호 단계 뒤에 별도 페이지/단계로 뜨는 2FA 입력칸. findLoginFields()가 아무것도 못 찾았을 때만
// (= 로그인 폼이 아닌 페이지) 찾는다 — 그래야 이메일/비밀번호 칸을 OTP로 오인하지 않는다.
function findOtpField() {
  for (const p of sitePatternsFor(location.hostname)) {
    for (const sel of p.otpFieldSelectors || []) {
      const el = deepQueryAll(sel).find(isVisible);
      if (el) return el;
    }
  }
  const inputs = deepQueryAll(
    'input[type="text"], input[type="tel"], input[type="number"], input[type="password"], input:not([type])'
  ).filter(isVisible);
  return inputs.find(looksLikeOtpField) || null;
}

// React/Vue 등은 value setter를 가로채므로 프로토타입 setter로 넣고, 실제 타이핑처럼 이벤트를 흘린다.
function fillInput(input, value) {
  input.focus();
  input.dispatchEvent(new KeyboardEvent("keydown", { bubbles: true }));
  const desc = Object.getOwnPropertyDescriptor(Object.getPrototypeOf(input), "value");
  if (desc?.set) desc.set.call(input, value);
  else input.value = value;
  input.dispatchEvent(new InputEvent("input", { bubbles: true, composed: true, inputType: "insertText", data: value }));
  input.dispatchEvent(new KeyboardEvent("keyup", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
  input.blur();
}

const SUBMIT_TEXT = /log ?in|sign ?in|next|continue|submit|로그인|다음|계속|확인/i;

// 사용자가 하듯 "로그인/다음" 버튼을 누르는 게 가장 안전하다(requestSubmit은 submit 핸들러가 없는 SPA에서
// 페이지를 엉뚱한 action URL로 보낼 수 있음). 버튼이 없으면 Enter 키 이벤트로 대신한다.
function submitFrom(input) {
  const scope = input.closest("form") || input.getRootNode();
  const buttons = Array.from(scope.querySelectorAll('button, input[type="submit"], [role="button"]')).filter(isVisible);
  const button =
    buttons.find((b) => b.type === "submit" && SUBMIT_TEXT.test(b.textContent || b.value || "")) ||
    buttons.find((b) => SUBMIT_TEXT.test(b.textContent || b.value || b.getAttribute("aria-label") || "")) ||
    buttons.find((b) => b.type === "submit");
  if (button) {
    button.click();
    return;
  }
  const opts = { key: "Enter", code: "Enter", keyCode: 13, bubbles: true, cancelable: true };
  input.dispatchEvent(new KeyboardEvent("keydown", opts));
  input.dispatchEvent(new KeyboardEvent("keypress", opts));
  input.dispatchEvent(new KeyboardEvent("keyup", opts));
}

// 페더레이션(SSO) 항목은 채울 아이디/비밀번호가 없다 — 저장된 그대로 이 사이트의 "Continue with
// Google" 같은 버튼을 찾아 대신 눌러준다(saveFederatedLogin이 username 자리에 provider 이름을 넣어둠).
const SSO_BUTTON_HINT = /continue|sign.?in|log.?in|로그인|계속/i;
function findProviderButton(provider) {
  if (!provider) return null;
  const candidates = deepQueryAll('button, a[role="button"], a').filter(isVisible);
  const providerRe = new RegExp(provider.replace(/[.*+?^${}()|[\]\\]/g, "\\$&"), "i");
  const withText = (el) => el.textContent || el.getAttribute("aria-label") || el.value || "";
  return (
    candidates.find((el) => providerRe.test(withText(el)) && SSO_BUTTON_HINT.test(withText(el))) ||
    candidates.find((el) => providerRe.test(withText(el))) ||
    null
  );
}

// 다단계 로그인(이메일 → 비밀번호[ → OTP])에서 앞 단계를 채운 항목과, 다음에 기다리는 단계.
// ponytail: 메모리에만 있어서 단계 사이에 전체 페이지 이동이 있으면 이어지지 않는다(SPA라면 괜찮음).
let pendingFillId = null;
let pendingFillStep = null; // "password" | "otp"

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "DO_AUTOFILL") {
    // 검증된 host와 지금 이 문서의 host가 다르면(그사이 이동함) 채우지 않는다.
    if (msg.host && location.hostname !== msg.host) {
      sendResponse({ ok: false, error: "페이지가 바뀌어 자동입력을 취소했습니다." });
      return;
    }
    const fields = findLoginFields();
    const otpField = fields ? null : findOtpField();
    if (!fields && !otpField) {
      sendResponse({ ok: false, error: "로그인 폼을 찾지 못했습니다." });
      return;
    }
    if (fields?.usernameInput && msg.username) fillInput(fields.usernameInput, msg.username);
    if (fields?.passwordInput && msg.password) fillInput(fields.passwordInput, msg.password);
    if (otpField && msg.totp) fillInput(otpField, msg.totp);
    const target = otpField || fields?.passwordInput || fields?.usernameInput;
    if (msg.submit && target) submitFrom(target);
    sendResponse({ ok: true, step: otpField ? "otp" : fields?.passwordInput ? "password" : "username" });
  }
  return true;
});

// ---- 인페이지 오버레이: 계정 선택 / 새 로그인 저장 제안 --------------------
// Shadow DOM(closed)에 그려서 페이지 CSS와 절대 충돌하지 않는다.

// 확장이 chrome://extensions에서 새로고침되면 이미 열려 있던 탭의 content script는 낡은
// chrome.runtime 참조를 들고 있게 된다. 그 상태에서 sendMessage를 부르면 프라미스가 아니라
// 그 자리에서 바로 예외를 던지므로(.catch로 못 잡음), 여기서 감싸 페이지 콘솔에 안 새게 한다.
// 이 경우 페이지를 새로고침해야 새 content script가 다시 붙는다 — 복구할 방법이 없다.
function send(msg) {
  try {
    return chrome.runtime.sendMessage(msg);
  } catch (err) {
    return Promise.reject(err);
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;");
}

// key + fort: brand.js, icons/icon.svg와 같은 방패+키홀 마크.
const MARK_SVG =
  '<svg class="m-mark" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.2 18.4 5.7 18.4 11.4C18.4 15.9 15.3 19.4 12 20.7 8.7 19.4 5.6 15.9 5.6 11.4L5.6 5.7Z"/><circle cx="12" cy="10.6" r="1.5"/><path d="M12 12.1V14.6"/></svg>';

const OVERLAY_STYLE = `
  .m-card {
    position: fixed; z-index: 2147483647; top: 16px; right: 16px; width: 400px; max-width: calc(100vw - 32px);
    background: #201f1c; color: #f0ede6; border: 1px solid #34322c; border-radius: 14px;
    box-shadow: 0 16px 40px rgba(0,0,0,.4); overflow: hidden;
    font: 15px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
    animation: m-in .16s ease-out;
  }
  @keyframes m-in { from { opacity: 0; transform: translateY(-6px); } }
  .m-head { display: flex; align-items: center; gap: 10px; padding: 14px 18px; border-bottom: 1px solid #34322c; }
  .m-mark { width: 22px; height: 22px; color: #f5a524; flex-shrink: 0; }
  .m-brand { font-weight: 700; font-size: 16px; }
  .m-host { color: #a09b8f; font-size: 13px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; flex: 1; }
  .m-close { background: none; border: none; color: #a09b8f; font-size: 24px; line-height: 1; cursor: pointer; padding: 0 2px; }
  .m-close:hover { color: #f0ede6; }
  .m-list { max-height: min(520px, calc(100vh - 110px)); overflow-y: auto; }
  .m-item {
    display: flex; align-items: center; gap: 14px; width: 100%; padding: 14px 18px; text-align: left;
    background: transparent; border: none; border-top: 1px solid #2a2823; color: inherit; font: inherit; cursor: pointer;
  }
  .m-item:first-child { border-top: none; }
  .m-item:hover, .m-item:focus-visible { background: #2a2823; outline: none; }
  .m-item:disabled { opacity: .5; cursor: default; }
  .m-avatar {
    width: 44px; height: 44px; border-radius: 11px; flex-shrink: 0; display: grid; place-items: center;
    font-weight: 700; font-size: 19px; color: #fff; overflow: hidden; position: relative;
  }
  .m-avatar img { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: contain; background: #fff; padding: 7px; box-sizing: border-box; }
  .m-text { min-width: 0; flex: 1; }
  .m-name { font-weight: 600; font-size: 16px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .m-user { color: #a09b8f; font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .m-go { color: #6b675e; font-size: 22px; }
  .m-recent { color: #f5a524; font-weight: 600; }
  .m-item.m-first { background: #26241f; }
  .m-badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 1px 6px; border-radius: 6px; margin-left: 6px; vertical-align: middle; }
  .m-badge-otp { background: #3a2f14; color: #f5a524; }
  .m-badge-sso { background: #1c2a3a; color: #6fa8dc; }
  .m-msg { padding: 14px 18px 4px; color: #a09b8f; font-size: 14px; }
  .m-row { display: flex; gap: 8px; justify-content: flex-end; padding: 4px 18px 18px; }
  .m-row button { border: none; border-radius: 8px; padding: 10px 18px; font: inherit; font-size: 14px; font-weight: 600; cursor: pointer; }
  .m-primary { background: #f5a524; color: #1c1306; }
  .m-secondary { background: #2a2823; color: #f0ede6; }
`;

let overlayHost = null;
let overlayShadow = null;

function overlayRoot() {
  if (overlayShadow) return overlayShadow;
  overlayHost = document.createElement("div");
  document.documentElement.appendChild(overlayHost);
  overlayShadow = overlayHost.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = OVERLAY_STYLE;
  overlayShadow.appendChild(style);
  return overlayShadow;
}

// 여기 뜨는 계정은 전부 이 사이트와 일치하는 항목이라 페이지 자신의 favicon이 곧 계정 아이콘이다.
// 외부 favicon 서비스를 쓰면 방문 사이트가 제3자에게 새므로 쓰지 않는다. 못 불러오면 첫 글자 아바타만 남는다.
// <link rel="icon">이 없는 페이지가 많아서(제일 흔한 경우), 후보를 여러 개 순서대로 본 뒤에야 /favicon.ico를 추측한다.
const FAVICON_LINK_SELECTORS = ['link[rel="icon"]', 'link[rel="shortcut icon"]', 'link[rel="apple-touch-icon"]', 'link[rel~="icon"]'];
function faviconUrl() {
  for (const sel of FAVICON_LINK_SELECTORS) {
    const href = document.querySelector(sel)?.href;
    if (href && /^https?:/.test(href)) return href;
  }
  return `${location.origin}/favicon.ico`;
}

function avatarHtml(label) {
  const text = String(label || "?");
  let hash = 0;
  for (const ch of text) hash = (hash * 31 + ch.codePointAt(0)) | 0;
  const icon = faviconUrl();
  return `<div class="m-avatar" style="background:hsl(${Math.abs(hash) % 360} 45% 38%)">${escapeHtml(text[0].toUpperCase())}${
    icon ? `<img src="${escapeHtml(icon)}" alt="">` : ""
  }</div>`;
}

function hideBrokenImages(el) {
  el.querySelectorAll(".m-avatar img").forEach((img) => img.addEventListener("error", () => img.remove()));
}

function cardHtml(body) {
  return `
    <div class="m-head">${MARK_SVG}<span class="m-brand">Keyfort</span><span class="m-host">${escapeHtml(location.hostname)}</span>
      <button class="m-close" aria-label="닫기">×</button></div>
    ${body}`;
}

function mountCard(body) {
  const el = document.createElement("div");
  el.className = "m-card";
  el.setAttribute("role", "dialog");
  el.setAttribute("aria-label", "Keyfort");
  el.innerHTML = cardHtml(body);
  overlayRoot().appendChild(el);
  el.querySelector(".m-close").addEventListener("click", () => el.remove());
  hideBrokenImages(el);
  return el;
}

function showSaveBanner({ host, username, password }) {
  const el = mountCard(`
    <div class="m-msg">이 로그인을 저장할까요?</div>
    <div class="m-item" style="cursor:default">${avatarHtml(host)}
      <div class="m-text"><div class="m-name">${escapeHtml(host)}</div><div class="m-user">${escapeHtml(username || "(사용자 이름 없음)")}</div></div></div>
    <div class="m-row">
      <button class="m-secondary" data-act="dismiss">무시</button>
      <button class="m-primary" data-act="save">저장</button>
    </div>`);
  el.querySelector('[data-act="dismiss"]').addEventListener("click", () => el.remove());
  el.querySelector('[data-act="save"]').addEventListener("click", async (e) => {
    e.target.disabled = true;
    const res = await send({ type: "SAVE_ITEM", host, username, password });
    if (res?.ok) {
      el.querySelector(".m-msg").textContent = "저장했습니다";
      el.querySelector(".m-row").remove();
      setTimeout(() => el.remove(), 1200);
    } else {
      el.querySelector(".m-msg").textContent = res?.error || "저장하지 못했습니다.";
      e.target.disabled = false;
    }
  });
}

// 일부 사이트는 "스캔 안 되나요?" 링크에 otpauth:// URI를 그대로 심어 두지만, 깃허브처럼 버튼 뒤에
// base32 시크릿 텍스트만 숨겨두는 곳도 많다("직접 입력" 다이얼로그). QR 이미지 자체를 디코딩하는 건
// 훨씬 비싸서(카메라/이미지 라이브러리) 스킵 — 필요해지면 추가.
// ponytail: 텍스트 쪽은 문맥 없이 아무 대문자 문자열이나 긁지 않도록, OTP 검증 칸이 있는 페이지에서
// secret/key/mono류 힌트가 붙은 요소만 본다. 그래도 보이지 않는 곳의 예시 값이 오탐될 수는 있다.
const BASE32_SECRET_RE = /^[A-Z2-7]{16,32}$/;
function findOtpSecret() {
  const link = deepQueryAll('a[href^="otpauth://"]')[0];
  if (link) return link.href;
  if (!findOtpField()) return null;
  for (const p of sitePatternsFor(location.hostname)) {
    for (const sel of p.secretTextSelectors || []) {
      const text = (deepQueryAll(sel)[0]?.textContent || "").trim();
      if (text) return text;
    }
  }
  for (const el of deepQueryAll('code, [class*="mono"], [class*="secret"], [class*="key"], [data-target*="secret"]')) {
    if (el.children.length) continue; // 텍스트만 가진 leaf 요소만
    const text = (el.textContent || "").trim();
    if (BASE32_SECRET_RE.test(text)) return text;
  }
  return null;
}

function saveTotpTo(secret, itemId) {
  return send({ type: "SAVE_TOTP", host: location.hostname, secret, itemId });
}

// candidates가 하나면 바로 확인 배너, 둘 이상이면(예: 같은 사이트에 계정이 여러 개) 로그인 계정
// 선택창과 같은 패턴으로 고르게 한다 — 안 그러면 background가 "특정할 수 없습니다"로 거부한다.
function showTotpBanner(secret, candidates) {
  if (candidates.length > 1) return showTotpPicker(secret, candidates);
  const item = candidates[0];
  const el = mountCard(`
    <div class="m-msg">이 사이트의 OTP(2단계 인증)를 저장할까요?</div>
    <div class="m-row">
      <button class="m-secondary" data-act="dismiss">무시</button>
      <button class="m-primary" data-act="save">저장</button>
    </div>`);
  el.querySelector('[data-act="dismiss"]').addEventListener("click", () => el.remove());
  el.querySelector('[data-act="save"]').addEventListener("click", async (e) => {
    e.target.disabled = true;
    const res = await saveTotpTo(secret, item.id);
    if (res?.ok) {
      el.querySelector(".m-msg").textContent = "저장했습니다";
      el.querySelector(".m-row").remove();
      setTimeout(() => el.remove(), 1200);
    } else {
      el.querySelector(".m-msg").textContent = res?.error || "저장하지 못했습니다.";
      e.target.disabled = false;
    }
  });
}

function showTotpPicker(secret, candidates) {
  const el = mountCard(`
    <div class="m-msg">이 OTP를 저장할 계정을 고르세요</div>
    <div class="m-list">${candidates
      .map((item, i) => {
        const { title, sub } = accountLines(item);
        return `
      <button class="m-item" data-i="${i}">${avatarHtml(item.username || item.name)}
        <div class="m-text"><div class="m-name">${title}${itemBadgesHtml(item)}</div>${sub ? `<div class="m-user">${sub}</div>` : ""}</div>
        <span class="m-go">›</span></button>`;
      })
      .join("")}</div>`);
  el.querySelectorAll(".m-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const item = candidates[Number(btn.dataset.i)];
      const res = await saveTotpTo(secret, item.id);
      if (res?.ok) {
        el.querySelector(".m-msg").textContent = "저장했습니다";
        el.querySelector(".m-list").remove();
        setTimeout(() => el.remove(), 1200);
      } else {
        btn.disabled = false;
        btn.querySelector(".m-text").insertAdjacentHTML("beforeend", `<div class="m-user">${escapeHtml(res?.error || "저장 실패")}</div>`);
      }
    });
  });
}

let lastOtpSecretShown = null;
async function checkOtpauth() {
  const secret = findOtpSecret();
  if (!secret || secret === lastOtpSecretShown) return;
  const matchRes = await send({ type: "GET_HOST_MATCHES" });
  const candidates = matchRes?.ok ? matchRes.items.filter((i) => !i.hasTotp) : [];
  if (!candidates.length) return; // 잠겨 있거나, 저장할 계정이 없거나, 전부 이미 있음
  lastOtpSecretShown = secret;
  showTotpBanner(secret, candidates);
}

// "Google로 로그인" 같은 페더레이션 로그인: 이 사이트엔 채울 비밀번호가 아예 없어서(신원을 다른
// 회사에 위임한 것) 일반 로그인 폼 저장 로직과는 다른 길이 필요하다. "어느 사이트가 어느 인증
// 도메인으로 로그인을 위임했는지"는 background가 chrome.tabs.onUpdated로 직접 추적한다(리다이렉트
// 체인 중간에서 Referrer-Policy가 origin을 지워버리는 사이트가 있어 document.referrer로는 못 미더웠음).
// 여기서는 그 결과(GET_PENDING_FEDERATED)를 물어보고 배너만 띄운다.
function showFederatedBanner(provider, host) {
  const el = mountCard(`
    <div class="m-msg">${escapeHtml(provider)}이(가) 이 사이트 로그인에 사용됨 — 저장할까요?</div>
    <div class="m-row">
      <button class="m-secondary" data-act="dismiss">무시</button>
      <button class="m-primary" data-act="save">저장</button>
    </div>`);
  el.querySelector('[data-act="dismiss"]').addEventListener("click", () => el.remove());
  el.querySelector('[data-act="save"]').addEventListener("click", async (e) => {
    e.target.disabled = true;
    const res = await send({ type: "SAVE_FEDERATED_LOGIN", host, provider });
    if (res?.ok) {
      el.querySelector(".m-msg").textContent = "저장했습니다";
      el.querySelector(".m-row").remove();
      setTimeout(() => el.remove(), 1200);
    } else {
      el.querySelector(".m-msg").textContent = res?.error || "저장하지 못했습니다.";
      e.target.disabled = false;
    }
  });
}

async function checkFederatedLogin() {
  const res = await send({ type: "GET_PENDING_FEDERATED" }).catch(() => null);
  if (res?.ok && res.pending) showFederatedBanner(res.pending.provider, location.hostname);
}

const relTime = new Intl.RelativeTimeFormat("ko", { numeric: "auto" });
function timeAgo(ts) {
  const sec = (ts - Date.now()) / 1000;
  for (const [unit, size] of [["year", 31536000], ["month", 2592000], ["day", 86400], ["hour", 3600], ["minute", 60]]) {
    if (Math.abs(sec) >= size) return relTime.format(Math.round(sec / size), unit);
  }
  return "방금";
}

// 저장 시 이름이 호스트로 자동 지정되므로(accounts.google.com 등) 그대로면 모든 줄이 같아 보인다.
// 그런 항목은 계정(사용자 이름)을 제목으로 올린다.
function accountLines(item) {
  const name = item.name || "";
  const hostLike = isSameSiteHost(name.toLowerCase(), location.hostname);
  const title = hostLike && item.username ? item.username : name || item.username || "(이름 없음)";
  const sub = [];
  if (!hostLike && item.username) sub.push(escapeHtml(item.username));
  if (item.lastUsedAt) sub.push(`<span class="m-recent">최근 사용 · ${escapeHtml(timeAgo(item.lastUsedAt))}</span>`);
  return { title: escapeHtml(title), sub: sub.join(" · ") };
}

// 목록에서 계정 종류를 한눈에 구분하려는 배지 — OTP(2단계 인증 있음), SSO(비밀번호 없이 다른 계정으로
// 로그인 위임된 항목, saveFederatedLogin이 만드는 종류). hasPassword가 없는 오래된 응답과도 호환되게
// 명시적으로 false일 때만 SSO로 본다(undefined면 그냥 표시 안 함).
function itemBadgesHtml(item) {
  const badges = [];
  if (item.hasTotp) badges.push('<span class="m-badge m-badge-otp">OTP</span>');
  if (item.hasPassword === false) badges.push('<span class="m-badge m-badge-sso">SSO</span>');
  return badges.join("");
}

function isSameSiteHost(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

// ---- 필드 앵커 계정 선택기 (1Password 스타일) -------------------------------
// 화면 우측 상단 고정 카드 대신, 로그인 입력창(비밀번호 있으면 그쪽, 없으면 아이디 칸)이나 OTP 칸 옆에
// 작은 아이콘을 그려 넣고 누르면 그 필드 바로 아래에 목록/폼이 뜬다. overlayHost/overlayShadow(저장·OTP
// 저장·federated 배너용)와는 완전히 분리된 별도 shadow root를 쓴다 — 그쪽 배너들의 생명주기와 엮이면
// 훗날 한쪽을 지울 때 다른 쪽까지 같이 사라지는 버그가 나기 쉽다.
const FIELD_ICON_SVG =
  '<svg viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round"><path d="M12 3.2 18.4 5.7 18.4 11.4C18.4 15.9 15.3 19.4 12 20.7 8.7 19.4 5.6 15.9 5.6 11.4L5.6 5.7Z"/><circle cx="12" cy="10.6" r="1.5"/><path d="M12 12.1V14.6"/></svg>';

const FIELD_STYLE = `
  .f-btn {
    all: unset; position: fixed; z-index: 2147483646; box-sizing: border-box;
    display: grid; place-items: center; width: 26px; height: 26px; border-radius: 7px;
    background: #201f1c; border: 1px solid #3a382f; color: #f5a524; cursor: pointer;
  }
  .f-btn:hover { background: #2a2823; }
  .f-btn svg { width: 15px; height: 15px; }
  .f-drop {
    position: fixed; z-index: 2147483647; width: 320px; max-width: calc(100vw - 24px);
    background: #201f1c; color: #f0ede6; border: 1px solid #34322c; border-radius: 12px;
    box-shadow: 0 16px 40px rgba(0,0,0,.4); overflow-y: auto; max-height: min(400px, calc(100vh - 80px));
    font: 15px/1.4 -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif; animation: f-in .12s ease-out;
  }
  @keyframes f-in { from { opacity: 0; transform: translateY(-4px); } }
  .m-item {
    display: flex; align-items: center; gap: 14px; width: 100%; padding: 14px 18px; text-align: left;
    background: transparent; border: none; border-top: 1px solid #2a2823; color: inherit; font: inherit; cursor: pointer;
  }
  .m-item:first-child { border-top: none; }
  .m-item:hover, .m-item:focus-visible { background: #2a2823; outline: none; }
  .m-item:disabled { opacity: .5; cursor: default; }
  .m-item.m-first { background: #26241f; }
  .m-avatar {
    width: 44px; height: 44px; border-radius: 11px; flex-shrink: 0; display: grid; place-items: center;
    font-weight: 700; font-size: 19px; color: #fff; overflow: hidden; position: relative;
  }
  .m-avatar img { position: absolute; inset: 0; width: 100%; height: 100%; object-fit: contain; background: #fff; padding: 7px; box-sizing: border-box; }
  .m-text { min-width: 0; flex: 1; }
  .m-name { font-weight: 600; font-size: 16px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .m-user { color: #a09b8f; font-size: 13.5px; overflow: hidden; text-overflow: ellipsis; white-space: nowrap; }
  .m-go { color: #6b675e; font-size: 22px; }
  .m-recent { color: #f5a524; font-weight: 600; }
  .m-badge { display: inline-block; font-size: 11px; font-weight: 700; padding: 1px 6px; border-radius: 6px; margin-left: 6px; vertical-align: middle; }
  .m-badge-otp { background: #3a2f14; color: #f5a524; }
  .m-badge-sso { background: #1c2a3a; color: #6fa8dc; }
  .f-unlock { padding: 16px 18px; }
  .f-unlock-title { font-weight: 700; font-size: 15px; margin-bottom: 10px; }
  .f-input {
    width: 100%; box-sizing: border-box; padding: 10px 12px; border-radius: 8px;
    border: 1px solid #3a382f; background: #161512; color: #f0ede6; font: inherit; margin-bottom: 10px;
  }
  .f-input:focus { outline: 2px solid #f5a524; outline-offset: -1px; }
  .f-primary {
    width: 100%; border: none; border-radius: 8px; padding: 10px; font: inherit; font-weight: 700;
    background: #f5a524; color: #1c1306; cursor: pointer;
  }
  .f-primary:disabled { opacity: .6; cursor: default; }
  .f-error { color: #e5484d; font-size: 13px; margin: -4px 0 10px; }
  .f-link { display: block; width: 100%; text-align: center; margin-top: 10px; background: none; border: none; color: #a09b8f; font-size: 13px; cursor: pointer; text-decoration: underline; }
`;

let fieldIconHost = null;
let fieldIconShadow = null;
function fieldIconRoot() {
  if (fieldIconShadow) return fieldIconShadow;
  fieldIconHost = document.createElement("div");
  document.documentElement.appendChild(fieldIconHost);
  fieldIconShadow = fieldIconHost.attachShadow({ mode: "closed" });
  const style = document.createElement("style");
  style.textContent = FIELD_STYLE;
  fieldIconShadow.appendChild(style);
  return fieldIconShadow;
}

// 1Password처럼 아이디 칸과 비밀번호 칸 둘 다에 아이콘이 붙을 수 있다(있는 칸만) — 그래서 단일 값이
// 아니라 입력칸별 Map으로 관리한다. 드롭다운은 한 번에 하나만 연다(어느 아이콘을 눌렀는지는 따로 추적).
const fieldIcons = new Map(); // input -> { btn }
let currentDropdown = null;
let currentDropdownInput = null;
const checkedNoResultInputs = new WeakSet(); // 매칭 없어서/잠기지 않았지만 빈 결과라 이미 확인해 본 필드
let iconRepositionTimer = null;

function positionOverInput(el, input) {
  const r = input.getBoundingClientRect();
  const size = 26;
  el.style.top = `${Math.round(r.top + (r.height - size) / 2)}px`;
  el.style.left = `${Math.round(r.right - size - 6)}px`;
}

function positionBelowInput(el, input) {
  const r = input.getBoundingClientRect();
  el.style.top = `${Math.round(r.bottom + 6)}px`;
  const left = Math.min(Math.max(8, r.right - 320), window.innerWidth - 320 - 8);
  el.style.left = `${Math.round(left)}px`;
}

function closeFieldDropdown() {
  currentDropdown?.remove();
  currentDropdown = null;
  if (currentDropdownInput) fieldIcons.get(currentDropdownInput)?.btn.setAttribute("aria-expanded", "false");
  currentDropdownInput = null;
}

// 방향키(위/아래)로 항목 이동 — 1Password의 실제 계정 메뉴와 같은 패턴("아래쪽 화살표 키로 선택하세요").
// activeElement는 shadowRoot 기준으로 읽어야 한다 — document.activeElement는 closed shadow root
// 안에서는 항상 그 host로 리타깃되어 못 쓴다.
function wireMenuKeyboardNav(container, shadowRoot) {
  container.addEventListener("keydown", (e) => {
    if (e.key !== "ArrowDown" && e.key !== "ArrowUp") return;
    e.preventDefault();
    const items = [...container.querySelectorAll(".m-item")];
    if (!items.length) return;
    const idx = items.indexOf(shadowRoot.activeElement);
    const next = e.key === "ArrowDown" ? items[idx + 1] || items[0] : items[idx - 1] || items[items.length - 1];
    next.focus();
  });
  container.querySelector(".m-item")?.focus();
}

function removeFieldIcon(input) {
  const entry = fieldIcons.get(input);
  if (!entry) return;
  entry.btn.remove();
  fieldIcons.delete(input);
  if (currentDropdownInput === input) closeFieldDropdown();
}

function removeAllFieldIcons() {
  for (const input of [...fieldIcons.keys()]) removeFieldIcon(input);
  if (iconRepositionTimer) {
    clearInterval(iconRepositionTimer);
    iconRepositionTimer = null;
  }
}

// 스크롤/리사이즈 이벤트만으로는 못 잡는 레이아웃 변화(애니메이션, 동적 삽입 등)까지 커버하려고
// 짧은 주기로 폴링한다 — 이 파일의 다른 스캔들과 같은 절충(코멘트: "스로틀 300ms").
function repositionFieldIcons() {
  for (const [input, entry] of [...fieldIcons.entries()]) {
    if (!input.isConnected || !isVisible(input)) {
      removeFieldIcon(input);
      continue;
    }
    positionOverInput(entry.btn, input);
  }
  if (currentDropdown && currentDropdownInput) {
    if (!currentDropdownInput.isConnected) closeFieldDropdown();
    else positionBelowInput(currentDropdown, currentDropdownInput);
  }
  if (fieldIcons.size === 0 && iconRepositionTimer) {
    clearInterval(iconRepositionTimer);
    iconRepositionTimer = null;
  }
}

// 필드 아이콘 드롭다운의 공통 뼈대(로그인 계정 선택 / OTP 채우기 제안이 둘 다 재사용) — 목록을 그리고
// 위치를 잡고 키보드 네비게이션을 붙인다. 항목 클릭 시 실제로 뭘 할지는 onSelect가 정한다.
function renderAccountMenu(input, items, onSelect) {
  closeFieldDropdown();
  const el = document.createElement("div");
  el.className = "f-drop";
  el.setAttribute("role", "menu");
  el.innerHTML = items
    .map((item, i) => {
      const { title, sub } = accountLines(item);
      return `
      <button class="m-item${i === 0 && item.lastUsedAt ? " m-first" : ""}" role="menuitem" data-i="${i}">${avatarHtml(item.username || item.name)}
        <div class="m-text"><div class="m-name">${title}${itemBadgesHtml(item)}</div>${sub ? `<div class="m-user">${sub}</div>` : ""}</div>
        <span class="m-go">›</span></button>`;
    })
    .join("");
  fieldIconRoot().appendChild(el);
  hideBrokenImages(el);
  positionBelowInput(el, input);
  currentDropdown = el;
  currentDropdownInput = input;
  fieldIcons.get(input)?.btn.setAttribute("aria-expanded", "true");
  wireMenuKeyboardNav(el, fieldIconShadow);

  el.querySelectorAll(".m-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const item = items[Number(btn.dataset.i)];
      const ok = await onSelect(item, btn);
      if (!ok) btn.disabled = false;
    });
  });
}

function openFieldDropdown(input, items) {
  renderAccountMenu(input, items, async (item, btn) => {
    // 페더레이션 항목(비밀번호 없음) — 채울 게 없으니 그 제공자의 "Continue with ___" 버튼을 대신 눌러준다.
    if (item.hasPassword === false) {
      const providerBtn = findProviderButton(item.username);
      if (!providerBtn) {
        btn.querySelector(".m-text").insertAdjacentHTML(
          "beforeend",
          `<div class="m-user">이 페이지에서 "${escapeHtml(item.username || "해당")}" 로그인 버튼을 못 찾았습니다.</div>`
        );
        return false;
      }
      removeAllFieldIcons();
      providerBtn.click();
      return true;
    }
    const res = await send({ type: "REQUEST_AUTOFILL", id: item.id, submit: true });
    if (!res?.ok) {
      btn.querySelector(".m-text").insertAdjacentHTML("beforeend", `<div class="m-user">${escapeHtml(res?.error || "자동입력 실패")}</div>`);
      return false;
    }
    removeAllFieldIcons();
    // 이메일만 채운 단계면 다음 화면(비밀번호)을, 비밀번호까지 채웠고 이 계정에 TOTP가 있으면
    // 다음 화면(OTP)을 기다린다.
    const after = findLoginFields();
    if (!after?.passwordInput) setPendingFill(item.id, "password");
    else if (res.hasTotp) setPendingFill(item.id, "otp");
    return true;
  });
}

// OTP 칸은 절대 자동으로 안 채운다 — 틀린 코드로 사이트가 자동 제출한 뒤 새로고침되면 또 채우는 식으로
// 실제 계정이 잠긴 적이 있어서(GitHub), 이제는 필드 아이콘으로 "채울까요?" 제안만 하고 클릭해야 채운다.
// 후보가 하나면 바로 채우고(그래도 클릭이 있어야만), 여럿이면 고르게 한다. 제출은 절대 안 한다.
function openOtpMenu(input, items) {
  if (items.length === 1) {
    fillOtp(items[0]);
    return;
  }
  renderAccountMenu(input, items, (item) => fillOtp(item));
}

async function fillOtp(item) {
  const res = await send({ type: "REQUEST_AUTOFILL", id: item.id }).catch(() => null); // submit 없음
  if (res?.ok) removeAllFieldIcons();
  return !!res?.ok;
}

// 지금 폼의 아이디/비번 칸을 다시 스캔해서(잠금 해제 직후처럼) 아이콘을 새로 붙인다. 매칭된 계정이
// 있으면 그 목록을 돌려준다(호출한 쪽에서 바로 드롭다운을 열지 결정하게).
async function refreshFieldIcons() {
  const fields = findLoginFields();
  if (!fields) return null;
  const matchRes = await send({ type: "GET_HOST_MATCHES" }).catch(() => null);
  removeAllFieldIcons();
  if (!matchRes?.ok) return null;
  const targets = [fields.usernameInput, fields.passwordInput].filter(Boolean);
  if (matchRes.locked) {
    for (const t of targets) attachFieldIcon(t, [], { locked: true });
    return null;
  }
  if (matchRes.items?.length) {
    for (const t of targets) attachFieldIcon(t, matchRes.items);
    return matchRes.items;
  }
  return null;
}

// 잠겨 있을 때 필드 아이콘을 누르면 팝업을 열 필요 없이 그 자리에서 바로 잠금 해제할 수 있게 한다.
// PIN이 설정돼 있으면 PIN부터 보여준다(더 빠르니까) — 다른 방식으로 전환하는 링크도 같이 둔다.
async function openUnlockDropdown(input, { usePassword = false } = {}) {
  closeFieldDropdown();
  const status = await send({ type: "GET_STATUS" }).catch(() => null);
  const pinMode = !!status?.pinEnabled && !usePassword;
  const el = document.createElement("div");
  el.className = "f-drop";
  el.innerHTML = `
    <div class="f-unlock">
      <div class="f-unlock-title">Keyfort 잠금 해제</div>
      <input class="f-input" type="password" id="f-secret" placeholder="${pinMode ? "PIN" : "마스터 비밀번호"}"
        ${pinMode ? 'inputmode="numeric" maxlength="8"' : 'autocomplete="current-password"'} />
      <div class="f-error" id="f-err" style="display:none"></div>
      <button class="f-primary" id="f-unlock-btn">잠금 해제</button>
      ${status?.pinEnabled ? `<button class="f-link" id="f-switch">${pinMode ? "마스터 비밀번호로 해제" : "PIN으로 해제"}</button>` : ""}
    </div>`;
  fieldIconRoot().appendChild(el);
  positionBelowInput(el, input);
  currentDropdown = el;
  currentDropdownInput = input;
  fieldIcons.get(input)?.btn.setAttribute("aria-expanded", "true");

  const secretInput = el.querySelector("#f-secret");
  const errBox = el.querySelector("#f-err");
  const btn = el.querySelector("#f-unlock-btn");
  secretInput.focus();

  async function submit() {
    const value = secretInput.value;
    if (!value) return;
    btn.disabled = true;
    errBox.style.display = "none";
    const res = await send(pinMode ? { type: "UNLOCK_PIN", pin: value } : { type: "UNLOCK", password: value }).catch((err) => ({
      ok: false,
      error: err.message,
    }));
    if (res?.ok) {
      closeFieldDropdown();
      // 잠금 해제됐으니 아이디/비번 칸 둘 다 다시 확인해서 매칭 있으면 바로 계정 목록으로 이어준다.
      const items = await refreshFieldIcons();
      if (items?.length) openFieldDropdown(input, items);
      return;
    }
    errBox.textContent = res?.error || "잠금 해제에 실패했습니다.";
    errBox.style.display = "block";
    secretInput.value = "";
    secretInput.focus();
    btn.disabled = false;
  }

  btn.addEventListener("click", submit);
  secretInput.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  el.querySelector("#f-switch")?.addEventListener("click", () => openUnlockDropdown(input, { usePassword: !pinMode }));
}

// closed shadow root 안에서 난 클릭은 document 레벨 리스너에서 보면 e.target이 항상 그 shadow host로
// 리타깃된다(캡슐화) — 그래서 개별 버튼/드롭다운에 .contains()를 걸어도 못 잡는다. "우리 UI 안이냐"는
// e.target이 이 host 자신인지로만 판단할 수 있다. 안이면 각 요소 자신의 클릭 핸들러가 알아서 처리한다.
document.addEventListener(
  "click",
  (e) => {
    if (!currentDropdown || e.target === fieldIconHost) return;
    closeFieldDropdown();
  },
  true
);
document.addEventListener("keydown", (e) => {
  if (e.key === "Escape") closeFieldDropdown();
});

// mode "login"(기본): 아이디/비번 자동입력 고르기. mode "otp": OTP 칸에 채울지 제안만 하고, 클릭해야 채운다
// (자동 채움은 절대 안 함 — 이유는 openOtpMenu 주석 참고).
function attachFieldIcon(input, items, { locked = false, mode = "login" } = {}) {
  if (fieldIcons.has(input)) return; // 이미 이 필드에 붙어있음
  const btn = document.createElement("button");
  btn.type = "button";
  btn.className = "f-btn";
  btn.setAttribute("aria-label", locked ? "Keyfort 잠금 해제" : mode === "otp" ? "Keyfort 인증 코드 채우기" : "Keyfort 계정 선택");
  btn.setAttribute("aria-haspopup", "menu");
  btn.setAttribute("aria-expanded", "false");
  btn.innerHTML = FIELD_ICON_SVG;
  fieldIconRoot().appendChild(btn);
  positionOverInput(btn, input);
  btn.addEventListener("click", (e) => {
    e.preventDefault();
    e.stopPropagation();
    if (currentDropdown && currentDropdownInput === input) {
      closeFieldDropdown();
    } else if (locked) {
      openUnlockDropdown(input);
    } else if (mode === "otp") {
      openOtpMenu(input, items);
    } else {
      openFieldDropdown(input, items);
    }
  });
  fieldIcons.set(input, { btn });
  if (!iconRepositionTimer) iconRepositionTimer = setInterval(repositionFieldIcons, 300);
}

let overlayShown = false;

// 구글처럼 이메일→비밀번호[→OTP] 단계가 완전히 새 페이지로 넘어가는 로그인은, 이 페이지의 메모리 상태가
// 다음 페이지에선 사라진다. background.js에 탭 단위로 복사해 두면 다음 페이지가 뜰 때 복원해서 이어 채울 수
// 있고, 그래야 이미 고른 계정을 또 고르라고 계정 선택창이 다시 뜨는 일이 없다.
function setPendingFill(id, step) {
  pendingFillId = id;
  pendingFillStep = step;
  send({ type: "SET_PENDING_FILL", id, step }).catch(() => {});
}

async function consumePendingFill() {
  const id = pendingFillId;
  const step = pendingFillStep;
  pendingFillId = null;
  pendingFillStep = null;
  send({ type: "CLEAR_PENDING_FILL" }).catch(() => {});
  if (step === "otp") {
    // OTP는 여기서도 자동으로 안 채운다 — 방금 고른 그 계정의 코드를 채울지 필드 아이콘으로 제안만 한다.
    const otpField = findOtpField();
    if (!otpField) return;
    const matchRes = await send({ type: "GET_HOST_MATCHES" }).catch(() => null);
    const item = matchRes?.ok ? matchRes.items.find((i) => i.id === id) : null;
    if (item) attachFieldIcon(otpField, [item], { mode: "otp" });
    return;
  }
  send({ type: "REQUEST_AUTOFILL", id, submit: true }).catch(() => {});
}

async function checkPage() {
  const fields = findLoginFields();
  if (pendingFillId) {
    // 비밀번호 단계를 기다리는 중엔 반드시 "새로 나타난" passwordInput이어야 한다 — 지금 막 채운
    // 바로 그 페이지에서 다시 안 채우도록, 대기 단계와 실제 나타난 필드가 맞을 때만 소비한다.
    if (pendingFillStep === "password" && fields?.passwordInput) return consumePendingFill();
    if (pendingFillStep === "otp" && !fields && findOtpField()) return consumePendingFill();
  }
  // 전체 페이지 새로고침으로 로그인하는 사이트(github.com 포함 대부분)는 로그인 성공 후 도착한
  // 페이지에 로그인 폼이 남아있지 않다 — 그래서 "폼이 있을 때만" 저장 제안을 물어보면 이 흔한
  // 경우를 영영 놓친다. fields 유무와 상관없이 먼저 물어본다(one-shot이라 매번 물어도 안전).
  if (!overlayShown) {
    const saveRes = await send({ type: "GET_PENDING_SAVE" });
    if (saveRes?.ok && saveRes.pending) {
      overlayShown = true;
      showSaveBanner(saveRes.pending);
      return;
    }
  }
  if (fields) {
    // 1Password처럼 아이디/비번 칸 둘 다에(있는 것만) 아이콘을 붙인다. 이미 붙어있거나 매칭 없어서
    // 이미 확인해 본 필드는 다시 안 물어본다.
    const targets = [fields.usernameInput, fields.passwordInput].filter(Boolean);
    const needsCheck = targets.some((t) => !fieldIcons.has(t) && !checkedNoResultInputs.has(t));
    if (needsCheck) {
      const matchRes = await send({ type: "GET_HOST_MATCHES" });
      if (matchRes?.ok && matchRes.locked) {
        // 잠겨 있으면 매칭 여부를 알 수 없다 — 그냥 숨기지 말고 아이콘으로 "잠금 해제하기"를 제안한다.
        for (const t of targets) attachFieldIcon(t, [], { locked: true });
      } else if (matchRes?.ok && matchRes.items?.length) {
        for (const t of targets) attachFieldIcon(t, matchRes.items);
      } else if (matchRes?.ok) {
        for (const t of targets) checkedNoResultInputs.add(t);
      }
    }
    return;
  }

  // 로그인 폼은 없고 OTP 칸만 있는 페이지 — Keyfort의 자동입력을 거치지 않고(직접 로그인 등) 2FA
  // 화면에 바로 도착한 경우다. 여기서도 절대 자동으로 안 채운다(이유는 openOtpMenu 주석 참고) —
  // 이 사이트에 TOTP가 저장된 계정이 있으면 필드 아이콘으로 "채울까요?" 제안만 한다.
  const otpField = findOtpField();
  if (otpField && !fieldIcons.has(otpField) && !checkedNoResultInputs.has(otpField)) {
    const matchRes = await send({ type: "GET_HOST_MATCHES" });
    const withTotp = matchRes?.ok ? matchRes.items.filter((i) => i.hasTotp) : [];
    if (withTotp.length) attachFieldIcon(otpField, withTotp, { mode: "otp" });
    else checkedNoResultInputs.add(otpField);
  }
}

// SPA는 로그인 폼을 나중에 그리거나 단계별로 교체한다. 변경이 있으면 최대 300ms에 한 번 다시 본다
// (디바운스가 아니라 스로틀 — DOM이 끊임없이 바뀌는 페이지에서도 검사가 굶지 않게).
let scanTimer = null;
const domObserver = new MutationObserver(() => scheduleCheck());
function scheduleCheck() {
  if (scanTimer) return;
  scanTimer = setTimeout(() => {
    scanTimer = null;
    checkPage().catch(() => {});
    checkOtpauth().catch(() => {});
  }, 300);
}

// 로그인 시점의 값을 캡처해 저장 제안 후보로 background에 넘긴다. submit 이벤트를 안 쓰는 SPA가 많아서
// 버튼 클릭과 Enter 키도 본다(isTrusted: 우리가 만든 합성 이벤트는 무시).
function captureCredentials(e) {
  if (!e.isTrusted) return;
  if (e.type === "keydown" && e.key !== "Enter") return;
  if (e.type === "click" && !e.target.closest?.('button, input[type="submit"], [role="button"]')) return;
  const fields = findLoginFields();
  if (!fields) return;
  const username = fields.usernameInput?.value || null;
  if (!fields.passwordInput) {
    // 이 단계엔 비밀번호 칸이 없다 — AWS SSO/Google처럼 다음 단계가 완전히 새 페이지(전체 네비게이션)일
    // 수 있으니, 이 페이지의 메모리가 아니라 탭 기준으로 background에 맡겨 다음 페이지에서도 살아남게 한다.
    if (username) send({ type: "NOTE_USERNAME", username }).catch(() => {});
    return;
  }
  if (!fields.passwordInput.value) return;
  // username이 이 페이지에 안 보이면(2단계만 새로 뜬 페이지) background가 1단계에서 맡겨둔 값으로 채운다.
  send({ type: "PENDING_SAVE", username, password: fields.passwordInput.value }).catch(() => {});
  // SPA 로그인은 페이지 리로드가 없으니, 잠시 뒤 로그인 폼이 사라졌으면 여기서 바로 저장 제안을 띄운다.
  setTimeout(async () => {
    if (findLoginFields()?.passwordInput) return; // 아직 폼이 있음 = 로그인 실패 또는 진행 중
    const res = await send({ type: "GET_PENDING_SAVE" }).catch(() => null);
    if (res?.ok && res.pending) showSaveBanner(res.pending);
  }, 2500);
}

for (const type of ["submit", "click", "keydown"]) document.addEventListener(type, captureCredentials, true);
// 기존 요소에 나중에 attachShadow된 폼은 어떤 관찰에도 안 잡힌다 — 사용자가 칸에 포커스하면 그때 다시 본다.
document.addEventListener("focusin", scheduleCheck, true);
domObserver.observe(document.documentElement, { childList: true, subtree: true });

// 이전 페이지가 남겨둔 이어채우기 상태를 복원한 뒤에야 첫 스캔을 한다 — 안 그러면 아직 상태를 모르는 채로
// 스캔해서 방금 고른 계정을 또 고르라고 뜬다.
send({ type: "GET_PENDING_FILL" })
  .catch(() => null)
  .then((res) => {
    if (res?.ok && res.pending) {
      pendingFillId = res.pending.id;
      pendingFillStep = res.pending.step;
    }
    checkPage().catch(() => {});
    checkOtpauth().catch(() => {});
    checkFederatedLogin().catch(() => {}); // 페이지당 한 번이면 충분 — DOM이 바뀐다고 결과가 달라지지 않는다
  });

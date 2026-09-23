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
function findLoginFields() {
  const passwordInput = deepQueryAll('input[type="password"]').find(isVisible) || null;
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

// 다단계 로그인(이메일 → 비밀번호)에서 이메일 단계를 채운 항목. 비밀번호 칸이 나타나면 이어서 채운다.
// ponytail: 메모리에만 있어서 두 단계 사이에 전체 페이지 이동이 있으면 이어지지 않는다(Google은 SPA라 괜찮음).
let pendingFillId = null;

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "DO_AUTOFILL") {
    // 검증된 host와 지금 이 문서의 host가 다르면(그사이 이동함) 채우지 않는다.
    if (msg.host && location.hostname !== msg.host) {
      sendResponse({ ok: false, error: "페이지가 바뀌어 자동입력을 취소했습니다." });
      return;
    }
    const fields = findLoginFields();
    if (!fields) {
      sendResponse({ ok: false, error: "로그인 폼을 찾지 못했습니다." });
      return;
    }
    if (fields.usernameInput && msg.username) fillInput(fields.usernameInput, msg.username);
    if (fields.passwordInput && msg.password) fillInput(fields.passwordInput, msg.password);
    if (msg.submit) submitFrom(fields.passwordInput || fields.usernameInput);
    sendResponse({ ok: true, step: fields.passwordInput ? "password" : "username" });
  }
  return true;
});

// ---- 인페이지 오버레이: 계정 선택 / 새 로그인 저장 제안 --------------------
// Shadow DOM(closed)에 그려서 페이지 CSS와 절대 충돌하지 않는다.

function send(msg) {
  return chrome.runtime.sendMessage(msg);
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

function clearOverlay() {
  overlayHost?.remove();
  overlayHost = null;
  overlayShadow = null;
}

// 여기 뜨는 계정은 전부 이 사이트와 일치하는 항목이라 페이지 자신의 favicon이 곧 계정 아이콘이다.
// 외부 favicon 서비스를 쓰면 방문 사이트가 제3자에게 새므로 쓰지 않는다. 못 불러오면 첫 글자 아바타만 남는다.
function faviconUrl() {
  const href = document.querySelector('link[rel~="icon"]')?.href || `${location.origin}/favicon.ico`;
  return /^https?:/.test(href) ? href : null;
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

function isSameSiteHost(a, b) {
  return a === b || a.endsWith(`.${b}`) || b.endsWith(`.${a}`);
}

function showAccountPicker(items) {
  const el = mountCard(`<div class="m-list">${items
    .map((item, i) => {
      const { title, sub } = accountLines(item);
      return `
      <button class="m-item${i === 0 && item.lastUsedAt ? " m-first" : ""}" data-i="${i}">${avatarHtml(item.username || item.name)}
        <div class="m-text"><div class="m-name">${title}</div>${sub ? `<div class="m-user">${sub}</div>` : ""}</div>
        <span class="m-go">›</span></button>`;
    })
    .join("")}</div>`);
  el.querySelectorAll(".m-item").forEach((btn) => {
    btn.addEventListener("click", async () => {
      btn.disabled = true;
      const item = items[Number(btn.dataset.i)];
      const res = await send({ type: "REQUEST_AUTOFILL", id: item.id, submit: true });
      if (res?.ok) {
        clearOverlay();
        overlayShown = false;
        // 이메일만 채운 단계면, 다음 화면에 비밀번호 칸이 뜰 때 같은 항목으로 이어서 채운다.
        if (!findLoginFields()?.passwordInput) pendingFillId = item.id;
      } else {
        btn.disabled = false;
        btn.querySelector(".m-text").insertAdjacentHTML("beforeend", `<div class="m-user">${escapeHtml(res?.error || "자동입력 실패")}</div>`);
      }
    });
  });
}

let overlayShown = false;
let lastUsername = null; // 이메일 단계에서 입력한 값 — 다음 단계의 비밀번호와 묶어 저장 제안에 쓴다

async function checkPage() {
  const fields = findLoginFields();
  if (fields?.passwordInput && pendingFillId) {
    const id = pendingFillId;
    pendingFillId = null;
    send({ type: "REQUEST_AUTOFILL", id, submit: true }).catch(() => {});
    return;
  }
  if (!fields || overlayShown) return;
  overlayShown = true;
  const [saveRes, matchRes] = await Promise.all([send({ type: "GET_PENDING_SAVE" }), send({ type: "GET_HOST_MATCHES" })]);
  if (saveRes?.ok && saveRes.pending) {
    showSaveBanner(saveRes.pending);
  } else if (matchRes?.ok && matchRes.items?.length) {
    showAccountPicker(matchRes.items);
  } else {
    overlayShown = false; // 잠겨 있었거나 매칭 없음 — 폼이 다시 바뀌면 재시도
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
    if (username) lastUsername = username;
    return;
  }
  if (!fields.passwordInput.value) return;
  send({ type: "PENDING_SAVE", username: username || lastUsername, password: fields.passwordInput.value }).catch(() => {});
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
checkPage().catch(() => {});

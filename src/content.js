// src/content.js - detects login forms, autofills on request, and offers an in-page
// overlay (Shadow DOM) to save new logins / pick a saved account, like 1Password's
// inline UI. MV3 content scripts cannot open the toolbar popup on their own, so this
// overlay is the only way to surface "저장할까요?" / "이 계정으로 로그인" without a click
// on the extension icon. Host matching for saved items always happens in background.js
// (using the authoritative sender.tab.url), never here — a page must not be trusted to
// self-report its own host.

function findLoginFields() {
  const passwordInputs = Array.from(
    document.querySelectorAll('input[type="password"]')
  ).filter((el) => el.offsetParent !== null);

  if (passwordInputs.length === 0) return null;
  const passwordInput = passwordInputs[0];

  // find a plausible username/email field: any text/email input before the
  // password field within the same form, or the closest preceding one on page.
  const form = passwordInput.closest("form");
  const scope = form || document;
  const candidates = Array.from(
    scope.querySelectorAll(
      'input[type="text"], input[type="email"], input:not([type])'
    )
  ).filter((el) => el.offsetParent !== null);

  let usernameInput = null;
  if (candidates.length > 0) {
    // Prefer one that appears before the password field in the DOM.
    const pwIndex = candidates.length;
    usernameInput =
      candidates.find((el) => {
        const pos = el.compareDocumentPosition(passwordInput);
        return !!(pos & Node.DOCUMENT_POSITION_FOLLOWING);
      }) || candidates[0];
  }

  return { usernameInput, passwordInput };
}

function setNativeValue(input, value) {
  const proto = Object.getPrototypeOf(input);
  const desc = Object.getOwnPropertyDescriptor(proto, "value");
  if (desc && desc.set) {
    desc.set.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

// ponytail: form.requestSubmit()으로 시도하고, 없으면 submit 버튼 클릭으로 대체한다.
// 버튼이 form 밖에 있거나 submit 이벤트를 안 쓰는 JS 기반 로그인(SPA)은 못 잡을 수 있음 — 그런 사이트는
// 채우기만 되고 로그인 버튼은 사용자가 직접 눌러야 한다.
function submitLoginForm(passwordInput) {
  const form = passwordInput.closest("form");
  if (form?.requestSubmit) {
    form.requestSubmit();
    return;
  }
  form?.querySelector('button[type="submit"], input[type="submit"]')?.click();
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "DO_AUTOFILL") {
    const fields = findLoginFields();
    if (!fields) {
      sendResponse({ ok: false, error: "로그인 폼을 찾지 못했습니다." });
      return;
    }
    if (fields.usernameInput && msg.username) {
      setNativeValue(fields.usernameInput, msg.username);
    }
    if (fields.passwordInput && msg.password) {
      setNativeValue(fields.passwordInput, msg.password);
    }
    if (msg.submit) submitLoginForm(fields.passwordInput);
    sendResponse({ ok: true });
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
  .m-toast, .m-picker {
    position: fixed; z-index: 2147483647; right: 16px; bottom: 16px;
    font: 13px -apple-system, BlinkMacSystemFont, "Segoe UI", sans-serif;
  }
  .m-toast {
    background: #201f1c; color: #f0ede6; border: 1px solid #34322c;
    border-radius: 10px; padding: 12px 14px; max-width: 280px;
    box-shadow: 0 8px 24px rgba(0,0,0,.35);
  }
  .m-toast .m-title { font-weight: 700; display: flex; align-items: center; gap: 6px; margin-bottom: 6px; }
  .m-toast .m-sub { color: #a09b8f; font-size: 12px; margin-bottom: 10px; word-break: break-all; }
  .m-toast .m-row { display: flex; gap: 6px; justify-content: flex-end; }
  .m-toast button { border: none; border-radius: 8px; padding: 6px 10px; font-size: 12px; cursor: pointer; font-weight: 600; }
  .m-toast .m-primary { background: #f5a524; color: #1c1306; }
  .m-toast .m-secondary { background: #2a2823; color: #f0ede6; }
  .m-mark { width: 14px; height: 14px; color: #f5a524; flex-shrink: 0; }
  .m-picker .m-pill {
    display: flex; align-items: center; gap: 6px; background: #201f1c; color: #f0ede6;
    border: 1px solid #34322c; border-radius: 20px; padding: 8px 12px; cursor: pointer;
    box-shadow: 0 8px 24px rgba(0,0,0,.35);
  }
  .m-picker .m-pill .m-mark { width: 16px; height: 16px; }
  .m-picker .m-list {
    margin-top: 6px; background: #201f1c; border: 1px solid #34322c; border-radius: 10px;
    overflow: hidden; box-shadow: 0 8px 24px rgba(0,0,0,.35);
  }
  .m-picker .m-item {
    display: block; width: 100%; text-align: left; background: transparent; border: none;
    border-top: 1px solid #34322c; color: #f0ede6; padding: 10px 12px; cursor: pointer; font-size: 13px;
  }
  .m-picker .m-item:first-child { border-top: none; }
  .m-picker .m-item:hover { background: #2a2823; }
  .m-picker .m-item .m-u { color: #a09b8f; font-size: 11px; }
  .m-picker .m-item:disabled { opacity: .5; cursor: default; }
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

function showSaveBanner({ host, username, password }) {
  const root = overlayRoot();
  const el = document.createElement("div");
  el.className = "m-toast";
  el.innerHTML = `
    <div class="m-title">${MARK_SVG}Keyfort에 저장할까요?</div>
    <div class="m-sub">${escapeHtml(username || "(사용자 이름 없음)")} — ${escapeHtml(host)}</div>
    <div class="m-row">
      <button class="m-secondary" data-act="dismiss">무시</button>
      <button class="m-primary" data-act="save">저장</button>
    </div>
  `;
  root.appendChild(el);
  el.querySelector('[data-act="dismiss"]').addEventListener("click", () => el.remove());
  el.querySelector('[data-act="save"]').addEventListener("click", async (e) => {
    e.target.disabled = true;
    const res = await send({ type: "SAVE_ITEM", host, username, password });
    if (res?.ok) {
      el.innerHTML = `<div class="m-title">${MARK_SVG}저장했습니다</div>`;
      setTimeout(() => el.remove(), 1200);
    } else {
      el.querySelector(".m-sub").textContent = res?.error || "저장하지 못했습니다.";
      e.target.disabled = false;
    }
  });
}

function showAccountPicker(items) {
  const root = overlayRoot();
  const el = document.createElement("div");
  el.className = "m-picker";
  el.innerHTML = `<div class="m-pill">${MARK_SVG}<span>${items.length}개 계정</span></div>`;
  root.appendChild(el);
  el.querySelector(".m-pill").addEventListener("click", () => {
    const existing = el.querySelector(".m-list");
    if (existing) {
      existing.remove();
      return;
    }
    const list = document.createElement("div");
    list.className = "m-list";
    list.innerHTML = items
      .map(
        (item, i) =>
          `<button class="m-item" data-i="${i}">${escapeHtml(item.name)}<div class="m-u">${escapeHtml(item.username || "")}</div></button>`
      )
      .join("");
    el.appendChild(list);
    list.querySelectorAll(".m-item").forEach((btn) => {
      btn.addEventListener("click", async () => {
        btn.disabled = true;
        const item = items[Number(btn.dataset.i)];
        const res = await send({ type: "REQUEST_AUTOFILL", id: item.id, submit: true });
        if (res?.ok) {
          clearOverlay();
        } else {
          btn.disabled = false;
          btn.textContent = res?.error || "자동입력 실패";
        }
      });
    });
  });
}

async function initOverlay() {
  if (!findLoginFields()) return; // 로그인 폼(password input)이 있는 페이지에서만 동작
  const [saveRes, matchRes] = await Promise.all([send({ type: "GET_PENDING_SAVE" }), send({ type: "GET_HOST_MATCHES" })]);
  if (saveRes?.ok && saveRes.pending) {
    showSaveBanner(saveRes.pending);
  } else if (matchRes?.ok && matchRes.items?.length) {
    showAccountPicker(matchRes.items);
  }
}

// 로그인 폼 제출 시점의 값을 캡처해 저장 제안 후보로 background에 넘긴다. 새로고침/리다이렉트로
// 이 스크립트 컨텍스트가 사라지므로, 실제 배너는 다음 페이지 로드에서 GET_PENDING_SAVE로 받아온다.
document.addEventListener(
  "submit",
  (e) => {
    const fields = findLoginFields();
    if (!fields?.passwordInput?.value) return;
    send({ type: "PENDING_SAVE", username: fields.usernameInput?.value || null, password: fields.passwordInput.value }).catch(() => {});
  },
  true
);

initOverlay();

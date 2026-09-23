// src/popup.js - UI logic for the extension popup.

import { icon } from "./icons.js";
import { brandHtml } from "./brand.js";
import { uriHostname, isSameSite } from "./lib/site.js";

const app = document.getElementById("app");

const TOAST_MS = 1200;
const ERROR_TOAST_MS = 3000;
const TOTP_TICK_MS = 1000;

// TOTP 갱신 타이머. 뷰가 바뀔 때마다 stopTotpTimer()로 정리한다.
let totpTimer = null;

function stopTotpTimer() {
  clearInterval(totpTimer);
  totpTimer = null;
}

function send(msg) {
  return chrome.runtime.sendMessage(msg);
}

// 자동 잠금(background alarms)으로 세션이 사라진 경우 잠금 해제 화면으로 전환한다. 처리했으면 true.
async function handleLockedResponse(res) {
  if (res?.error !== "Locked") return false;
  stopTotpTimer();
  await renderLocked();
  showToast("자동 잠금되었습니다.", ERROR_TOAST_MS);
  return true;
}

async function renderLocked() {
  const status = await send({ type: "GET_STATUS" });
  if (status.canUnlock) renderUnlock(status);
  else renderLogin(status);
}

function showToast(text, durationMs = TOAST_MS) {
  let toast = document.querySelector(".toast");
  if (!toast) {
    toast = document.createElement("div");
    toast.className = "toast";
    document.body.appendChild(toast);
  }
  toast.textContent = text;
  toast.classList.add("show");
  setTimeout(() => toast.classList.remove("show"), durationMs);
}

async function copyToClipboard(text, label) {
  try {
    await navigator.clipboard.writeText(text);
    showToast(`${label} 복사됨`);
  } catch (err) {
    showToast(`${label} 복사 실패: ${err.message}`, ERROR_TOAST_MS);
  }
}

function escapeHtml(str) {
  return String(str ?? "")
    .replace(/&/g, "&amp;")
    .replace(/</g, "&lt;")
    .replace(/>/g, "&gt;")
    .replace(/"/g, "&quot;")
    .replace(/'/g, "&#39;");
}

function initials(name) {
  return (name || "?").trim().slice(0, 2).toUpperCase();
}

// 서버(Vaultwarden) 아이콘 서비스로 파비콘을 받고, 실패하면 이니셜 타일이 그대로 보인다.
let serverUrl = "";

function faviconHtml(item, extraStyle = "") {
  const host = item.uris.map(uriHostname).find(Boolean);
  const img = host && serverUrl
    ? `<img src="${escapeHtml(serverUrl.replace(/\/+$/, ""))}/icons/${encodeURIComponent(host)}/icon.png" alt="" />`
    : "";
  return `<div class="item-favicon" style="${extraStyle}">${escapeHtml(initials(item.name))}${img}</div>`;
}

// MV3 CSP상 인라인 onerror를 쓸 수 없어 렌더 후 리스너를 단다.
function hideBrokenIcons(root) {
  root.querySelectorAll(".item-favicon img").forEach((img) => {
    img.addEventListener("error", () => img.remove());
  });
}

async function getActiveTabHost() {
  try {
    const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
    if (!tab?.url) return null;
    const u = new URL(tab.url);
    return u.hostname;
  } catch {
    return null;
  }
}

// ---- Views --------------------------------------------------------------

function renderLogin(prefill = {}) {
  stopTotpTimer();
  app.innerHTML = `
    <div class="header">
      ${brandHtml()}
    </div>
    <div class="body">
      <div>
        <label class="field-label">Vaultwarden 서버 URL</label>
        <input type="url" id="serverUrl" placeholder="https://localhost:8443" value="${escapeHtml(prefill.serverUrl || "https://localhost:8443")}" />
      </div>
      <div>
        <label class="field-label">이메일</label>
        <input type="email" id="email" placeholder="you@example.com" value="${escapeHtml(prefill.email || "")}" />
      </div>
      <div>
        <label class="field-label">마스터 비밀번호</label>
        <input type="password" id="password" placeholder="Master password" />
      </div>
      <div id="errorBox"></div>
      <button class="btn btn-primary" id="loginBtn">로그인</button>
    </div>
    <div class="footer">
      <span>self-hosted vault</span>
    </div>
  `;

  document.getElementById("loginBtn").addEventListener("click", async () => {
    const serverUrl = document.getElementById("serverUrl").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const btn = document.getElementById("loginBtn");
    const errorBox = document.getElementById("errorBox");
    errorBox.innerHTML = "";
    if (!serverUrl || !email || !password) {
      errorBox.innerHTML = `<div class="error-box">모든 필드를 입력하세요.</div>`;
      return;
    }
    btn.disabled = true;
    btn.textContent = "로그인 중...";
    try {
      const res = await send({ type: "LOGIN", serverUrl, email, password });
      if (res?.ok) {
        renderVault();
        return;
      }
      if (res?.twoFactorRequired) {
        renderOtp({ serverUrl, email, password });
        return;
      }
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(res?.error || "알 수 없는 오류")}</div>`;
    } catch (err) {
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "로그인";
    }
  });

  document.getElementById("password").addEventListener("keydown", (e) => {
    if (e.key === "Enter") document.getElementById("loginBtn").click();
  });
}

const OTP_LENGTH = 6;

function renderOtp(creds) {
  stopTotpTimer();
  app.innerHTML = `
    <div class="header">${brandHtml()}</div>
    <div class="body center-view">
      <div class="hero-icon">${icon("shieldCheck")}</div>
      <div class="hero-title">2단계 인증</div>
      <div class="hero-sub">인증 앱에 표시된 6자리 코드를 입력하세요<br><b>${escapeHtml(creds.email)}</b></div>
      <div class="otp" id="otp">
        ${Array.from({ length: OTP_LENGTH }, (_, i) => `<input class="otp-box" inputmode="numeric" maxlength="1" aria-label="${i + 1}번째 자리" ${i === 0 ? 'autocomplete="one-time-code"' : 'autocomplete="off"'} />`).join("")}
      </div>
      <div id="errorBox"></div>
      <button class="btn btn-primary btn-block" id="otpBtn" disabled>확인</button>
      <div class="hint">이 기기는 기억되어, 다음부터는 코드를 묻지 않아요.</div>
      <button class="link-btn" id="otpBack">${icon("back")} 다른 계정으로 로그인</button>
    </div>
  `;
  const boxes = [...document.querySelectorAll(".otp-box")];
  const btn = document.getElementById("otpBtn");
  const code = () => boxes.map((b) => b.value).join("");
  const sync = () => {
    btn.disabled = code().length !== OTP_LENGTH;
    boxes.forEach((b) => b.classList.toggle("filled", !!b.value));
  };

  // 한 칸에 여러 글자(붙여넣기·자동완성)가 들어오면 뒤 칸으로 흘려 보낸다.
  const spread = (from, digits) => {
    digits.slice(0, OTP_LENGTH - from).split("").forEach((d, k) => (boxes[from + k].value = d));
    boxes[Math.min(from + digits.length, OTP_LENGTH - 1)].focus();
    sync();
    if (code().length === OTP_LENGTH) submit();
  };

  boxes.forEach((box, i) => {
    box.addEventListener("input", () => {
      const digits = box.value.replace(/\D/g, "");
      box.value = "";
      if (digits) spread(i, digits);
      else sync();
    });
    box.addEventListener("keydown", (e) => {
      if (e.key === "Backspace" && !box.value && i > 0) {
        boxes[i - 1].value = "";
        boxes[i - 1].focus();
        sync();
      } else if (e.key === "ArrowLeft" && i > 0) boxes[i - 1].focus();
      else if (e.key === "ArrowRight" && i < OTP_LENGTH - 1) boxes[i + 1].focus();
      else if (e.key === "Enter" && !btn.disabled) submit();
    });
    box.addEventListener("paste", (e) => {
      e.preventDefault();
      spread(i, (e.clipboardData.getData("text") || "").replace(/\D/g, ""));
    });
    box.addEventListener("focus", () => box.select());
  });

  let busy = false;
  async function submit() {
    if (busy) return;
    busy = true;
    btn.disabled = true;
    btn.textContent = "확인 중...";
    const errorBox = document.getElementById("errorBox");
    errorBox.innerHTML = "";
    try {
      const res = await send({ type: "LOGIN", ...creds, twoFactorCode: code() });
      if (res?.ok) {
        renderVault();
        return;
      }
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(res?.twoFactorRequired ? "코드가 올바르지 않습니다. 다시 입력하세요." : res?.error || "알 수 없는 오류")}</div>`;
      const otp = document.getElementById("otp");
      otp.classList.remove("shake");
      void otp.offsetWidth; // 애니메이션 재시작
      otp.classList.add("shake");
      boxes.forEach((b) => (b.value = ""));
      boxes[0].focus();
    } catch (err) {
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      busy = false;
      btn.textContent = "확인";
      sync();
    }
  }

  btn.addEventListener("click", submit);
  document.getElementById("otpBack").addEventListener("click", () => renderLogin(creds));
  boxes[0].focus();
}

function accountHeaderHtml(status) {
  let host = status.serverUrl;
  try {
    host = new URL(status.serverUrl).host;
  } catch {
    /* 그대로 표시 */
  }
  return `
    <div class="account-avatar">${escapeHtml((status.email || "?")[0].toUpperCase())}</div>
    <div class="hero-title">${escapeHtml(status.email)}</div>
    <div class="hero-sub">${escapeHtml(host)}</div>`;
}

function renderUnlock(status, { usePassword = false } = {}) {
  stopTotpTimer();
  const pinMode = status.pinEnabled && !usePassword;
  app.innerHTML = `
    <div class="header">${brandHtml()}<span class="lock-chip">${icon("lock")} 잠김</span></div>
    <div class="body center-view">
      ${accountHeaderHtml(status)}
      ${
        pinMode
          ? `<input type="password" id="secret" class="pin-input" inputmode="numeric" autocomplete="off" maxlength="8" placeholder="PIN" aria-label="PIN" />`
          : `<input type="password" id="secret" autocomplete="current-password" placeholder="마스터 비밀번호" aria-label="마스터 비밀번호" />`
      }
      <div id="errorBox"></div>
      <button class="btn btn-primary btn-block" id="unlockBtn">잠금 해제</button>
      ${
        status.pinEnabled
          ? `<button class="link-btn" id="switchMode">${pinMode ? "마스터 비밀번호로 해제" : "PIN으로 해제"}</button>`
          : ""
      }
    </div>
    <div class="footer">
      <button class="link-btn" id="logoutBtn">다른 계정으로 로그인</button>
    </div>
  `;
  const input = document.getElementById("secret");
  const btn = document.getElementById("unlockBtn");
  const errorBox = document.getElementById("errorBox");

  async function submit() {
    const value = input.value;
    if (!value) return;
    btn.disabled = true;
    btn.textContent = "여는 중...";
    errorBox.innerHTML = "";
    try {
      const res = await send(pinMode ? { type: "UNLOCK_PIN", pin: value } : { type: "UNLOCK", password: value });
      if (res?.ok) {
        renderVault();
        return;
      }
      if (res?.pinDisabled) {
        renderUnlock({ ...status, pinEnabled: false });
        document.getElementById("errorBox").innerHTML = `<div class="error-box">${escapeHtml(res.error)}</div>`;
        return;
      }
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(res?.error || "알 수 없는 오류")}</div>`;
      input.value = "";
      input.focus();
    } catch (err) {
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "잠금 해제";
    }
  }

  btn.addEventListener("click", submit);
  input.addEventListener("keydown", (e) => {
    if (e.key === "Enter") submit();
  });
  document.getElementById("switchMode")?.addEventListener("click", () => renderUnlock(status, { usePassword: pinMode }));
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await send({ type: "LOGOUT" });
    renderLogin(status);
  });
  input.focus();
}

const LOCK_OPTIONS = [
  [1, "1분"],
  [5, "5분"],
  [15, "15분"],
  [30, "30분"],
  [60, "1시간"],
  [0, "브라우저 종료 시"],
];

async function renderSettings() {
  stopTotpTimer();
  const status = await send({ type: "GET_STATUS" });
  if (status.locked) return renderLocked();
  app.innerHTML = `
    <div class="header">
      <button class="back-btn" id="backBtn">${icon("back")} 설정</button>
    </div>
    <div class="body">
      <section class="settings-card">
        <div class="settings-title">자동 잠금</div>
        <div class="settings-desc">팝업을 쓰거나 계정을 골라 채우지 않은 채 이 시간이 지나면 잠급니다.</div>
        <div class="segmented" role="radiogroup" aria-label="자동 잠금 시간">
          ${LOCK_OPTIONS.map(
            ([m, label]) =>
              `<button role="radio" aria-checked="${m === status.lockMinutes}" class="${m === status.lockMinutes ? "on" : ""}" data-m="${m}">${label}</button>`
          ).join("")}
        </div>
      </section>
      <section class="settings-card">
        <div class="settings-title">PIN 잠금 해제 ${status.pinEnabled ? '<span class="on-chip">사용 중</span>' : ""}</div>
        <div class="settings-desc">마스터 비밀번호 대신 숫자 PIN으로 엽니다. 브라우저를 완전히 닫으면 PIN은 지워지고 한 번은 마스터 비밀번호가 필요해요. 5번 틀리면 해제됩니다.</div>
        <div class="pin-row">
          <input type="password" id="newPin" inputmode="numeric" maxlength="8" placeholder="${status.pinEnabled ? "새 PIN (4~8자리)" : "PIN (4~8자리)"}" />
          <button class="btn btn-primary" id="savePin">${status.pinEnabled ? "변경" : "설정"}</button>
        </div>
        ${status.pinEnabled ? '<button class="link-btn danger" id="removePin">PIN 해제</button>' : ""}
      </section>
      <section class="settings-card">
        <div class="settings-title">계정</div>
        <div class="settings-desc">${escapeHtml(status.email)}</div>
        <button class="btn btn-secondary" id="logoutBtn">로그아웃</button>
      </section>
    </div>
  `;
  document.getElementById("backBtn").addEventListener("click", renderVault);
  document.querySelectorAll(".segmented button").forEach((b) =>
    b.addEventListener("click", async () => {
      const res = await send({ type: "SET_LOCK_MINUTES", minutes: Number(b.dataset.m) });
      if (!res?.ok) return showToast(res?.error || "저장 실패", ERROR_TOAST_MS);
      renderSettings();
      showToast("저장됨");
    })
  );
  const savePin = async () => {
    const res = await send({ type: "SET_PIN", pin: document.getElementById("newPin").value });
    if (await handleLockedResponse(res)) return;
    if (!res?.ok) return showToast(res?.error || "PIN 설정 실패", ERROR_TOAST_MS);
    renderSettings();
    showToast("PIN 설정됨");
  };
  document.getElementById("savePin").addEventListener("click", savePin);
  document.getElementById("newPin").addEventListener("keydown", (e) => e.key === "Enter" && savePin());
  document.getElementById("removePin")?.addEventListener("click", async () => {
    await send({ type: "REMOVE_PIN" });
    renderSettings();
    showToast("PIN 해제됨");
  });
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    await send({ type: "LOGOUT" });
    renderLogin(status);
  });
}

async function renderVault() {
  stopTotpTimer();
  app.innerHTML = `
    <div class="header">
      ${brandHtml()}
      <div style="display:flex; gap:4px;">
        <button class="icon-btn" id="syncBtn" title="동기화" aria-label="동기화">${icon("sync")}</button>
        <button class="icon-btn" id="lockBtn" title="잠금" aria-label="잠금">${icon("lock")}</button>
        <button class="icon-btn" id="settingsBtn" title="설정" aria-label="설정">${icon("settings")}</button>
      </div>
    </div>
    <div class="body">
      <div class="search-box">
        <span class="search-icon">${icon("search")}</span>
        <input type="text" id="search" placeholder="항목 검색..." />
      </div>
      <div id="currentSiteRow" style="font-size:11px; color:var(--text-muted); display:flex; align-items:center; gap:6px;"></div>
      <div class="item-list" id="itemList"><div class="empty-state">불러오는 중...</div></div>
      <div id="skippedNote" style="font-size:11px; color:var(--text-muted);"></div>
    </div>
    <div class="footer">
      <span><span class="status-dot"></span>잠금 해제됨</span>
      <span id="itemCount"></span>
    </div>
  `;

  document.getElementById("lockBtn").addEventListener("click", async () => {
    await send({ type: "LOCK" });
    renderLocked();
  });
  document.getElementById("settingsBtn").addEventListener("click", renderSettings);

  document.getElementById("syncBtn").addEventListener("click", async () => {
    const btn = document.getElementById("syncBtn");
    btn.disabled = true;
    try {
      const res = await send({ type: "SYNC" });
      if (await handleLockedResponse(res)) return;
      if (!res?.ok) {
        showToast(`동기화 실패: ${res?.error || "알 수 없는 오류"}`, ERROR_TOAST_MS);
        return;
      }
      await loadItems();
    } catch (err) {
      showToast(`동기화 실패: ${err.message}`, ERROR_TOAST_MS);
    } finally {
      btn.disabled = false;
    }
  });

  document.getElementById("search").addEventListener("input", (e) => {
    filterAndRender(e.target.value);
  });

  let allItems = [];
  const host = await getActiveTabHost();
  serverUrl = (await send({ type: "GET_CONFIG" }))?.serverUrl || "";

  async function loadItems() {
    const res = await send({ type: "GET_ITEMS" });
    if (await handleLockedResponse(res)) return;
    if (!res.ok) {
      document.getElementById("itemList").innerHTML = `<div class="error-box">${escapeHtml(res.error)}</div>`;
      return;
    }
    allItems = res.items;
    const skipped = Number(res.skipped) || 0;
    document.getElementById("skippedNote").textContent =
      skipped > 0 ? `복호화할 수 없는 항목 ${skipped}개는 표시되지 않습니다` : "";
    if (host) {
      const siteRow = document.getElementById("currentSiteRow");
      const matches = allItems.filter((i) => i.uris.some((u) => u.includes(host)));
      siteRow.innerHTML = `${icon("globe")}<span>${escapeHtml(
        matches.length ? `${host}에 대한 항목 ${matches.length}개` : `${host} — 저장된 항목 없음`
      )}</span>`;
    }
    filterAndRender("");
  }

  function filterAndRender(query) {
    const q = query.trim().toLowerCase();
    const filtered = !q
      ? allItems
      : allItems.filter(
          (i) =>
            i.name?.toLowerCase().includes(q) ||
            i.username?.toLowerCase().includes(q) ||
            i.uris.some((u) => u.toLowerCase().includes(q))
        );

    // Sort: matches for current host first (copy — allItems must not be reordered in place)
    const sorted = host
      ? [...filtered].sort((a, b) => {
          const aMatch = a.uris.some((u) => u.includes(host)) ? 0 : 1;
          const bMatch = b.uris.some((u) => u.includes(host)) ? 0 : 1;
          return aMatch - bMatch;
        })
      : filtered;

    const listEl = document.getElementById("itemList");
    document.getElementById("itemCount").textContent = `${allItems.length}개 항목`;
    if (sorted.length === 0) {
      listEl.innerHTML = `<div class="empty-state">항목이 없습니다.<br/>Vaultwarden 웹앱에서 추가해보세요.</div>`;
      return;
    }
    listEl.innerHTML = sorted
      .map(
        (item) => `
      <div class="item-card" data-id="${escapeHtml(item.id)}">
        ${faviconHtml(item)}
        <div class="item-meta">
          <div class="item-name">${escapeHtml(item.name || "(이름 없음)")}</div>
          <div class="item-sub">${escapeHtml(item.username || "")}</div>
        </div>
        ${item.hasTotp ? '<span class="badge-totp">2FA</span>' : ""}
      </div>
    `
      )
      .join("");

    hideBrokenIcons(listEl);
    listEl.querySelectorAll(".item-card").forEach((card) => {
      card.addEventListener("click", () => renderItemDetail(card.dataset.id, allItems));
    });
  }

  loadItems();
}

async function renderItemDetail(id, allItems) {
  stopTotpTimer();
  const item = allItems.find((i) => i.id === id);
  const res = await send({ type: "GET_ITEM_SECRETS", id });
  if (await handleLockedResponse(res)) return;
  if (!item || !res?.ok) {
    showToast(`항목을 불러오지 못했습니다: ${res?.error || "알 수 없는 오류"}`, ERROR_TOAST_MS);
    return;
  }
  // 복사 버튼은 이 변수를 직접 참조한다(DOM 속성에 비밀을 싣지 않음). TOTP 갱신 시 재할당된다.
  let currentTotp = res.totp?.code ?? "";

  app.innerHTML = `
    <div class="header">
      ${brandHtml()}
    </div>
    <div class="body">
      <div class="back-btn" id="backBtn">${icon("back")} 목록으로</div>
      <div style="display:flex; align-items:center; gap:10px;">
        ${faviconHtml(item, "width:40px;height:40px;font-size:15px;")}
        <div>
          <div style="font-weight:700; font-size:15px;">${escapeHtml(item.name)}</div>
          <div class="item-sub">${item.uris[0] ? escapeHtml(item.uris[0]) : ""}</div>
        </div>
      </div>

      ${
        item.username
          ? `
      <div class="detail-row">
        <div>
          <label class="field-label">사용자 이름</label>
          <div class="detail-value">${escapeHtml(item.username)}</div>
        </div>
        <div class="detail-actions">
          <button class="icon-btn" id="copyUsername" title="복사" aria-label="사용자 이름 복사">${icon("copy")}</button>
        </div>
      </div>`
          : ""
      }

      <div class="detail-row">
        <div>
          <label class="field-label">비밀번호</label>
          <div class="detail-value" id="pwField">••••••••••••</div>
        </div>
        <div class="detail-actions">
          <button class="icon-btn" id="togglePw" title="보기" aria-label="비밀번호 보기">${icon("eye")}</button>
          <button class="icon-btn" id="copyPassword" title="복사" aria-label="비밀번호 복사">${icon("copy")}</button>
        </div>
      </div>

      ${
        res.totp
          ? `
      <div class="detail-row">
        <div>
          <label class="field-label">인증 코드 (TOTP)</label>
          <div class="totp-code" id="totpCode">${res.totp.code.slice(0, 3)} ${res.totp.code.slice(3)}</div>
        </div>
        <div class="detail-actions">
          <button class="icon-btn" id="copyTotp" title="복사" aria-label="인증 코드 복사">${icon("copy")}</button>
        </div>
      </div>`
          : ""
      }

      <button class="btn btn-primary" id="autofillBtn">이 탭에 자동입력</button>
    </div>
  `;

  document.getElementById("backBtn").addEventListener("click", renderVault);
  hideBrokenIcons(app);

  const pwField = document.getElementById("pwField");
  let pwVisible = false;
  const toggleBtn = document.getElementById("togglePw");
  toggleBtn.addEventListener("click", () => {
    pwVisible = !pwVisible;
    pwField.textContent = pwVisible ? res.password : "••••••••••••";
    toggleBtn.innerHTML = icon(pwVisible ? "eyeOff" : "eye");
  });

  document.getElementById("copyUsername")?.addEventListener("click", () => copyToClipboard(item.username, "사용자 이름"));
  document.getElementById("copyPassword").addEventListener("click", () => copyToClipboard(res.password || "", "비밀번호"));
  document.getElementById("copyTotp")?.addEventListener("click", () => copyToClipboard(currentTotp, "인증 코드"));

  document.getElementById("autofillBtn").addEventListener("click", () => autofillActiveTab(item, res.password));

  // live-refresh TOTP countdown
  if (res.totp) {
    startTotpTimer(id, res.totp.secondsRemaining, (code) => {
      currentTotp = code;
      document.getElementById("totpCode").textContent = `${code.slice(0, 3)} ${code.slice(3)}`;
    });
  }
}

async function autofillActiveTab(item, password) {
  const [tab] = await chrome.tabs.query({ active: true, currentWindow: true });
  if (!tab?.id) return;

  // 선택한 항목의 사이트와 다른 탭이면 비밀번호를 넘기기 전에 사용자 확인을 받는다.
  const tabHost = uriHostname(tab.url || "");
  const isMatch = item.uris.some((u) => isSameSite(tabHost, uriHostname(u)));
  if (!isMatch && !confirm(`현재 탭(${tabHost || "알 수 없음"})은 이 항목의 사이트와 일치하지 않습니다.\n그래도 자동입력할까요?`)) {
    return;
  }

  try {
    const reply = await chrome.tabs.sendMessage(tab.id, {
      type: "DO_AUTOFILL",
      host: tabHost, // 확인 후 탭이 다른 사이트로 이동했으면 content.js가 거부한다
      username: item.username,
      password,
    }, { frameId: 0 }); // 최상위 프레임만 — all_frames라 다른 출처 iframe에 비밀번호가 새지 않게
    if (!reply?.ok) {
      showToast(reply?.error || "자동입력에 실패했습니다.", ERROR_TOAST_MS);
      return;
    }
    window.close();
  } catch (err) {
    // content script가 주입되지 않은 탭(chrome://, 웹스토어, 새로고침 전 탭 등)
    showToast(`이 탭에서는 자동입력할 수 없습니다: ${err.message}`, ERROR_TOAST_MS);
  }
}

function startTotpTimer(id, secondsRemaining, onFresh) {
  stopTotpTimer();
  let remaining = secondsRemaining;
  let isRefreshing = false;
  const timer = setInterval(async () => {
    // 뷰가 바뀌어 요소가 사라졌으면 즉시 정리
    if (!document.getElementById("totpCode")) {
      clearInterval(timer);
      return;
    }
    remaining -= 1;
    if (remaining > 0 || isRefreshing) return;
    isRefreshing = true;
    try {
      const fresh = await send({ type: "GET_ITEM_SECRETS", id });
      if (totpTimer !== timer) return; // 대기 중 다른 뷰로 이동함
      if (await handleLockedResponse(fresh)) return;
      if (!fresh?.ok || !fresh.totp) throw new Error(fresh?.error || "응답 없음");
      onFresh(fresh.totp.code);
      remaining = fresh.totp.secondsRemaining;
    } catch (err) {
      clearInterval(timer);
      showToast(`TOTP 갱신 실패: ${err.message}`, ERROR_TOAST_MS);
    } finally {
      isRefreshing = false;
    }
  }, TOTP_TICK_MS);
  totpTimer = timer;
}

// ---- boot -----------------------------------------------------------------

(async function init() {
  const status = await send({ type: "GET_STATUS" });
  if (!status.locked) renderVault();
  else if (status.canUnlock) renderUnlock(status);
  else renderLogin(status);
})();

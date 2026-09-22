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

// 자동 잠금(background alarms)으로 세션이 사라진 경우 로그인 화면으로 전환한다. 처리했으면 true.
async function handleLockedResponse(res) {
  if (res?.error !== "Locked") return false;
  stopTotpTimer();
  renderLogin(await send({ type: "GET_CONFIG" }));
  showToast("자동 잠금되었습니다. 다시 로그인하세요.", ERROR_TOAST_MS);
  return true;
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
      <div id="twoFactorRow" hidden>
        <label class="field-label">인증 앱 코드 (2단계 인증)</label>
        <input type="text" id="twoFactorCode" inputmode="numeric" autocomplete="one-time-code" maxlength="8" placeholder="123456" />
      </div>
      <div id="errorBox"></div>
      <button class="btn btn-primary" id="loginBtn">잠금 해제</button>
    </div>
    <div class="footer">
      <span>self-hosted vault</span>
    </div>
  `;

  document.getElementById("loginBtn").addEventListener("click", async () => {
    const serverUrl = document.getElementById("serverUrl").value.trim();
    const email = document.getElementById("email").value.trim();
    const password = document.getElementById("password").value;
    const twoFactorRow = document.getElementById("twoFactorRow");
    const twoFactorInput = document.getElementById("twoFactorCode");
    const twoFactorCode = twoFactorRow.hidden ? "" : twoFactorInput.value.trim();
    const btn = document.getElementById("loginBtn");
    const errorBox = document.getElementById("errorBox");
    errorBox.innerHTML = "";
    if (!serverUrl || !email || !password || (!twoFactorRow.hidden && !twoFactorCode)) {
      errorBox.innerHTML = `<div class="error-box">모든 필드를 입력하세요.</div>`;
      return;
    }
    btn.disabled = true;
    btn.textContent = "로그인 중...";
    try {
      const res = await send({ type: "LOGIN", serverUrl, email, password, twoFactorCode });
      if (res?.ok) {
        renderVault();
        return;
      }
      if (res?.twoFactorRequired) {
        twoFactorRow.hidden = false;
        twoFactorInput.focus();
        errorBox.innerHTML = `<div class="error-box">2단계 인증 코드를 입력하세요.</div>`;
        return;
      }
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(res?.error || "알 수 없는 오류")}</div>`;
    } catch (err) {
      errorBox.innerHTML = `<div class="error-box">${escapeHtml(err.message)}</div>`;
    } finally {
      btn.disabled = false;
      btn.textContent = "잠금 해제";
    }
  });

  // Enter key submits
  for (const id of ["password", "twoFactorCode"]) {
    document.getElementById(id).addEventListener("keydown", (e) => {
      if (e.key === "Enter") document.getElementById("loginBtn").click();
    });
  }
}

async function renderVault() {
  stopTotpTimer();
  app.innerHTML = `
    <div class="header">
      ${brandHtml()}
      <div style="display:flex; gap:4px;">
        <button class="icon-btn" id="syncBtn" title="동기화" aria-label="동기화">${icon("sync")}</button>
        <button class="icon-btn" id="lockBtn" title="잠금" aria-label="잠금">${icon("lock")}</button>
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
    renderLogin(await send({ type: "GET_CONFIG" }));
  });

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
      username: item.username,
      password,
    });
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
  if (status.locked) {
    renderLogin(status);
  } else {
    renderVault();
  }
})();

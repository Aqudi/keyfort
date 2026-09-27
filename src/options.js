import { brandHtml } from "./brand.js";
import { icon } from "./icons.js";
import { parseCsv } from "./lib/csv.js";
import { normalizeImportRows } from "./lib/importers.js";
import { findDuplicateGroups } from "./lib/duplicates.js";
import { uriHostname } from "./lib/site.js";

const app = document.getElementById("app");

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

const NAV = [
  { key: "general", label: "일반", icon: "clock" },
  { key: "security", label: "보안", icon: "shieldCheck" },
  { key: "import", label: "가져오기", icon: "download" },
  { key: "admin", label: "계정 관리", icon: "copy" },
  { key: "account", label: "계정", icon: "user" },
];

const LOCK_OPTIONS = [
  [1, "1분"],
  [5, "5분"],
  [15, "15분"],
  [30, "30분"],
  [60, "1시간"],
  [0, "브라우저 종료 시"],
];

const relTime = new Intl.RelativeTimeFormat("ko", { numeric: "auto" });
function timeAgo(ts) {
  const sec = (ts - Date.now()) / 1000;
  for (const [unit, size] of [
    ["year", 31536000],
    ["month", 2592000],
    ["day", 86400],
    ["hour", 3600],
    ["minute", 60],
  ]) {
    if (Math.abs(sec) >= size) return relTime.format(Math.round(sec / size), unit);
  }
  return "방금";
}

// 자동입력한 적이 있으면 그 시각, 없으면 서버에 마지막으로 저장/수정된 시각(revisionDate) — 최근 사용 기록이
// 아예 없는 둘 중에서도 "더 최근에 만들어진/고쳐진 쪽"이 남길 후보로는 더 합리적인 기본값이다.
function bestKnownDate(item) {
  if (item.lastUsedAt) return { ts: item.lastUsedAt, label: `최근 사용 ${timeAgo(item.lastUsedAt)}` };
  if (item.revisionDate) {
    const ts = new Date(item.revisionDate).getTime();
    if (!Number.isNaN(ts)) return { ts, label: `등록/수정 ${timeAgo(ts)}` };
  }
  return { ts: 0, label: "사용 기록 없음" };
}

function pickDefaultKeep(group) {
  return group.reduce((best, item) => (bestKnownDate(item).ts > bestKnownDate(best).ts ? item : best), group[0]);
}

function renderDuplicatesPane(groups) {
  if (!groups.length) {
    return `<div class="dup-summary"><span>중복으로 보이는 계정이 없습니다.</span></div>`;
  }
  const extra = groups.reduce((n, g) => n + g.length - 1, 0);
  const summary = `
    <div class="dup-summary">
      <span><strong>${groups.length}</strong>개 그룹에서 중복 <strong>${extra}</strong>개 발견</span>
      <button class="btn btn-primary" id="dedupeAll">전체 자동 정리</button>
    </div>`;
  const groupsHtml = groups
    .map((group, gi) => {
      const keep = pickDefaultKeep(group);
      const site = uriHostname(group[0].uris[0]?.uri || "") || group[0].uris[0]?.uri || "";
      const rows = group
        .map(
          (item) => `
        <tr>
          <td style="width:28px;"><input type="radio" name="dup-${gi}" value="${item.id}" ${item.id === keep.id ? "checked" : ""} /></td>
          <td>${escapeHtml(item.name)}</td>
          <td class="dup-used">${escapeHtml(bestKnownDate(item).label)}</td>
        </tr>`
        )
        .join("");
      return `
      <div class="dup-group">
        <div class="dup-group-head">
          <span>${escapeHtml(group[0].username || "(사용자 이름 없음)")}</span>
          <span class="dup-site">${escapeHtml(site)}</span>
        </div>
        <table class="dup-table">
          <thead><tr><th>남길 항목</th><th>이름</th><th>기록</th></tr></thead>
          <tbody>${rows}</tbody>
        </table>
        <div style="padding:4px 12px 12px;"><button class="btn btn-secondary" data-dedupe="${gi}">이 그룹만 정리</button></div>
      </div>`;
    })
    .join("");
  return `${summary}<div style="display:flex; flex-direction:column; gap:12px; margin-top:12px;">${groupsHtml}</div>`;
}

let activeCat = NAV[0].key; // 재렌더링(PIN 저장 등) 후에도 보던 탭을 유지한다

async function renderOptions() {
  const status = await send({ type: "GET_STATUS" });
  if (status.locked) {
    app.innerHTML = `
      <div style="max-width:420px; margin:60px auto; padding:0 20px; text-align:center;">
        <h1 style="font-size:16px; display:flex; align-items:center; gap:8px; justify-content:center;">${brandHtml()}</h1>
        <p style="color:var(--text-muted); font-size:13px;">잠겨 있습니다. 먼저 팝업 아이콘을 눌러 잠금을 해제한 뒤 이 탭을 새로고침하세요.</p>
      </div>
    `;
    return;
  }

  const foldersRes = await send({ type: "GET_FOLDERS" });
  const folders = foldersRes?.ok ? foldersRes.folders : [];
  const itemsRes = await send({ type: "GET_ITEMS" });
  const duplicateGroups = findDuplicateGroups(itemsRes?.ok ? itemsRes.items : []);

  app.innerHTML = `
    <div class="options-shell">
      <aside class="options-sidebar">
        <div class="options-brand"><h1>${brandHtml()}</h1></div>
        <nav>
          ${NAV.map(
            (n) => `<button class="options-nav-btn" data-cat="${n.key}">${icon(n.icon)}<span>${n.label}</span></button>`
          ).join("")}
        </nav>
      </aside>
      <main class="options-content">
        <section class="options-pane" data-pane="general">
          <h2>자동 잠금</h2>
          <div class="settings-desc">팝업을 쓰거나 계정을 골라 채우지 않은 채 이 시간이 지나면 잠급니다.</div>
          <div class="segmented" role="radiogroup" aria-label="자동 잠금 시간">
            ${LOCK_OPTIONS.map(
              ([m, label]) =>
                `<button role="radio" aria-checked="${m === status.lockMinutes}" class="${m === status.lockMinutes ? "on" : ""}" data-m="${m}">${label}</button>`
            ).join("")}
          </div>
        </section>

        <section class="options-pane" data-pane="security">
          <h2>PIN 잠금 해제 ${status.pinEnabled ? '<span class="on-chip">사용 중</span>' : ""}</h2>
          <div class="settings-desc">마스터 비밀번호 대신 숫자 PIN으로 엽니다. 브라우저를 완전히 닫으면 PIN은 지워지고 한 번은 마스터 비밀번호가 필요해요. 5번 틀리면 해제됩니다.</div>
          <div class="pin-row">
            <input type="password" id="newPin" inputmode="numeric" maxlength="8" placeholder="${status.pinEnabled ? "새 PIN (4~8자리)" : "PIN (4~8자리)"}" />
            <button class="btn btn-primary" id="savePin">${status.pinEnabled ? "변경" : "설정"}</button>
          </div>
          ${status.pinEnabled ? '<button class="link-btn danger" id="removePin">PIN 해제</button>' : ""}
        </section>

        <section class="options-pane" data-pane="import">
          <h2>가져오기</h2>
          <div class="settings-desc">Chrome, Arc, Edge, Brave, 1Password에서 내보낸 CSV를 가져옵니다. 이미 저장된 계정(같은 아이디+사이트)은 자동으로 건너뜁니다.</div>
          <div class="options-field">
            <input type="file" id="importFile" accept=".csv,text/csv" />
            <label class="field-label" for="importFolder">폴더</label>
            <select id="importFolder">
              <option value="">(폴더 없음)</option>
              ${folders.map((f) => `<option value="${f.id}">${escapeHtml(f.name)}</option>`).join("")}
            </select>
            <input type="text" id="importNewFolder" placeholder="또는 새 폴더 이름 (예: 회사) — 입력하면 이쪽이 우선" maxlength="100" />
            <button class="btn btn-primary" id="importBtn" disabled>가져오기</button>
            <div id="importStatus"></div>
          </div>
        </section>

        <section class="options-pane" data-pane="admin">
          <h2>중복 계정 정리</h2>
          <div class="settings-desc">같은 아이디 + 같은 사이트로 저장된 항목을 찾습니다. 남길 항목을 고르면(기본은 최근 사용한 것) 나머지는 삭제됩니다 — 되돌릴 수 없습니다.</div>
          ${renderDuplicatesPane(duplicateGroups)}
        </section>

        <section class="options-pane" data-pane="account">
          <h2>계정</h2>
          <div class="settings-desc">${escapeHtml(status.email)}<br>${escapeHtml(status.serverUrl)}</div>
          <button class="btn btn-secondary" id="logoutBtn" style="align-self:flex-start;">로그아웃</button>
        </section>
      </main>
    </div>
  `;

  const showCat = (cat) => {
    document.querySelectorAll(".options-nav-btn").forEach((b) => b.classList.toggle("active", b.dataset.cat === cat));
    document.querySelectorAll(".options-pane").forEach((pane) => {
      pane.hidden = pane.dataset.pane !== cat;
    });
  };
  showCat(activeCat);
  document.querySelectorAll(".options-nav-btn").forEach((btn) => {
    btn.addEventListener("click", () => {
      activeCat = btn.dataset.cat;
      showCat(activeCat);
    });
  });

  document.querySelectorAll(".segmented button").forEach((b) =>
    b.addEventListener("click", async () => {
      const res = await send({ type: "SET_LOCK_MINUTES", minutes: Number(b.dataset.m) });
      if (res?.ok) renderOptions();
    })
  );

  const savePin = async () => {
    const res = await send({ type: "SET_PIN", pin: document.getElementById("newPin").value });
    if (res?.ok) renderOptions();
  };
  document.getElementById("savePin").addEventListener("click", savePin);
  document.getElementById("newPin").addEventListener("keydown", (e) => e.key === "Enter" && savePin());
  document.getElementById("removePin")?.addEventListener("click", async () => {
    await send({ type: "REMOVE_PIN" });
    renderOptions();
  });
  document.getElementById("logoutBtn").addEventListener("click", async () => {
    if (!confirm("로그아웃할까요? 로컬에 저장된 금고도 지워집니다.")) return;
    await send({ type: "LOGOUT" });
    renderOptions();
  });

  const deleteGroupExcept = async (group, keepId) => {
    for (const item of group) {
      if (item.id !== keepId) await send({ type: "DELETE_ITEM", id: item.id });
    }
  };

  document.querySelectorAll("[data-dedupe]").forEach((btn) => {
    btn.addEventListener("click", async () => {
      const gi = Number(btn.dataset.dedupe);
      const group = duplicateGroups[gi];
      const keepId = document.querySelector(`input[name="dup-${gi}"]:checked`)?.value;
      if (!keepId) return;
      btn.disabled = true;
      btn.textContent = "정리하는 중...";
      await deleteGroupExcept(group, keepId);
      renderOptions();
    });
  });

  document.getElementById("dedupeAll")?.addEventListener("click", async (e) => {
    const extra = duplicateGroups.reduce((n, g) => n + g.length - 1, 0);
    if (!confirm(`중복 ${extra}개 항목을 삭제합니다. 각 그룹은 최근 사용한 항목만 남습니다. 계속할까요?`)) return;
    e.target.disabled = true;
    e.target.textContent = "정리하는 중...";
    for (const group of duplicateGroups) {
      await deleteGroupExcept(group, pickDefaultKeep(group).id);
    }
    renderOptions();
  });

  wireImportForm();
}

function wireImportForm() {
  const fileInput = document.getElementById("importFile");
  const folderSelect = document.getElementById("importFolder");
  const newFolderInput = document.getElementById("importNewFolder");
  const importBtn = document.getElementById("importBtn");
  const statusEl = document.getElementById("importStatus");

  fileInput.addEventListener("change", () => {
    importBtn.disabled = !fileInput.files.length;
    statusEl.textContent = "";
  });

  const setFormDisabled = (disabled) => {
    fileInput.disabled = disabled;
    folderSelect.disabled = disabled;
    newFolderInput.disabled = disabled;
    importBtn.disabled = disabled || !fileInput.files.length;
  };

  importBtn.addEventListener("click", async () => {
    const file = fileInput.files[0];
    if (!file) return;
    setFormDisabled(true);
    statusEl.textContent = "가져오는 중...";
    try {
      const entries = normalizeImportRows(parseCsv(await file.text()));
      if (!entries.length) {
        statusEl.textContent = "이 파일에서 로그인 항목을 찾지 못했습니다.";
        return;
      }
      const res = await send({
        type: "IMPORT_ITEMS",
        entries,
        folderId: folderSelect.value || null,
        newFolderName: newFolderInput.value,
      });
      if (!res?.ok) {
        statusEl.textContent = res?.error === "Locked" ? "잠겨 있습니다. 먼저 팝업에서 잠금을 해제하세요." : res?.error || "가져오기 실패";
        return;
      }
      statusEl.textContent = `${res.imported}개 가져왔습니다. 이미 있던 ${res.skipped}개는 건너뛰었고, ${res.failed}개는 실패했습니다.`;
      if (newFolderInput.value.trim()) {
        renderOptions(); // 새 폴더가 생겼으니 폴더 목록을 다시 불러온다
        return;
      }
    } catch (err) {
      statusEl.textContent = `가져오기 실패: ${err.message}`;
    } finally {
      fileInput.value = "";
      setFormDisabled(false);
    }
  });
}

renderOptions();

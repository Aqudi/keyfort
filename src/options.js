import { brandHtml } from "./brand.js";
import { parseCsv } from "./lib/csv.js";
import { normalizeImportRows } from "./lib/importers.js";

document.getElementById("brand").innerHTML = brandHtml();

const fileInput = document.getElementById("importFile");
const importBtn = document.getElementById("importBtn");
const statusEl = document.getElementById("importStatus");

fileInput.addEventListener("change", () => {
  importBtn.disabled = !fileInput.files.length;
  statusEl.textContent = "";
});

importBtn.addEventListener("click", async () => {
  const file = fileInput.files[0];
  if (!file) return;
  importBtn.disabled = true;
  statusEl.textContent = "가져오는 중...";
  try {
    const entries = normalizeImportRows(parseCsv(await file.text()));
    if (!entries.length) {
      statusEl.textContent = "이 파일에서 로그인 항목을 찾지 못했습니다.";
      return;
    }
    const res = await chrome.runtime.sendMessage({ type: "IMPORT_ITEMS", entries });
    if (!res?.ok) {
      statusEl.textContent = res?.error === "Locked" ? "잠겨 있습니다. 먼저 팝업에서 잠금을 해제하세요." : res?.error || "가져오기 실패";
      return;
    }
    statusEl.textContent = `${res.imported}개 가져왔습니다. 이미 있던 ${res.skipped}개는 건너뛰었고, ${res.failed}개는 실패했습니다.`;
  } catch (err) {
    statusEl.textContent = `가져오기 실패: ${err.message}`;
  } finally {
    importBtn.disabled = !fileInput.files.length;
    fileInput.value = "";
  }
});

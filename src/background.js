// src/background.js - MV3 service worker: session/auth hub for the extension.
import {
  deriveMasterKey,
  hashMasterKey,
  stretchKey,
  decryptSymmetricKey,
  decryptEncString,
  encryptString,
  generateTotp,
} from "./lib/crypto.js";
import { VaultwardenClient } from "./lib/api.js";
import { uriHostname, isSameSite } from "./lib/site.js";

const AUTO_LOCK_MINUTES = 15;
const AUTO_LOCK_ALARM = "auto-lock";
const PENDING_SAVE_TTL_MS = 5 * 60 * 1000;
const MAX_CAPTURED_FIELD_LENGTH = 1000; // 페이지에서 캡처한 값에 대한 방어적 상한

// Bumped on every lock (LOCK message / auto-lock). In-flight writers capture it up front
// and refuse to write if it changed, so a lock can never be undone by a stale write.
let lockEpoch = 0;

// ---- storage helpers -------------------------------------------------

async function getConfig() {
  const { serverUrl, email } = await chrome.storage.local.get(["serverUrl", "email"]);
  return { serverUrl: serverUrl || "", email: email || "" };
}

async function setConfig(cfg) {
  await chrome.storage.local.set(cfg);
}

async function getSession() {
  const { session } = await chrome.storage.session.get(["session"]);
  return session || null;
}

async function setSession(session) {
  await chrome.storage.session.set({ session });
}

async function clearSession() {
  lockEpoch += 1;
  await chrome.storage.session.remove(["session"]);
}

// Writes only if the vault is still unlocked and no lock happened since `epoch` was
// captured, so an in-flight SYNC/refresh cannot resurrect a session that LOCK (or
// auto-lock) has just cleared. The epoch is re-checked synchronously after the last
// await, right before the write is issued.
async function updateSession(session, epoch) {
  if (epoch !== lockEpoch) throw new Error("Locked");
  if (!(await getSession())) throw new Error("Locked");
  if (epoch !== lockEpoch) throw new Error("Locked");
  await setSession(session);
}

async function scheduleAutoLock() {
  if (await getSession()) {
    await chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: AUTO_LOCK_MINUTES });
  } else {
    await chrome.alarms.clear(AUTO_LOCK_ALARM);
  }
}

function userKeyFromSession(session) {
  return {
    encKey: Uint8Array.from(atob(session.userKey.encKey), (c) => c.charCodeAt(0)),
    macKey: Uint8Array.from(atob(session.userKey.macKey), (c) => c.charCodeAt(0)),
  };
}

function bytesToB64(bytes) {
  let bin = "";
  for (const b of bytes) bin += String.fromCharCode(b);
  return btoa(bin);
}

// ---- core actions ------------------------------------------------------

const TWO_FACTOR_AUTHENTICATOR = 0;

async function doLogin({ serverUrl, email, password, twoFactorCode }) {
  const client = new VaultwardenClient(serverUrl);
  const { kdfIterations } = await client.prelogin(email);
  const masterKey = await deriveMasterKey(password, email, kdfIterations);
  const mpHash = await hashMasterKey(masterKey, password);
  let loginData;
  try {
    const twoFactor = twoFactorCode ? { token: twoFactorCode, provider: TWO_FACTOR_AUTHENTICATOR } : undefined;
    loginData = await client.login(email, mpHash, twoFactor);
  } catch (err) {
    if (!err.twoFactorRequired) throw err;
    // ponytail: 인증 앱(TOTP) 코드만 지원. 이메일/YubiKey/WebAuthn은 필요해지면 추가.
    if (!err.twoFactorProviders.includes(TWO_FACTOR_AUTHENTICATOR)) {
      throw new Error(`지원하지 않는 2단계 인증 방식입니다 (provider: ${err.twoFactorProviders.join(", ")}). 인증 앱(TOTP)을 활성화하세요.`);
    }
    return { ok: false, twoFactorRequired: true };
  }
  const stretched = await stretchKey(masterKey);
  const userKey = await decryptSymmetricKey(loginData.Key, stretched);

  const syncData = await client.sync(loginData.access_token);
  const ciphers = syncData.ciphers ?? syncData.Ciphers ?? [];

  const session = {
    serverUrl,
    email,
    accessToken: loginData.access_token,
    refreshToken: loginData.refresh_token,
    tokenObtainedAt: Date.now(),
    expiresIn: loginData.expires_in,
    userKey: { encKey: bytesToB64(userKey.encKey), macKey: bytesToB64(userKey.macKey) },
    ciphers,
  };
  await setSession(session);
  await setConfig({ serverUrl, email });
  return { ok: true };
}

async function ensureFreshToken(session, epoch) {
  const ageSec = (Date.now() - session.tokenObtainedAt) / 1000;
  if (ageSec < (session.expiresIn || 3600) - 60) return session;
  const client = new VaultwardenClient(session.serverUrl);
  const data = await client.refreshToken(session.refreshToken);
  const refreshed = {
    ...session,
    accessToken: data.access_token,
    refreshToken: data.refresh_token || session.refreshToken,
    tokenObtainedAt: Date.now(),
    expiresIn: data.expires_in,
  };
  await updateSession(refreshed, epoch);
  return refreshed;
}

async function doSync() {
  const epoch = lockEpoch;
  const current = await getSession();
  if (!current) throw new Error("Locked");
  const session = await ensureFreshToken(current, epoch);
  const client = new VaultwardenClient(session.serverUrl);
  const syncData = await client.sync(session.accessToken);
  const ciphers = syncData.ciphers ?? syncData.Ciphers ?? [];
  await updateSession({ ...session, ciphers }, epoch);
  return ciphers;
}

function cipherField(cipher, camel, pascal) {
  return cipher[camel] ?? cipher[pascal];
}

async function decryptCipherSummary(cipher, userKey) {
  const name = await decryptEncString(cipherField(cipher, "name", "Name"), userKey);
  const login = cipherField(cipher, "login", "Login");
  let username = null;
  let uris = [];
  let hasTotp = false;
  if (login) {
    const u = cipherField(login, "username", "Username");
    username = u ? await decryptEncString(u, userKey) : null;
    hasTotp = !!cipherField(login, "totp", "Totp");
    const uriList = cipherField(login, "uris", "Uris") || [];
    for (const uriObj of uriList) {
      const encUri = cipherField(uriObj, "uri", "Uri");
      if (encUri) {
        try {
          uris.push(await decryptEncString(encUri, userKey));
        } catch {
          /* ignore individual bad uri */
        }
      }
    }
  }
  return {
    id: cipherField(cipher, "id", "Id"),
    type: cipherField(cipher, "type", "Type"),
    name,
    username,
    uris,
    hasTotp,
  };
}

async function getItemList() {
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const userKey = userKeyFromSession(session);
  const items = [];
  let skipped = 0;
  for (const cipher of session.ciphers) {
    if (cipherField(cipher, "type", "Type") !== 1) continue; // 1 = Login
    if (cipherField(cipher, "deletedDate", "DeletedDate")) continue; // trashed
    try {
      items.push(await decryptCipherSummary(cipher, userKey));
    } catch {
      skipped += 1; // undecryptable with the user key (e.g. org item); surfaced via `skipped`
    }
  }
  return { items, skipped };
}

async function getItemSecrets(id) {
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const userKey = userKeyFromSession(session);
  const cipher = session.ciphers.find((c) => cipherField(c, "id", "Id") === id);
  if (!cipher) throw new Error("Item not found");
  const login = cipherField(cipher, "login", "Login");
  const passwordEnc = cipherField(login, "password", "Password");
  const totpEnc = cipherField(login, "totp", "Totp");
  const password = passwordEnc ? await decryptEncString(passwordEnc, userKey) : null;
  if (!totpEnc) return { password, totp: null };
  // A corrupt TOTP seed must not take the password down with it.
  try {
    const seed = await decryptEncString(totpEnc, userKey);
    return { password, totp: await generateTotp(seed) };
  } catch (err) {
    console.warn("TOTP generation failed:", err.message);
    return { password, totp: null, totpError: err.message };
  }
}

// ---- 페이지 통합: 계정 자동 제안 + 새 로그인 저장 제안 ----------------------
// 콘텐츠 스크립트(임의의 웹페이지)가 보내는 메시지는 host를 절대 그대로 믿지 않는다.
// 항상 sender.tab.url에서 우리가 직접 다시 계산한다.

// 같은 사용자 이름이 이미 저장돼 있으면 다시 묻지 않는다.
// ponytail: 비밀번호가 바뀐 경우의 "업데이트" 제안은 범위 밖 — 필요해지면 추가.
async function maybeQueuePendingSave(tabId, host, username, password) {
  const session = await getSession();
  if (!session) return; // 잠겨 있으면 비교/저장 둘 다 불가능하니 조용히 무시
  const { items } = await getItemList();
  const alreadySaved = items.some(
    (item) => item.username === username && item.uris.some((u) => isSameSite(uriHostname(u), host))
  );
  if (alreadySaved) return;
  // ponytail: 탭이 닫히면 항목이 남을 수 있다(5분 뒤 TTL로 무시됨). 탭 종료 리스너 정리는 필요해지면 추가.
  await chrome.storage.session.set({
    [`pendingSave:${tabId}`]: { host, username, password, createdAt: Date.now() },
  });
}

async function takePendingSave(tabId, tabUrl) {
  const key = `pendingSave:${tabId}`;
  const { [key]: entry } = await chrome.storage.session.get([key]);
  if (!entry) return null;
  await chrome.storage.session.remove([key]); // 한 번 보여주면 끝 — 새로고침해도 다시 안 뜬다
  if (Date.now() - entry.createdAt > PENDING_SAVE_TTL_MS) return null;
  if (entry.host !== uriHostname(tabUrl)) return null; // 대기 중 다른 사이트로 이동함
  return { host: entry.host, username: entry.username, password: entry.password };
}

async function saveItem({ host, username, password }) {
  const epoch = lockEpoch;
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const userKey = userKeyFromSession(session);
  const client = new VaultwardenClient(session.serverUrl);
  const payload = {
    type: 1,
    name: await encryptString(host, userKey),
    notes: null,
    favorite: false,
    folderId: null,
    organizationId: null,
    login: {
      username: username ? await encryptString(username, userKey) : null,
      password: await encryptString(password, userKey),
      totp: null,
      uris: [{ uri: await encryptString(`https://${host}`, userKey), match: null }],
    },
  };
  const created = await client.createCipher(session.accessToken, payload);
  const current = await getSession();
  if (!current) throw new Error("Locked");
  await updateSession({ ...current, ciphers: [...current.ciphers, created] }, epoch);
}

// 현재 탭 사이트와 일치하는 저장된 계정 목록(이름/사용자명만, 비밀번호 없음).
async function getHostMatches(tabUrl) {
  const host = uriHostname(tabUrl);
  if (!host) return [];
  if (!(await getSession())) return [];
  const { items } = await getItemList();
  return items
    .filter((item) => item.uris.some((u) => isSameSite(uriHostname(u), host)))
    .map(({ id, name, username, hasTotp }) => ({ id, name, username, hasTotp }));
}

// id로 지정한 항목의 비밀번호를 복호화해 해당 탭에 직접 채워 넣는다(+옵션으로 제출).
// id는 클라이언트가 보낸 값이라도, 실제로 그 항목의 저장된 URI가 현재 탭 host와 일치하는지 여기서 다시 검증한다.
async function requestAutofill(id, tab, submit) {
  const session = await getSession();
  if (!session) return { ok: false, error: "Locked" };
  const host = uriHostname(tab.url);
  if (!host) return { ok: false, error: "이 페이지에서는 자동입력할 수 없습니다." };
  const userKey = userKeyFromSession(session);
  const cipher = session.ciphers.find((c) => cipherField(c, "id", "Id") === id);
  if (!cipher) return { ok: false, error: "항목을 찾을 수 없습니다." };
  const summary = await decryptCipherSummary(cipher, userKey).catch(() => null);
  if (!summary || !summary.uris.some((u) => isSameSite(uriHostname(u), host))) {
    return { ok: false, error: "사이트가 일치하지 않습니다." };
  }
  const { password } = await getItemSecrets(id);
  await chrome.tabs.sendMessage(tab.id, { type: "DO_AUTOFILL", username: summary.username, password, submit });
  return { ok: true };
}

function isCapturedFieldValid(value, { required }) {
  if (value == null) return !required;
  return typeof value === "string" && value.length > 0 && value.length <= MAX_CAPTURED_FIELD_LENGTH;
}

// ---- message router ------------------------------------------------------

chrome.alarms.onAlarm.addListener((alarm) => {
  if (alarm.name !== AUTO_LOCK_ALARM) return;
  clearSession().catch((err) => console.error("auto-lock failed:", err));
});

// Only the extension's own pages (popup/options, even when opened in a tab) may talk to
// the vault; content scripts carry sender.tab with a web page url.
function isExtensionPage(sender) {
  if (sender.id !== chrome.runtime.id) return false;
  if (!sender.tab) return true;
  return typeof sender.url === "string" && sender.url.startsWith(chrome.runtime.getURL(""));
}

// content.js(모든 웹페이지에서 실행)가 보낼 수 있는 메시지는 이 목록으로 제한한다.
// 각 핸들러는 클라이언트가 보낸 host/id를 그대로 믿지 않고 sender.tab.url로 다시 검증한다.
const CONTENT_SCRIPT_MESSAGE_TYPES = new Set([
  "GET_HOST_MATCHES",
  "REQUEST_AUTOFILL",
  "PENDING_SAVE",
  "GET_PENDING_SAVE",
  "SAVE_ITEM",
]);

function isAllowedSender(msg, sender) {
  if (isExtensionPage(sender)) return true;
  return (
    sender.id === chrome.runtime.id &&
    !!sender.tab &&
    typeof sender.tab.url === "string" &&
    CONTENT_SCRIPT_MESSAGE_TYPES.has(msg?.type)
  );
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!isAllowedSender(msg, sender)) {
    sendResponse({ ok: false, error: "forbidden" });
    return false;
  }
  (async () => {
    try {
      switch (msg.type) {
        case "GET_STATUS": {
          const session = await getSession();
          const cfg = await getConfig();
          sendResponse({ locked: !session, email: session?.email || cfg.email, serverUrl: session?.serverUrl || cfg.serverUrl });
          break;
        }
        case "GET_CONFIG": {
          sendResponse(await getConfig());
          break;
        }
        case "LOGIN": {
          const result = await doLogin(msg);
          sendResponse(result);
          break;
        }
        case "LOCK": {
          await clearSession();
          sendResponse({ ok: true });
          break;
        }
        case "SYNC": {
          await doSync();
          sendResponse({ ok: true });
          break;
        }
        case "GET_ITEMS": {
          const { items, skipped } = await getItemList();
          sendResponse({ ok: true, items, skipped });
          break;
        }
        case "GET_ITEM_SECRETS": {
          const secrets = await getItemSecrets(msg.id);
          sendResponse({ ok: true, ...secrets });
          break;
        }
        case "GET_HOST_MATCHES": {
          const items = await getHostMatches(sender.tab.url);
          sendResponse({ ok: true, items });
          break;
        }
        case "REQUEST_AUTOFILL": {
          sendResponse(await requestAutofill(msg.id, sender.tab, !!msg.submit));
          break;
        }
        case "PENDING_SAVE": {
          const host = uriHostname(sender.tab.url);
          if (host && isCapturedFieldValid(msg.password, { required: true }) && isCapturedFieldValid(msg.username, { required: false })) {
            await maybeQueuePendingSave(sender.tab.id, host, msg.username || null, msg.password);
          }
          sendResponse({ ok: true });
          break;
        }
        case "GET_PENDING_SAVE": {
          const pending = await takePendingSave(sender.tab.id, sender.tab.url);
          sendResponse({ ok: true, pending });
          break;
        }
        case "SAVE_ITEM": {
          if (uriHostname(sender.tab.url) !== msg.host) {
            sendResponse({ ok: false, error: "사이트가 일치하지 않습니다." });
            break;
          }
          await saveItem({ host: msg.host, username: msg.username, password: msg.password });
          sendResponse({ ok: true });
          break;
        }
        default:
          sendResponse({ ok: false, error: "unknown message type" });
      }
    } catch (err) {
      sendResponse({ ok: false, error: err.message });
    }
    scheduleAutoLock().catch((err) => console.error("auto-lock schedule failed:", err));
  })();
  return true; // keep channel open for async sendResponse
});

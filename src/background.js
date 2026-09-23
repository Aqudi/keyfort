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

const DEFAULT_LOCK_MINUTES = 15;
const LOCK_MINUTE_CHOICES = [1, 5, 15, 30, 60, 0]; // 0 = 타이머 없음, 브라우저를 완전히 닫을 때만 잠김
const AUTO_LOCK_ALARM = "auto-lock";
const PIN_KDF_ITERATIONS = 600000;
const MAX_PIN_ATTEMPTS = 5;
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
  await persistVault(session);
}

async function clearSession() {
  lockEpoch += 1;
  await chrome.storage.session.remove(["session"]);
}

// ---- 잠긴 금고(storage.local) --------------------------------------------
// 잠금은 메모리 세션(storage.session)만 지우고, 아래 기록으로 서버 없이 마스터 비밀번호/PIN만으로 푼다.
// 여기 있는 건 전부 암호문이다: protectedKey는 서버가 주는 그대로(마스터 키로 암호화), ciphers도 서버 응답
// 그대로, refresh token은 user key로 다시 암호화했다. 디스크를 통째로 가져가도 마스터 비밀번호 없이는 못 연다.

async function getVault() {
  const { vault } = await chrome.storage.local.get(["vault"]);
  return vault || null;
}

// 세션이 바뀔 때마다(동기화, 토큰 갱신, 항목 저장) 잠긴 금고 사본도 맞춘다. 로그인 전(금고 기록 없음)이면 건너뛴다.
async function persistVault(session) {
  const vault = await getVault();
  if (!vault || vault.email !== session.email || vault.serverUrl !== session.serverUrl) return;
  const encRefreshToken = session.refreshToken
    ? await encryptString(session.refreshToken, userKeyFromSession(session))
    : null;
  await chrome.storage.local.set({ vault: { ...vault, ciphers: session.ciphers, encRefreshToken } });
}

function userKeyToB64(userKey) {
  return { encKey: bytesToB64(userKey.encKey), macKey: bytesToB64(userKey.macKey) };
}

async function unlockWithUserKey(vault, userKey) {
  const keys = userKeyToB64(userKey);
  const refreshToken = vault.encRefreshToken ? await decryptEncString(vault.encRefreshToken, userKey) : null;
  lockEpoch += 1;
  await chrome.storage.session.set({
    session: {
      serverUrl: vault.serverUrl,
      email: vault.email,
      accessToken: null,
      refreshToken,
      tokenObtainedAt: 0, // 다음 서버 호출 때 refresh token으로 새 access token을 받는다
      expiresIn: 0,
      userKey: keys,
      ciphers: vault.ciphers || [],
    },
  });
  // 캐시로 바로 열고, 최신 항목은 뒤에서 받아온다. 오프라인이거나 토큰이 만료돼도 잠금 해제는 성공한다.
  doSync().catch((err) => console.warn("background sync after unlock failed:", err.message));
}

async function unlockWithPassword(password) {
  const vault = await getVault();
  if (!vault) throw new Error("저장된 계정이 없습니다. 다시 로그인하세요.");
  const masterKey = await deriveMasterKey(password, vault.email, vault.kdfIterations);
  let userKey;
  try {
    userKey = await decryptSymmetricKey(vault.protectedKey, await stretchKey(masterKey));
  } catch {
    throw new Error("마스터 비밀번호가 올바르지 않습니다.");
  }
  await unlockWithUserKey(vault, userKey);
}

// PIN으로 감싼 user key는 storage.session(메모리)에만 둔다. 짧은 PIN은 디스크에 남기면 오프라인 대입에 약하다.
// 그래서 브라우저를 완전히 닫으면 PIN도 사라지고 마스터 비밀번호가 필요하다.
async function pinKey(pin, email) {
  return stretchKey(await deriveMasterKey(pin, `${email}|keyfort-pin`, PIN_KDF_ITERATIONS));
}

async function setPin(pin) {
  if (!/^\d{4,8}$/.test(pin)) throw new Error("PIN은 숫자 4~8자리여야 합니다.");
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const wrapped = await encryptString(JSON.stringify(session.userKey), await pinKey(pin, session.email));
  await chrome.storage.session.set({ pin: { email: session.email, wrapped, failures: 0 } });
}

// 시도는 한 번에 하나씩만 처리한다. 동시에 여러 요청이 오면 모두 같은 실패 횟수를 읽고(느린 KDF 동안)
// 제한이 무력화되고, 지운 PIN 기록을 늦게 끝난 요청이 되살릴 수 있다.
let pinQueue = Promise.resolve();
function unlockWithPin(pin) {
  const run = pinQueue.then(() => unlockWithPinNow(pin));
  pinQueue = run.catch(() => {});
  return run;
}

async function unlockWithPinNow(pin) {
  const { pin: record } = await chrome.storage.session.get(["pin"]);
  const vault = await getVault();
  if (!record || !vault || record.email !== vault.email) throw new Error("PIN이 설정되어 있지 않습니다.");
  let keys;
  try {
    keys = JSON.parse(await decryptEncString(record.wrapped, await pinKey(pin, record.email)));
  } catch {
    const { pin: current } = await chrome.storage.session.get(["pin"]);
    if (current?.wrapped !== record.wrapped) throw new Error("PIN이 설정되어 있지 않습니다."); // KDF 중 해제·변경됨
    const failures = record.failures + 1;
    if (failures >= MAX_PIN_ATTEMPTS) {
      await chrome.storage.session.remove(["pin"]);
      return { ok: false, pinDisabled: true, error: `PIN을 ${MAX_PIN_ATTEMPTS}번 틀려 해제했습니다. 마스터 비밀번호로 여세요.` };
    }
    await chrome.storage.session.set({ pin: { ...record, failures } });
    return { ok: false, error: `PIN이 올바르지 않습니다. (${MAX_PIN_ATTEMPTS - failures}번 남음)` };
  }
  await chrome.storage.session.set({ pin: { ...record, failures: 0 } });
  await unlockWithUserKey(vault, {
    encKey: Uint8Array.from(atob(keys.encKey), (c) => c.charCodeAt(0)),
    macKey: Uint8Array.from(atob(keys.macKey), (c) => c.charCodeAt(0)),
  });
  return { ok: true };
}

async function logout() {
  await clearSession();
  await chrome.storage.session.remove(["pin"]);
  await chrome.storage.local.remove(["vault", "lastUsed"]);
}

async function getLockMinutes() {
  const { lockMinutes } = await chrome.storage.local.get(["lockMinutes"]);
  return LOCK_MINUTE_CHOICES.includes(lockMinutes) ? lockMinutes : DEFAULT_LOCK_MINUTES;
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
  const minutes = await getLockMinutes();
  if (minutes && (await getSession())) {
    await chrome.alarms.create(AUTO_LOCK_ALARM, { delayInMinutes: minutes });
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
const TWO_FACTOR_REMEMBER = 5;
const REMEMBERED_2FA_KEY = "rememberedTwoFactor"; // { "<serverUrl>|<email>": TwoFactorToken }

// 서버가 이 기기(deviceIdentifier)에 발급한 "2FA 기억" 토큰. storage.local은 content script도 읽을 수 있으므로
// 마스터 키로 암호화해 둔다(로그인 때마다 어차피 마스터 키를 만든다). 서버가 거부하면 지우고 다시 OTP를 묻는다.
async function rememberedTwoFactor(account, stretched, token) {
  const { [REMEMBERED_2FA_KEY]: all = {} } = await chrome.storage.local.get([REMEMBERED_2FA_KEY]);
  if (token === undefined) {
    if (!all[account]) return null;
    return decryptEncString(all[account], stretched).catch(() => null); // 비밀번호가 바뀌었으면 못 푼다 → OTP
  }
  const next = { ...all };
  if (token) next[account] = await encryptString(token, stretched);
  else delete next[account];
  await chrome.storage.local.set({ [REMEMBERED_2FA_KEY]: next });
}

async function doLogin({ serverUrl, email, password, twoFactorCode }) {
  const client = new VaultwardenClient(serverUrl);
  const { kdfIterations } = await client.prelogin(email);
  const masterKey = await deriveMasterKey(password, email, kdfIterations);
  const mpHash = await hashMasterKey(masterKey, password);
  const account = `${client.serverUrl}|${email.toLowerCase()}`;
  const stretched = await stretchKey(masterKey);
  const remembered = twoFactorCode ? null : await rememberedTwoFactor(account, stretched);
  let loginData;
  try {
    const twoFactor = twoFactorCode
      ? { token: twoFactorCode, provider: TWO_FACTOR_AUTHENTICATOR, remember: true }
      : remembered
        ? { token: remembered, provider: TWO_FACTOR_REMEMBER }
        : undefined;
    loginData = await client.login(email, mpHash, twoFactor);
  } catch (err) {
    if (!err.twoFactorRequired) throw err;
    if (remembered) await rememberedTwoFactor(account, stretched, null);
    // ponytail: 인증 앱(TOTP) 코드만 지원. 이메일/YubiKey/WebAuthn은 필요해지면 추가.
    if (!err.twoFactorProviders.includes(TWO_FACTOR_AUTHENTICATOR)) {
      throw new Error(`지원하지 않는 2단계 인증 방식입니다 (provider: ${err.twoFactorProviders.join(", ")}). 인증 앱(TOTP)을 활성화하세요.`);
    }
    return { ok: false, twoFactorRequired: true };
  }
  if (loginData.TwoFactorToken) await rememberedTwoFactor(account, stretched, loginData.TwoFactorToken);
  const userKey = await decryptSymmetricKey(loginData.Key, stretched);

  const syncData = await client.sync(loginData.access_token);
  const ciphers = syncData.ciphers ?? syncData.Ciphers ?? [];

  await chrome.storage.local.set({
    vault: { serverUrl, email, kdfIterations, protectedKey: loginData.Key, ciphers: [], encRefreshToken: null },
  });
  // 다른 계정으로 로그인했으면 이전 계정 기준의 PIN은 무효다.
  const { pin } = await chrome.storage.session.get(["pin"]);
  if (pin && pin.email !== email) await chrome.storage.session.remove(["pin"]);
  const session = {
    serverUrl,
    email,
    accessToken: loginData.access_token,
    refreshToken: loginData.refresh_token,
    tokenObtainedAt: Date.now(),
    expiresIn: loginData.expires_in,
    userKey: userKeyToB64(userKey),
    ciphers,
  };
  lockEpoch += 1;
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
// 항상 sender.url(메시지를 보낸 프레임의 URL, 브라우저가 채움)에서 우리가 직접 다시 계산한다.
// all_frames라 iframe도 보낼 수 있으므로 탭 URL이 아니라 프레임 URL 기준이어야 한다.

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
  // all_frames라 같은 탭의 다른 출처 iframe(광고 등)도 묻는다 — host가 맞는 프레임만 가져가게 먼저 비교한다.
  if (entry.host !== uriHostname(tabUrl)) return null;
  await chrome.storage.session.remove([key]); // 한 번 보여주면 끝 — 새로고침해도 다시 안 뜬다
  if (Date.now() - entry.createdAt > PENDING_SAVE_TTL_MS) return null;
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
  const { lastUsed = {} } = await chrome.storage.local.get(["lastUsed"]);
  return items
    .filter((item) => item.uris.some((u) => isSameSite(uriHostname(u), host)))
    .map(({ id, name, username, hasTotp }) => ({ id, name, username, hasTotp, lastUsedAt: lastUsed[id] || null }))
    .sort((a, b) => (b.lastUsedAt || 0) - (a.lastUsedAt || 0));
}

// 항목 id → 마지막 자동입력 시각. 어느 사이트였는지는 남기지 않는다(방문 기록이 되지 않게).
async function markUsed(id) {
  const { lastUsed = {} } = await chrome.storage.local.get(["lastUsed"]);
  await chrome.storage.local.set({ lastUsed: { ...lastUsed, [id]: Date.now() } });
}

// id로 지정한 항목의 비밀번호를 복호화해 해당 탭에 직접 채워 넣는다(+옵션으로 제출).
// id는 클라이언트가 보낸 값이라도, 실제로 그 항목의 저장된 URI가 현재 탭 host와 일치하는지 여기서 다시 검증한다.
async function requestAutofill(id, tab, frameUrl, documentId, submit) {
  const session = await getSession();
  if (!session) return { ok: false, error: "Locked" };
  const host = uriHostname(frameUrl);
  if (!host) return { ok: false, error: "이 페이지에서는 자동입력할 수 없습니다." };
  const userKey = userKeyFromSession(session);
  const cipher = session.ciphers.find((c) => cipherField(c, "id", "Id") === id);
  if (!cipher) return { ok: false, error: "항목을 찾을 수 없습니다." };
  const summary = await decryptCipherSummary(cipher, userKey).catch(() => null);
  if (!summary || !summary.uris.some((u) => isSameSite(uriHostname(u), host))) {
    return { ok: false, error: "사이트가 일치하지 않습니다." };
  }
  const { password } = await getItemSecrets(id);
  // documentId로 보내야 검증 후 프레임이 다른 페이지로 이동했을 때 새 문서가 비밀번호를 받지 않는다.
  // content.js도 host를 한 번 더 확인한다.
  await chrome.tabs.sendMessage(tab.id, { type: "DO_AUTOFILL", host, username: summary.username, password, submit }, { documentId });
  await markUsed(id);
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
// 각 핸들러는 클라이언트가 보낸 host/id를 그대로 믿지 않고 프레임 URL(sender.url)로 다시 검증한다.
const CONTENT_SCRIPT_MESSAGE_TYPES = new Set([
  "GET_HOST_MATCHES",
  "REQUEST_AUTOFILL",
  "PENDING_SAVE",
  "GET_PENDING_SAVE",
  "SAVE_ITEM",
]);

const USER_ACTION_MESSAGE_TYPES = new Set(["REQUEST_AUTOFILL", "SAVE_ITEM"]);

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
  const frameUrl = sender.url ?? sender.tab?.url;
  (async () => {
    try {
      switch (msg.type) {
        case "GET_STATUS": {
          const session = await getSession();
          const cfg = await getConfig();
          const vault = await getVault();
          const { pin } = await chrome.storage.session.get(["pin"]);
          sendResponse({
            locked: !session,
            canUnlock: !!vault, // 로컬 금고가 있으면 서버 로그인 없이 비밀번호/PIN으로 연다
            pinEnabled: !!pin && pin.email === vault?.email,
            lockMinutes: await getLockMinutes(),
            email: session?.email || vault?.email || cfg.email,
            serverUrl: session?.serverUrl || vault?.serverUrl || cfg.serverUrl,
          });
          break;
        }
        case "UNLOCK": {
          await unlockWithPassword(msg.password);
          sendResponse({ ok: true });
          break;
        }
        case "UNLOCK_PIN": {
          sendResponse(await unlockWithPin(String(msg.pin ?? "")));
          break;
        }
        case "SET_PIN": {
          await setPin(String(msg.pin ?? ""));
          sendResponse({ ok: true });
          break;
        }
        case "REMOVE_PIN": {
          await chrome.storage.session.remove(["pin"]);
          sendResponse({ ok: true });
          break;
        }
        case "LOGOUT": {
          await logout();
          sendResponse({ ok: true });
          break;
        }
        case "SET_LOCK_MINUTES": {
          if (!LOCK_MINUTE_CHOICES.includes(msg.minutes)) throw new Error("지원하지 않는 잠금 시간입니다.");
          await chrome.storage.local.set({ lockMinutes: msg.minutes });
          sendResponse({ ok: true });
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
          const items = await getHostMatches(frameUrl);
          sendResponse({ ok: true, items });
          break;
        }
        case "REQUEST_AUTOFILL": {
          sendResponse(await requestAutofill(msg.id, sender.tab, frameUrl, sender.documentId, !!msg.submit));
          break;
        }
        case "PENDING_SAVE": {
          const host = uriHostname(frameUrl);
          if (host && isCapturedFieldValid(msg.password, { required: true }) && isCapturedFieldValid(msg.username, { required: false })) {
            await maybeQueuePendingSave(sender.tab.id, host, msg.username || null, msg.password);
          }
          sendResponse({ ok: true });
          break;
        }
        case "GET_PENDING_SAVE": {
          const pending = await takePendingSave(sender.tab.id, frameUrl);
          sendResponse({ ok: true, pending });
          break;
        }
        case "SAVE_ITEM": {
          if (uriHostname(frameUrl) !== msg.host) {
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
    // 잠금 타이머는 사용자가 직접 한 일(팝업 사용, 계정 선택, 저장)로만 연장한다. 로그인 폼이 있는 페이지를
    // 여는 것만으로(GET_HOST_MATCHES 등) 연장되면 사실상 영영 안 잠긴다.
    if (isExtensionPage(sender) || USER_ACTION_MESSAGE_TYPES.has(msg.type)) {
      scheduleAutoLock().catch((err) => console.error("auto-lock schedule failed:", err));
    }
  })();
  return true; // keep channel open for async sendResponse
});

// src/background.js - MV3 service worker: session/auth hub for the extension.
import {
  deriveMasterKey,
  hashMasterKey,
  stretchKey,
  decryptSymmetricKey,
  decryptEncString,
  generateTotp,
} from "./lib/crypto.js";
import { VaultwardenClient } from "./lib/api.js";

const AUTO_LOCK_MINUTES = 15;
const AUTO_LOCK_ALARM = "auto-lock";

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

async function doLogin({ serverUrl, email, password }) {
  const client = new VaultwardenClient(serverUrl);
  const { kdfIterations } = await client.prelogin(email);
  const masterKey = await deriveMasterKey(password, email, kdfIterations);
  const mpHash = await hashMasterKey(masterKey, password);
  const loginData = await client.login(email, mpHash);
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

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (!isExtensionPage(sender)) {
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

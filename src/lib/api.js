// src/lib/api.js
// Minimal Bitwarden-compatible API client for Vaultwarden.

const KDF_PBKDF2 = 0;
const MIN_KDF_ITERATIONS = 5000;
const MAX_KDF_ITERATIONS = 10_000_000;
const DEVICE_TYPE_CHROME_EXTENSION = "2";
const DEVICE_ID_KEY = "deviceIdentifier";

// Stable per-install device id (a fresh one per login would register a new device each time).
// Falls back to an ephemeral id where chrome.storage is unavailable (Node test scripts).
async function getDeviceIdentifier() {
  const storage = typeof chrome !== "undefined" ? chrome.storage?.local : null;
  if (!storage) return crypto.randomUUID();
  try {
    const stored = (await storage.get([DEVICE_ID_KEY]))[DEVICE_ID_KEY];
    if (stored) return stored;
    const id = crypto.randomUUID();
    await storage.set({ [DEVICE_ID_KEY]: id });
    return id;
  } catch (err) {
    console.warn("device id storage unavailable, using an ephemeral id:", err.message);
    return crypto.randomUUID();
  }
}

export class VaultwardenClient {
  constructor(serverUrl) {
    this.serverUrl = serverUrl.replace(/\/$/, "");
  }

  async prelogin(email) {
    const res = await fetch(`${this.serverUrl}/identity/accounts/prelogin`, {
      method: "POST",
      headers: { "content-type": "application/json" },
      body: JSON.stringify({ email }),
    });
    if (!res.ok) throw new Error(`prelogin failed: ${res.status}`);
    const data = await res.json();
    const kdf = data.kdf ?? KDF_PBKDF2;
    const kdfIterations = data.kdfIterations ?? 600000;
    if (kdf !== KDF_PBKDF2) {
      throw new Error("이 계정은 Argon2id KDF를 사용합니다. 아직 지원하지 않습니다");
    }
    if (!Number.isInteger(kdfIterations)) {
      throw new Error("서버가 유효하지 않은 KDF 반복 횟수를 반환했습니다. 거부합니다");
    }
    if (kdfIterations < MIN_KDF_ITERATIONS) {
      throw new Error(`서버가 비정상적으로 낮은 KDF 반복 횟수(${kdfIterations})를 반환했습니다. 거부합니다`);
    }
    if (kdfIterations > MAX_KDF_ITERATIONS) {
      throw new Error(`서버가 비정상적으로 높은 KDF 반복 횟수(${kdfIterations})를 반환했습니다. 거부합니다`);
    }
    return { kdf, kdfIterations };
  }

  // masterPasswordHashB64: base64 hash computed via hashMasterKey()
  async login(email, masterPasswordHashB64) {
    const body = new URLSearchParams({
      grant_type: "password",
      username: email,
      password: masterPasswordHashB64,
      scope: "api offline_access",
      client_id: "browser",
      deviceType: DEVICE_TYPE_CHROME_EXTENSION,
      deviceIdentifier: await getDeviceIdentifier(),
      deviceName: "1pw-clone-extension",
    });
    const res = await fetch(`${this.serverUrl}/identity/connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    const data = await res.json();
    if (!res.ok) {
      const msg = data.error_description || data.ErrorModel?.Message || data.error || `login failed: ${res.status}`;
      const err = new Error(msg);
      err.raw = data;
      throw err;
    }
    return data; // { access_token, refresh_token, Key, PrivateKey, ... }
  }

  async refreshToken(refreshToken) {
    const body = new URLSearchParams({
      grant_type: "refresh_token",
      refresh_token: refreshToken,
      client_id: "browser",
    });
    const res = await fetch(`${this.serverUrl}/identity/connect/token`, {
      method: "POST",
      headers: { "content-type": "application/x-www-form-urlencoded" },
      body: body.toString(),
    });
    if (!res.ok) throw new Error(`refresh failed: ${res.status}`);
    return res.json();
  }

  async sync(accessToken) {
    const res = await fetch(`${this.serverUrl}/api/sync?excludeDomains=true`, {
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) throw new Error(`sync failed: ${res.status}`);
    return res.json();
  }
}

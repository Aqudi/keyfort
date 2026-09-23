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
  // twoFactor: { token, provider, remember } — 서버가 2단계 인증을 요구할 때 두 번째 호출에서 넘긴다.
  // remember면 서버가 응답에 TwoFactorToken을 주고, 다음부터 provider 5(Remember)로 그 토큰을 내면 OTP를 건너뛴다.
  async login(email, masterPasswordHashB64, twoFactor) {
    const body = new URLSearchParams({
      grant_type: "password",
      username: email,
      password: masterPasswordHashB64,
      scope: "api offline_access",
      client_id: "browser",
      deviceType: DEVICE_TYPE_CHROME_EXTENSION,
      deviceIdentifier: await getDeviceIdentifier(),
      deviceName: "keyfort-extension",
      ...(twoFactor && {
        twoFactorToken: twoFactor.token,
        twoFactorProvider: String(twoFactor.provider),
        twoFactorRemember: twoFactor.remember ? "1" : "0",
      }),
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
      if (Array.isArray(data.TwoFactorProviders)) {
        err.twoFactorRequired = true;
        err.twoFactorProviders = data.TwoFactorProviders.map(Number);
      }
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

  // cipher: 이미 암호화된(EncString) 필드로 구성된 Bitwarden Cipher 요청 바디.
  async createCipher(accessToken, cipher) {
    const res = await fetch(`${this.serverUrl}/api/ciphers`, {
      method: "POST",
      headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(cipher),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.Message || data.message || `create cipher failed: ${res.status}`);
    }
    return data;
  }

  // cipher: createCipher와 같은 형태의 전체 바디(부분 patch가 아님 — Vaultwarden PUT은 전체 교체).
  async updateCipher(accessToken, id, cipher) {
    const res = await fetch(`${this.serverUrl}/api/ciphers/${encodeURIComponent(id)}`, {
      method: "PUT",
      headers: { "content-type": "application/json", authorization: `Bearer ${accessToken}` },
      body: JSON.stringify(cipher),
    });
    const data = await res.json();
    if (!res.ok) {
      throw new Error(data.Message || data.message || `update cipher failed: ${res.status}`);
    }
    return data;
  }

  async deleteCipher(accessToken, id) {
    const res = await fetch(`${this.serverUrl}/api/ciphers/${encodeURIComponent(id)}`, {
      method: "DELETE",
      headers: { authorization: `Bearer ${accessToken}` },
    });
    if (!res.ok) throw new Error(`delete cipher failed: ${res.status}`);
  }
}

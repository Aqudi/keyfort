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
import { uriHostname, uriMatches } from "./lib/site.js";

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

// ciphers/folders는 storage.session에 안 둔다 — storage.session은 unlimitedStorage로도 못 늘어나는
// 하드 10MB 한도가 있어서(직접 확인함), 계정에 항목이 많아지면 조용히 quota exceeded로 저장이 실패한다.
// 대신 storage.local(잠긴 금고, 이미 암호문이라 디스크에 있어도 안전)에서 매번 합쳐서 돌려준다.
async function getSession() {
  const { session } = await chrome.storage.session.get(["session"]);
  if (!session) return null;
  const vault = await getVault();
  return { ...session, ciphers: vault?.ciphers || [], folders: vault?.folders || [] };
}

async function setSession(session, epoch = lockEpoch) {
  const { ciphers, folders, ...small } = session;
  await persistVault(session); // ciphers/folders는 storage.local로 (unlimitedStorage가 실제로 적용됨)
  // persistVault가 await를 거치는 동안 LOCK/auto-lock이 끼어들 수 있다 — 그 사이 잠겼으면 여기서
  // storage.session에 "session"을 다시 써서 잠금을 되살리면 안 된다(updateSession의 epoch 재검사와 같은 이유).
  if (epoch !== lockEpoch) throw new Error("Locked");
  await chrome.storage.session.set({ session: small });
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
  await chrome.storage.local.set({ vault: { ...vault, ciphers: session.ciphers, folders: session.folders, encRefreshToken } });
}

function userKeyToB64(userKey) {
  return { encKey: bytesToB64(userKey.encKey), macKey: bytesToB64(userKey.macKey) };
}

async function unlockWithUserKey(vault, userKey) {
  const keys = userKeyToB64(userKey);
  const refreshToken = vault.encRefreshToken ? await decryptEncString(vault.encRefreshToken, userKey) : null;
  lockEpoch += 1;
  // ciphers/folders는 여기서 storage.session에 쓰지 않는다 — getSession()이 storage.local(vault)에서
  // 바로 합쳐서 돌려준다. vault.ciphers는 이미 거기 있으니 다시 쓸 필요도 없다.
  await chrome.storage.session.set({
    session: {
      serverUrl: vault.serverUrl,
      email: vault.email,
      accessToken: null,
      refreshToken,
      tokenObtainedAt: 0, // 다음 서버 호출 때 refresh token으로 새 access token을 받는다
      expiresIn: 0,
      userKey: keys,
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

// PIN은 storage.local(디스크)에 둔다 — 1Password/Bitwarden처럼 브라우저를 껐다 켜도 그대로 남아야
// "간편 비밀번호"로서 의미가 있다. 마스터 비밀번호와 같은 강도의 KDF(60만 회)로 감싸서 저장하므로
// (vault.protectedKey와 동일한 모델) 디스크에 있어도 오프라인 대입이 비현실적으로 느리다.
async function setPin(pin) {
  if (!/^\d{4,8}$/.test(pin)) throw new Error("PIN은 숫자 4~8자리여야 합니다.");
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const wrapped = await encryptString(JSON.stringify(session.userKey), await pinKey(pin, session.email));
  await chrome.storage.local.set({ pin: { email: session.email, wrapped, failures: 0 } });
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
  const { pin: record } = await chrome.storage.local.get(["pin"]);
  const vault = await getVault();
  if (!record || !vault || record.email !== vault.email) throw new Error("PIN이 설정되어 있지 않습니다.");
  let keys;
  try {
    keys = JSON.parse(await decryptEncString(record.wrapped, await pinKey(pin, record.email)));
  } catch {
    const { pin: current } = await chrome.storage.local.get(["pin"]);
    if (current?.wrapped !== record.wrapped) throw new Error("PIN이 설정되어 있지 않습니다."); // KDF 중 해제·변경됨
    const failures = record.failures + 1;
    if (failures >= MAX_PIN_ATTEMPTS) {
      await chrome.storage.local.remove(["pin"]);
      return { ok: false, pinDisabled: true, error: `PIN을 ${MAX_PIN_ATTEMPTS}번 틀려 해제했습니다. 마스터 비밀번호로 여세요.` };
    }
    await chrome.storage.local.set({ pin: { ...record, failures } });
    return { ok: false, error: `PIN이 올바르지 않습니다. (${MAX_PIN_ATTEMPTS - failures}번 남음)` };
  }
  await chrome.storage.local.set({ pin: { ...record, failures: 0 } });
  await unlockWithUserKey(vault, {
    encKey: Uint8Array.from(atob(keys.encKey), (c) => c.charCodeAt(0)),
    macKey: Uint8Array.from(atob(keys.macKey), (c) => c.charCodeAt(0)),
  });
  return { ok: true };
}

async function logout() {
  await clearSession();
  await chrome.storage.local.remove(["pin", "vault", "lastUsed"]);
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
  await setSession(session, epoch);
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
  const folders = syncData.folders ?? syncData.Folders ?? [];

  await chrome.storage.local.set({
    vault: { serverUrl, email, kdfIterations, protectedKey: loginData.Key, ciphers: [], folders: [], encRefreshToken: null },
  });
  // 다른 계정으로 로그인했으면 이전 계정 기준의 PIN은 무효다.
  const { pin } = await chrome.storage.local.get(["pin"]);
  if (pin && pin.email !== email) await chrome.storage.local.remove(["pin"]);
  const session = {
    serverUrl,
    email,
    accessToken: loginData.access_token,
    refreshToken: loginData.refresh_token,
    tokenObtainedAt: Date.now(),
    expiresIn: loginData.expires_in,
    userKey: userKeyToB64(userKey),
    ciphers,
    folders,
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
  let data;
  try {
    data = await client.refreshToken(session.refreshToken);
  } catch (err) {
    // Vaultwarden refresh tokens are single-use (rotate on every refresh); a 400/401 means this one
    // is permanently dead (e.g. a previous refresh's rotated token never got persisted), not just
    // offline. Left alone, accessToken stays null forever and every server call keeps failing the
    // same way while the cached vault still renders — looks "logged in" but nothing can save/sync.
    // Force a clean logout so the next popup open shows the real login screen instead of that limbo.
    if (err.status === 400 || err.status === 401) {
      await logout();
      throw new Error("세션이 만료되었습니다. 다시 로그인해 주세요.");
    }
    throw err;
  }
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
  const folders = syncData.folders ?? syncData.Folders ?? [];
  await updateSession({ ...session, ciphers, folders }, epoch);
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
          uris.push({ uri: await decryptEncString(encUri, userKey), match: cipherField(uriObj, "match", "Match") ?? null });
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
    // 페더레이션 로그인("Google로 로그인함") 항목은 비밀번호가 없다 — 이미 저장된 일반 비밀번호
    // 항목과 구분하는 유일한 단서라 여기서 표시해 둔다(saveFederatedLogin 참고).
    hasPassword: !!cipherField(login || {}, "password", "Password"),
    // 서버가 주는 그대로(암호화 안 된 필드) — 언제 만들었고/고쳤는지는 중복 정리처럼
    // "둘 중 뭘 남길지" 판단할 때 마지막 자동입력 기록이 없어도 쓸 수 있는 단서가 된다.
    revisionDate: cipherField(cipher, "revisionDate", "RevisionDate") ?? null,
  };
}

async function getFolderList() {
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const userKey = userKeyFromSession(session);
  const folders = [];
  for (const f of session.folders || []) {
    try {
      folders.push({ id: cipherField(f, "id", "Id"), name: await decryptEncString(cipherField(f, "name", "Name"), userKey) });
    } catch {
      /* undecryptable folder name — skip it rather than fail the whole list */
    }
  }
  return folders;
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
  const notesEnc = cipherField(cipher, "notes", "Notes");
  const password = passwordEnc ? await decryptEncString(passwordEnc, userKey) : null;
  const notes = notesEnc ? await decryptEncString(notesEnc, userKey).catch(() => null) : null;
  if (!totpEnc) return { password, notes, totp: null };
  // A corrupt TOTP seed must not take the password down with it.
  try {
    const seed = await decryptEncString(totpEnc, userKey);
    return { password, notes, totp: await generateTotp(seed) };
  } catch (err) {
    console.warn("TOTP generation failed:", err.message);
    return { password, notes, totp: null, totpError: err.message };
  }
}

// 세부정보 수정 화면(팝업)에서 이름/아이디/비밀번호/URL들/메모를 통째로 교체한다.
// URI는 문자열 그대로 넘어오고, 기존에 저장돼 있던 match 값은 같은 URI 문자열이면 그대로 유지한다.
async function updateItem(id, { name, username, password, notes, uris, removeTotp }) {
  const epoch = lockEpoch;
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const cipher = session.ciphers.find((c) => cipherField(c, "id", "Id") === id);
  if (!cipher) throw new Error("항목을 찾을 수 없습니다.");
  const userKey = userKeyFromSession(session);
  const summary = await decryptCipherSummary(cipher, userKey);
  const matchByUri = new Map(summary.uris.map((u) => [u.uri, u.match]));
  const login = cipherField(cipher, "login", "Login");
  const payload = {
    type: 1,
    name: await encryptString(name, userKey),
    notes: notes ? await encryptString(notes, userKey) : null,
    favorite: cipherField(cipher, "favorite", "Favorite") ?? false,
    folderId: cipherField(cipher, "folderId", "FolderId") ?? null,
    organizationId: cipherField(cipher, "organizationId", "OrganizationId") ?? null,
    login: {
      username: username ? await encryptString(username, userKey) : null,
      password: await encryptString(password, userKey),
      totp: removeTotp ? null : cipherField(login, "totp", "Totp") ?? null,
      uris: await Promise.all(
        uris.map(async (uri) => ({ uri: await encryptString(uri, userKey), match: matchByUri.get(uri) ?? null }))
      ),
    },
  };
  const client = new VaultwardenClient(session.serverUrl);
  const updated = await client.updateCipher(session.accessToken, id, payload);
  const current = await getSession();
  if (!current) throw new Error("Locked");
  await updateSession(
    { ...current, ciphers: current.ciphers.map((c) => (cipherField(c, "id", "Id") === id ? updated : c)) },
    epoch
  );
}

// ---- 페이지 통합: 계정 자동 제안 + 새 로그인 저장 제안 ----------------------
// 콘텐츠 스크립트(임의의 웹페이지)가 보내는 메시지는 host를 절대 그대로 믿지 않는다.
// 항상 sender.url(메시지를 보낸 프레임의 URL, 브라우저가 채움)에서 우리가 직접 다시 계산한다.
// all_frames라 iframe도 보낼 수 있으므로 탭 URL이 아니라 프레임 URL 기준이어야 한다.

// 같은 사용자 이름이 이미 저장돼 있으면 다시 묻지 않는다.
// ponytail: 비밀번호가 바뀐 경우의 "업데이트" 제안은 범위 밖 — 필요해지면 추가.
async function maybeQueuePendingSave(tabId, host, url, username, password) {
  const session = await getSession();
  if (!session) return; // 잠겨 있으면 비교/저장 둘 다 불가능하니 조용히 무시
  const { items } = await getItemList();
  const alreadySaved = items.some(
    (item) => item.username === username && item.uris.some((u) => uriMatches(u.uri, u.match, url))
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

// "Google로 로그인" 같은 페더레이션 로그인은 이 사이트만 봐서는 비밀번호가 아예 없다 — 1Password처럼
// "Google이(가) 여기 로그인에 사용됨"이라는 연결 기록만 저장한다.
//
// document.referrer로 감지하는 방식은 실전에서 안 됐다 — SSO 리다이렉트 체인은 자기 사이트가 먼저 만든
// 중간 URL을 거치는 경우가 많고(예: github.com/orgs/x/sso → 서버가 302로 구글에 보냄), 그 중간 홉의
// Referrer-Policy가 origin을 지워버리면 도착한 페이지에서 "어디서 왔는지"를 알 방법이 없다.
// 대신 background가 chrome.tabs.onUpdated로 그 탭이 실제로 어느 호스트에서 어느 호스트로 넘어갔는지
// 직접 추적한다 — 페이지의 JS나 헤더에 좌우되지 않는다. host_permissions가 이미 모든 사이트를 덮고
// 있어서 별도 tabs 권한 없이도 tab.url이 보인다.
const PENDING_FEDERATED_TTL_MS = 5 * 60 * 1000;
const KNOWN_FEDERATED_PROVIDERS = new Set(["Google", "Microsoft", "Apple", "Okta"]);
const FEDERATED_PROVIDER_HOSTS = [
  { name: "Google", hostRe: /(^|\.)accounts\.google\.com$/ },
  { name: "Microsoft", hostRe: /(^|\.)login\.microsoftonline\.com$/ },
  { name: "Apple", hostRe: /(^|\.)appleid\.apple\.com$/ },
  { name: "Okta", hostRe: /\.okta\.com$/ },
];

async function setPendingFederated(tabId, provider, originHost) {
  await chrome.storage.session.set({
    [`pendingFederated:${tabId}`]: { provider, originHost, createdAt: Date.now() },
  });
}

// 탭이 새 URL로 넘어갈 때마다 직전 호스트를 기억해 뒀다가, 방금 도착한 호스트가 알려진 인증 전용
// 도메인이면 "직전 호스트가 여기로 로그인을 위임했다"고 기록한다. 그 인증 도메인 안에서의 이동(같은
// 호스트끼리)은 무시한다.
async function trackFederatedNavigation(tabId, url) {
  const newHost = uriHostname(url);
  if (!newHost) return;
  const key = `lastTabHost:${tabId}`;
  const { [key]: prevHost } = await chrome.storage.session.get([key]);
  await chrome.storage.session.set({ [key]: newHost });
  if (!prevHost || prevHost === newHost) return;
  console.debug(`[federated] tab ${tabId}: 탭 이동 감지 ${prevHost} -> ${newHost}`); // 임시: 실제 이동 경로 확인용
  const provider = FEDERATED_PROVIDER_HOSTS.find((p) => p.hostRe.test(newHost));
  if (provider) {
    console.debug(`[federated] tab ${tabId}: ${prevHost} -> ${newHost} (${provider.name}) — pending 기록`);
    await setPendingFederated(tabId, provider.name, prevHost);
  }
}

// 사이트가 SSO를 팝업/새 탭으로 열 때(window.open 등)는 원래 탭의 URL이 안 바뀌므로
// trackFederatedNavigation(같은 탭 안 이동만 봄)으로는 못 잡는다. chrome.webNavigation의
// onCreatedNavigationTarget이 "어느 탭이 새 탭을 열었는지"(sourceTabId)를 알려주므로, 새 탭이 아니라
// 그 원본 탭 기준으로 기록을 남긴다 — 팝업이 로그인 후 스스로 닫혀도 원본 탭이 그 기록을 보게 된다.
async function trackFederatedPopup(sourceTabId, url) {
  const newHost = uriHostname(url);
  if (!newHost) return;
  const provider = FEDERATED_PROVIDER_HOSTS.find((p) => p.hostRe.test(newHost));
  if (!provider) return;
  const key = `lastTabHost:${sourceTabId}`;
  const { [key]: sourceHost } = await chrome.storage.session.get([key]);
  if (!sourceHost) return; // 원본 탭 호스트를 아직 모르면(추적 시작 전 탭) 포기
  console.debug(`[federated] tab ${sourceTabId}: 팝업으로 ${newHost} 열림 (${provider.name}) — pending 기록(원본 탭 기준)`);
  await setPendingFederated(sourceTabId, provider.name, sourceHost);
}

async function takePendingFederated(tabId, frameUrl) {
  const key = `pendingFederated:${tabId}`;
  const { [key]: entry } = await chrome.storage.session.get([key]);
  if (!entry) {
    console.debug(`[federated] tab ${tabId}: pending 기록 없음 (frame=${uriHostname(frameUrl)})`);
    return null;
  }
  if (entry.originHost !== uriHostname(frameUrl)) {
    // 지우면 안 된다 — content.js는 <all_urls>라 지금 이 순간에도 accounts.google.com 자기 자신의
    // 페이지에서 돌고 있고, 거기서도 이걸 확인한다. 그때는 당연히 origin이 안 맞는다(아직 github.com으로
    // 안 돌아왔을 뿐). 여기서 지워버리면 나중에 진짜 github.com으로 돌아왔을 때 볼 기록이 없어진다.
    console.debug(`[federated] tab ${tabId}: origin 불일치 (기록=${entry.originHost}, 지금=${uriHostname(frameUrl)}) — 아직 때가 아님, 보존`);
    return null;
  }
  if (Date.now() - entry.createdAt > PENDING_FEDERATED_TTL_MS) {
    await chrome.storage.session.remove([key]);
    console.debug(`[federated] tab ${tabId}: TTL 만료 — 버림`);
    return null;
  }
  const session = await getSession();
  if (!session) {
    // 잠겨 있으면 여기서 지우지 않는다 — 구글 계정 선택/OTP를 거치는 동안 자동 잠금이 걸리면
    // (기본 15분) 그 순간 지워버려서 잠금 해제 후에도 다시는 못 보게 되는 게 더 나쁘다.
    // TTL 안에서 다음 페이지 로드 때 다시 시도할 수 있게 그대로 둔다.
    console.debug(`[federated] tab ${tabId}: 잠겨 있어 판단 보류(안 지움) — 잠금 해제 후 재시도`);
    return null;
  }
  await chrome.storage.session.remove([key]); // 이제 보여줄지 결정할 수 있으니, 한 번 보여주면 끝
  const { items } = await getItemList();
  // 일반 비밀번호 항목(예: 기존 GitHub 아이디/비번)은 여기서 걸러지면 안 된다 — 이미 저장된
  // "페더레이션 로그인" 표식 항목(saveFederatedLogin이 만드는, 비밀번호 없는 항목)만 중복으로 본다.
  const alreadySaved = items.some((item) => !item.hasPassword && item.uris.some((u) => uriMatches(u.uri, u.match, frameUrl)));
  if (alreadySaved) {
    console.debug(`[federated] tab ${tabId}: 비밀번호 없는 항목이 이미 있어 배너 생략 (${entry.provider})`);
    return null;
  }
  console.debug(`[federated] tab ${tabId}: 배너 표시 (${entry.provider})`);
  return { provider: entry.provider };
}

async function saveFederatedLogin(host, provider) {
  const epoch = lockEpoch;
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const userKey = userKeyFromSession(session);
  const client = new VaultwardenClient(session.serverUrl);
  const payload = {
    type: 1,
    name: await encryptString(host, userKey),
    notes: await encryptString(`${provider} 계정으로 로그인함`, userKey),
    favorite: false,
    folderId: null,
    organizationId: null,
    login: {
      // username 자리에 provider 이름을 넣어둔다 — GET_HOST_MATCHES 요약에 그대로 노출되니(추가 복호화
      // 없이), 계정 선택 목록에서 "이 항목은 Google로 로그인한다"를 바로 보여주고, 클릭했을 때 페이지의
      // 어느 "Continue with ___" 버튼을 눌러야 할지도 이걸로 찾는다.
      username: await encryptString(provider, userKey),
      password: null,
      totp: null,
      uris: [{ uri: await encryptString(`https://${host}`, userKey), match: null }],
    },
  };
  const created = await client.createCipher(session.accessToken, payload);
  const current = await getSession();
  if (!current) throw new Error("Locked");
  await updateSession({ ...current, ciphers: [...current.ciphers, created] }, epoch);
}

// 이메일 → 비밀번호[ → OTP] 같은 다단계 로그인은 구글처럼 단계마다 완전히 새 페이지로 넘어가는 경우가 많다.
// content.js의 메모리 상태(pendingFillId)는 새 페이지가 뜨면 날아가므로, 여기 탭별로 하나 더 들고 있다가
// 다음 페이지가 뜨면 content.js가 복원해서 이어 채운다 — 안 그러면 다음 단계에서 계정 선택창이 또 뜬다.
const PENDING_FILL_TTL_MS = 5 * 60 * 1000;

async function setPendingFill(tabId, id, step) {
  await chrome.storage.session.set({ [`pendingFill:${tabId}`]: { id, step, createdAt: Date.now() } });
}

async function getPendingFill(tabId) {
  const key = `pendingFill:${tabId}`;
  const { [key]: entry } = await chrome.storage.session.get([key]);
  if (!entry) return null;
  if (Date.now() - entry.createdAt > PENDING_FILL_TTL_MS) {
    await chrome.storage.session.remove([key]);
    return null;
  }
  return { id: entry.id, step: entry.step };
}

async function clearPendingFill(tabId) {
  await chrome.storage.session.remove([`pendingFill:${tabId}`]);
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

async function deleteItem(id) {
  const epoch = lockEpoch;
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const cipher = session.ciphers.find((c) => cipherField(c, "id", "Id") === id);
  if (!cipher) throw new Error("항목을 찾을 수 없습니다.");
  const client = new VaultwardenClient(session.serverUrl);
  await client.deleteCipher(session.accessToken, id);
  const current = await getSession();
  if (!current) throw new Error("Locked");
  await updateSession({ ...current, ciphers: current.ciphers.filter((c) => cipherField(c, "id", "Id") !== id) }, epoch);
}

const MAX_IMPORT_ENTRIES = 2000;
const MAX_FOLDER_NAME_LENGTH = 100;

// Chrome/Arc/Edge/Brave나 1Password에서 내보낸 CSV를 통째로 가져온다. 이미 같은 아이디+사이트로
// 저장된 항목은 조용히 건너뛴다(중복 정리) — 1Password류의 "그냥 가져오기"에 맞춰 미리보기는 없다.
// folderSelection.newFolderName이 있으면 새 폴더를 만들어 거기 넣고, 없으면 folderId(빈 값이면 폴더 없음)를 쓴다.
async function importItems(entries, folderSelection = {}) {
  const epoch = lockEpoch;
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const userKey = userKeyFromSession(session);
  const client = new VaultwardenClient(session.serverUrl);

  let folderId = folderSelection.folderId || null;
  let newFolder = null;
  const newFolderName = String(folderSelection.newFolderName || "").trim().slice(0, MAX_FOLDER_NAME_LENGTH);
  if (newFolderName) {
    newFolder = await client.createFolder(session.accessToken, await encryptString(newFolderName, userKey));
    folderId = cipherField(newFolder, "id", "Id");
  }

  const { items: existing } = await getItemList();
  const alreadySaved = (username, url) =>
    existing.some((item) => item.username === username && item.uris.some((u) => uriMatches(u.uri, u.match, url)));

  const created = [];
  let skipped = 0;
  let failed = 0;
  for (const entry of entries) {
    const host = uriHostname(entry.url);
    if (!host) {
      failed += 1;
      continue;
    }
    if (alreadySaved(entry.username || null, entry.url)) {
      skipped += 1;
      continue;
    }
    try {
      const payload = {
        type: 1,
        name: await encryptString(entry.name || host, userKey),
        notes: entry.notes ? await encryptString(entry.notes, userKey) : null,
        favorite: false,
        folderId,
        organizationId: null,
        login: {
          username: entry.username ? await encryptString(entry.username, userKey) : null,
          password: await encryptString(entry.password, userKey),
          totp: entry.otpauth ? await encryptString(entry.otpauth, userKey) : null,
          uris: [{ uri: await encryptString(entry.url, userKey), match: null }],
        },
      };
      created.push(await client.createCipher(session.accessToken, payload));
    } catch {
      failed += 1;
    }
  }
  if (created.length || newFolder) {
    const current = await getSession();
    if (!current) throw new Error("Locked");
    await updateSession(
      {
        ...current,
        ciphers: [...current.ciphers, ...created],
        folders: newFolder ? [...(current.folders || []), newFolder] : current.folders,
      },
      epoch
    );
  }
  return { imported: created.length, skipped, failed, folderId };
}

// 현재 탭 사이트와 일치하는 저장된 계정 목록(이름/사용자명만, 비밀번호 없음).
// locked를 같이 돌려준다 — 잠겨서 items가 빈 것과, 정말 매칭이 없는 것을 content.js가 구분해야
// 필드 아이콘을 "잠금 해제하기"로 보여줄지 그냥 숨길지 정할 수 있다.
async function getHostMatches(tabUrl) {
  const host = uriHostname(tabUrl);
  if (!host) return { items: [], locked: !(await getSession()) };
  if (!(await getSession())) return { items: [], locked: true };
  const { items } = await getItemList();
  const { lastUsed = {} } = await chrome.storage.local.get(["lastUsed"]);
  const matched = items
    .filter((item) => item.uris.some((u) => uriMatches(u.uri, u.match, tabUrl)))
    .map(({ id, name, username, hasTotp, hasPassword }) => ({ id, name, username, hasTotp, hasPassword, lastUsedAt: lastUsed[id] || null }))
    .sort((a, b) => (b.lastUsedAt || 0) - (a.lastUsedAt || 0));
  return { items: matched, locked: false };
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
  if (!summary || !summary.uris.some((u) => uriMatches(u.uri, u.match, frameUrl))) {
    return { ok: false, error: "사이트가 일치하지 않습니다." };
  }
  const { password, totp } = await getItemSecrets(id);
  // documentId로 보내야 검증 후 프레임이 다른 페이지로 이동했을 때 새 문서가 비밀번호를 받지 않는다.
  // content.js도 host를 한 번 더 확인한다. totp는 이 시점의 코드일 뿐이라 OTP 칸이 없는 페이지면 그냥 버려진다.
  await chrome.tabs.sendMessage(
    tab.id,
    { type: "DO_AUTOFILL", host, username: summary.username, password, totp: totp?.code ?? null, submit },
    { documentId }
  );
  await markUsed(id);
  return { ok: true, hasTotp: summary.hasTotp };
}

// otpauth://totp/...?secret=... 형태나, 사이트가 "직접 입력" 텍스트로 보여주는 순수 base32 시크릿
// 둘 다 받는다(HOTP는 카운터 기반이라 generateTotp가 처리 못 해 otpauth:// 쪽은 totp만 허용).
const BASE32_SECRET_RE = /^[A-Z2-7]{16,32}$/;
function isValidTotpSecret(value) {
  if (typeof value !== "string" || value.length > 2000) return false;
  if (BASE32_SECRET_RE.test(value)) return true;
  try {
    const url = new URL(value);
    return url.protocol === "otpauth:" && url.host.toLowerCase() === "totp" && !!url.searchParams.get("secret");
  } catch {
    return false;
  }
}

// 2FA 설정 페이지가 보여준 시크릿을, 이 사이트에 이미 저장된(그리고 아직 TOTP가 없는) 계정에 붙인다.
// TOTP 없는 계정이 후보 하나뿐이면 itemId 없이도 그 계정으로 정해지고, 둘 이상이면 content.js가
// 고른 itemId가 필요하다(없으면 어느 것인지 알 수 없어 거부).
async function saveTotpForHost(url, secret, itemId) {
  const epoch = lockEpoch;
  const session = await getSession();
  if (!session) throw new Error("Locked");
  const { items } = await getItemList();
  const matches = items.filter((item) => !item.hasTotp && item.uris.some((u) => uriMatches(u.uri, u.match, url)));
  let target;
  if (itemId) {
    target = matches.find((item) => item.id === itemId);
    if (!target) throw new Error("선택한 계정을 찾을 수 없습니다.");
  } else if (matches.length === 0) {
    throw new Error("이 사이트에 저장된 계정이 없습니다.");
  } else if (matches.length > 1) {
    throw new Error("저장할 계정을 하나로 특정할 수 없습니다.");
  } else {
    target = matches[0];
  }
  const cipher = session.ciphers.find((c) => cipherField(c, "id", "Id") === target.id);
  if (!cipher) throw new Error("항목을 찾을 수 없습니다.");
  const userKey = userKeyFromSession(session);
  const login = cipherField(cipher, "login", "Login");
  const payload = {
    type: 1,
    name: cipherField(cipher, "name", "Name"),
    notes: cipherField(cipher, "notes", "Notes") ?? null,
    favorite: cipherField(cipher, "favorite", "Favorite") ?? false,
    folderId: cipherField(cipher, "folderId", "FolderId") ?? null,
    organizationId: cipherField(cipher, "organizationId", "OrganizationId") ?? null,
    login: {
      username: cipherField(login, "username", "Username") ?? null,
      password: cipherField(login, "password", "Password") ?? null,
      totp: await encryptString(secret, userKey),
      uris: cipherField(login, "uris", "Uris") ?? [],
    },
  };
  const client = new VaultwardenClient(session.serverUrl);
  const updated = await client.updateCipher(session.accessToken, target.id, payload);
  const current = await getSession();
  if (!current) throw new Error("Locked");
  await updateSession(
    { ...current, ciphers: current.ciphers.map((c) => (cipherField(c, "id", "Id") === target.id ? updated : c)) },
    epoch
  );
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

// chrome.tabs.onUpdated 대신 chrome.webNavigation.onCommitted를 쓴다 — "탭 URL이 바뀜"이 아니라 "네비게이션이
// 실제로 커밋됨"이라는 더 명확한 공식 신호다(1Password도 이 API를 쓴다). onCreatedNavigationTarget은
// tabs.onUpdated로는 원천적으로 못 보는 경우(SSO를 팝업/새 탭으로 여는 사이트)까지 잡아준다.
chrome.webNavigation.onCommitted.addListener((details) => {
  if (details.frameId !== 0) return; // 최상위 프레임만 — iframe 안 이동은 무시
  trackFederatedNavigation(details.tabId, details.url).catch((err) => console.warn("federated nav tracking failed:", err.message));
});
chrome.webNavigation.onCreatedNavigationTarget.addListener((details) => {
  trackFederatedPopup(details.sourceTabId, details.url).catch((err) => console.warn("federated popup tracking failed:", err.message));
});
chrome.tabs.onRemoved.addListener((tabId) => {
  chrome.storage.session
    .remove([`lastTabHost:${tabId}`, `pendingFederated:${tabId}`])
    .catch(() => {});
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
  "GET_STATUS",
  "UNLOCK",
  "UNLOCK_PIN",
  "GET_HOST_MATCHES",
  "REQUEST_AUTOFILL",
  "PENDING_SAVE",
  "GET_PENDING_SAVE",
  "SAVE_ITEM",
  "SAVE_TOTP",
  "SET_PENDING_FILL",
  "GET_PENDING_FILL",
  "CLEAR_PENDING_FILL",
  "GET_PENDING_FEDERATED",
  "SAVE_FEDERATED_LOGIN",
]);

const USER_ACTION_MESSAGE_TYPES = new Set(["REQUEST_AUTOFILL", "SAVE_ITEM", "SAVE_TOTP", "SAVE_FEDERATED_LOGIN", "UNLOCK", "UNLOCK_PIN"]);

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
          const { pin } = await chrome.storage.local.get(["pin"]);
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
          await chrome.storage.local.remove(["pin"]);
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
          const { lastUsed = {} } = await chrome.storage.local.get(["lastUsed"]);
          sendResponse({ ok: true, items: items.map((i) => ({ ...i, lastUsedAt: lastUsed[i.id] || null })), skipped });
          break;
        }
        case "GET_FOLDERS": {
          sendResponse({ ok: true, folders: await getFolderList() });
          break;
        }
        case "GET_ITEM_SECRETS": {
          const secrets = await getItemSecrets(msg.id);
          sendResponse({ ok: true, ...secrets });
          break;
        }
        case "GET_HOST_MATCHES": {
          const { items, locked } = await getHostMatches(frameUrl);
          sendResponse({ ok: true, items, locked });
          break;
        }
        case "REQUEST_AUTOFILL": {
          sendResponse(await requestAutofill(msg.id, sender.tab, frameUrl, sender.documentId, !!msg.submit));
          break;
        }
        case "PENDING_SAVE": {
          const host = uriHostname(frameUrl);
          if (host && isCapturedFieldValid(msg.password, { required: true }) && isCapturedFieldValid(msg.username, { required: false })) {
            await maybeQueuePendingSave(sender.tab.id, host, frameUrl, msg.username || null, msg.password);
          }
          sendResponse({ ok: true });
          break;
        }
        case "GET_PENDING_SAVE": {
          const pending = await takePendingSave(sender.tab.id, frameUrl);
          sendResponse({ ok: true, pending });
          break;
        }
        case "SET_PENDING_FILL": {
          if (typeof msg.id === "string" && msg.id.length > 0 && msg.id.length <= 100 && (msg.step === "password" || msg.step === "otp")) {
            await setPendingFill(sender.tab.id, msg.id, msg.step);
          }
          sendResponse({ ok: true });
          break;
        }
        case "GET_PENDING_FILL": {
          sendResponse({ ok: true, pending: await getPendingFill(sender.tab.id) });
          break;
        }
        case "CLEAR_PENDING_FILL": {
          await clearPendingFill(sender.tab.id);
          sendResponse({ ok: true });
          break;
        }
        case "GET_PENDING_FEDERATED": {
          sendResponse({ ok: true, pending: await takePendingFederated(sender.tab.id, frameUrl) });
          break;
        }
        case "SAVE_FEDERATED_LOGIN": {
          if (uriHostname(frameUrl) !== msg.host || !KNOWN_FEDERATED_PROVIDERS.has(msg.provider)) {
            sendResponse({ ok: false, error: "잘못된 요청입니다." });
            break;
          }
          await saveFederatedLogin(msg.host, msg.provider);
          sendResponse({ ok: true });
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
        case "UPDATE_ITEM": {
          if (typeof msg.id !== "string" || !msg.id) {
            sendResponse({ ok: false, error: "잘못된 요청입니다." });
            break;
          }
          if (!isCapturedFieldValid(msg.name, { required: true }) || !isCapturedFieldValid(msg.password, { required: true })) {
            sendResponse({ ok: false, error: "이름과 비밀번호는 필수입니다." });
            break;
          }
          const uris = Array.isArray(msg.uris) ? msg.uris.filter((u) => isCapturedFieldValid(u, { required: true })) : [];
          await updateItem(msg.id, {
            name: msg.name,
            username: isCapturedFieldValid(msg.username, { required: false }) ? msg.username : null,
            password: msg.password,
            notes: isCapturedFieldValid(msg.notes, { required: false }) ? msg.notes : null,
            uris,
            removeTotp: !!msg.removeTotp,
          });
          sendResponse({ ok: true });
          break;
        }
        case "DELETE_ITEM": {
          if (typeof msg.id !== "string" || !msg.id) {
            sendResponse({ ok: false, error: "잘못된 요청입니다." });
            break;
          }
          await deleteItem(msg.id);
          sendResponse({ ok: true });
          break;
        }
        case "IMPORT_ITEMS": {
          if (!Array.isArray(msg.entries) || msg.entries.length === 0 || msg.entries.length > MAX_IMPORT_ENTRIES) {
            sendResponse({ ok: false, error: "가져올 항목이 없습니다." });
            break;
          }
          sendResponse({ ok: true, ...(await importItems(msg.entries, { folderId: msg.folderId, newFolderName: msg.newFolderName })) });
          break;
        }
        case "SAVE_TOTP": {
          if (uriHostname(frameUrl) !== msg.host || !isValidTotpSecret(msg.secret)) {
            sendResponse({ ok: false, error: "잘못된 요청입니다." });
            break;
          }
          await saveTotpForHost(frameUrl, msg.secret, typeof msg.itemId === "string" ? msg.itemId : undefined);
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

// Regression tests for src/background.js driven through mocked chrome.* and fetch.
// No network, no real secrets: all keys are random and generated per run.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { encryptString, decryptEncString, bytesToB64, deriveMasterKey, stretchKey } from "../src/lib/crypto.js";

// ---- chrome / fetch mocks (installed before background.js is imported) ----
const store = { local: {}, session: {} };
const alarms = {};
const EXT_ID = "testextensionid";
let storageDelayMs = 0; // >0 simulates slow chrome.storage: each call applies after the delay
const storageLatency = () => (storageDelayMs ? new Promise((r) => setTimeout(r, storageDelayMs)) : undefined);
let messageListener;
let alarmListener;
let fetchImpl = async () => {
  throw new Error("unexpected fetch");
};

const storageArea = (backing) => ({
  async get(keys) {
    await storageLatency();
    const out = {};
    for (const k of [].concat(keys)) if (k in backing) out[k] = structuredClone(backing[k]);
    return out;
  },
  async set(values) {
    await storageLatency();
    Object.assign(backing, structuredClone(values));
  },
  async remove(keys) {
    await storageLatency();
    for (const k of [].concat(keys)) delete backing[k];
  },
});

const tabMessages = []; // {tabId, msg} sent via chrome.tabs.sendMessage (DO_AUTOFILL relay)

globalThis.chrome = {
  storage: { local: storageArea(store.local), session: storageArea(store.session) },
  alarms: {
    async create(name, info) {
      alarms[name] = info;
    },
    async clear(name) {
      delete alarms[name];
    },
    onAlarm: { addListener: (fn) => (alarmListener = fn) },
  },
  tabs: {
    async sendMessage(tabId, msg, options) {
      tabMessages.push({ tabId, msg, documentId: options?.documentId });
      return { ok: true };
    },
  },
  runtime: {
    id: EXT_ID,
    getURL: (path) => `chrome-extension://${EXT_ID}/${path}`,
    onMessage: { addListener: (fn) => (messageListener = fn) },
  },
};
globalThis.fetch = (url, opts) => fetchImpl(url, opts);

await import("../src/background.js");

// ---- helpers ----
const sleep = (ms) => new Promise((r) => setTimeout(r, ms));
const send = (msg, sender = { id: EXT_ID }) => new Promise((resolve) => messageListener(msg, sender, resolve));
const jsonResponse = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
const randomKeys = () => ({
  encKey: crypto.getRandomValues(new Uint8Array(32)),
  macKey: crypto.getRandomValues(new Uint8Array(32)),
});
const keysToB64 = (k) => ({ encKey: bytesToB64(k.encKey), macKey: bytesToB64(k.macKey) });

const userKey = randomKeys();
const foreignKey = randomKeys();

async function makeCipher(id, name, key, extra = {}) {
  return {
    id,
    type: 1,
    name: await encryptString(name, key),
    login: {
      username: await encryptString(`user-${name}`, key),
      password: await encryptString("pw", key),
      uris: [{ uri: await encryptString("https://example.test", key) }],
    },
    ...extra,
  };
}

function seedSession(ciphers) {
  store.session.session = {
    serverUrl: "https://vault.test",
    email: "user@example.test",
    accessToken: "access",
    refreshToken: "refresh",
    tokenObtainedAt: Date.now(),
    expiresIn: 7200,
    userKey: keysToB64(userKey),
    ciphers,
  };
}

beforeEach(() => {
  storageDelayMs = 0;
  for (const area of [store.local, store.session, alarms]) {
    for (const k of Object.keys(area)) delete area[k];
  }
  tabMessages.length = 0;
  fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
});

const contentScriptSender = (tabId, url, frame = { frameId: 0, documentId: "doc-top", url }) => ({ id: EXT_ID, tab: { id: tabId, url }, ...frame });

// ---- tests ----
test("LOCK during an in-flight SYNC does not resurrect the session", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);
  fetchImpl = async () => {
    await sleep(100);
    return jsonResponse({ ciphers: [] });
  };

  const inFlightSync = send({ type: "SYNC" });
  await sleep(20);
  assert.deepEqual(await send({ type: "LOCK" }), { ok: true });
  const syncResult = await inFlightSync;

  assert.equal(store.session.session, undefined);
  assert.equal((await send({ type: "GET_STATUS" })).locked, true);
  assert.equal(syncResult.ok, false);
});

test("GET_ITEMS returns the decryptable item and counts the undecryptable one, skipping trash", async () => {
  seedSession([
    await makeCipher("good", "good", userKey),
    await makeCipher("foreign", "foreign", foreignKey),
    await makeCipher("trashed", "trashed", userKey, { deletedDate: "2026-01-01T00:00:00Z" }),
  ]);

  const res = await send({ type: "GET_ITEMS" });

  assert.equal(res.ok, true);
  assert.deepEqual(res.items.map((i) => i.name), ["good"]);
  assert.equal(res.skipped, 1);
});

test("messages from a sender with a tab (content script) are forbidden", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  const res = await send({ type: "GET_ITEMS" }, { id: EXT_ID, tab: { id: 1 }, url: "https://evil.test/page" });

  assert.deepEqual(res, { ok: false, error: "forbidden" });
});

test("messages from the popup (no sender.tab) are handled", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  const res = await send({ type: "GET_ITEMS" }, { id: EXT_ID, url: `chrome-extension://${EXT_ID}/popup.html` });

  assert.equal(res.ok, true);
  assert.equal(res.items.length, 1);
});

test("handling a message with an active session schedules a 15 minute auto-lock alarm", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  await send({ type: "GET_STATUS" });
  await sleep(10); // alarm scheduling runs after sendResponse

  assert.equal(alarms["auto-lock"]?.delayInMinutes, 15);
});

test("auto-lock alarm firing clears the session", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  alarmListener({ name: "auto-lock" });
  await sleep(10);

  assert.equal(store.session.session, undefined);
});

test("an unrelated alarm does not clear the session", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  alarmListener({ name: "something-else" });
  await sleep(10);

  assert.ok(store.session.session);
});

test("popup.html opened in a tab (extension url) is allowed", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);
  const sender = { id: EXT_ID, tab: { id: 7 }, url: `chrome-extension://${EXT_ID}/popup.html` };

  const res = await send({ type: "GET_ITEMS" }, sender);

  assert.equal(res.ok, true);
});

test("a tab sender with a web page url is forbidden even with the extension id", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  const res = await send({ type: "GET_ITEMS" }, { id: EXT_ID, tab: { id: 7 }, url: "https://evil.example/" });

  assert.deepEqual(res, { ok: false, error: "forbidden" });
});

test("a sender from another extension is forbidden", async () => {
  seedSession([await makeCipher("1", "one", userKey)]);

  const res = await send({ type: "GET_ITEMS" }, { id: "otherextension", url: "chrome-extension://otherextension/x.html" });

  assert.deepEqual(res, { ok: false, error: "forbidden" });
});

test("LOCK landing at any point during a slow SYNC never resurrects the session", async () => {
  storageDelayMs = 40;
  fetchImpl = async () => jsonResponse({ ciphers: [] });

  for (let lockAt = 0; lockAt <= 200; lockAt += 10) {
    seedSession([await makeCipher("1", "one", userKey)]);
    const inFlightSync = send({ type: "SYNC" });
    await sleep(lockAt);
    await send({ type: "LOCK" });
    await inFlightSync;
    await sleep(2 * storageDelayMs); // let any straggling write land
    assert.equal(store.session.session, undefined, `session resurrected when LOCK sent at +${lockAt}ms`);
  }
});

test("auto-lock firing during a slow SYNC never resurrects the session", async () => {
  storageDelayMs = 40;
  fetchImpl = async () => jsonResponse({ ciphers: [] });

  for (let lockAt = 0; lockAt <= 200; lockAt += 20) {
    seedSession([await makeCipher("1", "one", userKey)]);
    const inFlightSync = send({ type: "SYNC" });
    await sleep(lockAt);
    alarmListener({ name: "auto-lock" });
    await inFlightSync;
    await sleep(3 * storageDelayMs);
    assert.equal(store.session.session, undefined, `session resurrected when auto-lock fired at +${lockAt}ms`);
  }
});

test("GET_ITEM_SECRETS still returns the password when the TOTP seed is corrupt", async () => {
  const cipher = await makeCipher("1", "one", userKey);
  cipher.login.totp = await encryptString("!!!", userKey);
  seedSession([cipher]);

  const res = await send({ type: "GET_ITEM_SECRETS", id: "1" });

  assert.equal(res.ok, true);
  assert.equal(res.password, "pw");
  assert.equal(res.totp, null);
  assert.equal(typeof res.totpError, "string");
});

test("GET_ITEM_SECRETS returns a TOTP code for a valid seed", async () => {
  const cipher = await makeCipher("1", "one", userKey);
  cipher.login.totp = await encryptString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", userKey);
  seedSession([cipher]);

  const res = await send({ type: "GET_ITEM_SECRETS", id: "1" });

  assert.equal(res.ok, true);
  assert.equal(res.password, "pw");
  assert.equal(res.totpError, undefined);
  assert.ok(res.totp);
});

// ---- content-script surface: host matches, autofill, save prompt ----------

test("a content script may send GET_HOST_MATCHES/REQUEST_AUTOFILL/PENDING_SAVE/GET_PENDING_SAVE/SAVE_ITEM, nothing else", async () => {
  seedSession([]);
  const sender = contentScriptSender(1, "https://evil.test/page");

  assert.notDeepEqual(await send({ type: "GET_HOST_MATCHES" }, sender), { ok: false, error: "forbidden" });
  assert.deepEqual(await send({ type: "SYNC" }, sender), { ok: false, error: "forbidden" });
  assert.deepEqual(await send({ type: "GET_ITEMS" }, sender), { ok: false, error: "forbidden" });
});

test("GET_HOST_MATCHES returns only items whose saved uri matches the tab's real host", async () => {
  seedSession([
    await makeCipher("1", "example", userKey), // uris: https://example.test
    await makeCipher("2", "other", userKey, {
      login: { username: await encryptString("u", userKey), password: await encryptString("p", userKey), uris: [{ uri: await encryptString("https://other.test", userKey) }] },
    }),
  ]);

  const res = await send({ type: "GET_HOST_MATCHES" }, contentScriptSender(1, "https://example.test/login"));

  assert.equal(res.ok, true);
  assert.deepEqual(res.items.map((i) => i.id), ["1"]);
  assert.equal(res.items[0].password, undefined); // 비밀번호는 절대 포함하지 않는다
});

test("GET_HOST_MATCHES ignores the host a malicious page claims and uses sender.tab.url instead", async () => {
  seedSession([await makeCipher("1", "example", userKey)]);

  const res = await send(
    { type: "GET_HOST_MATCHES", host: "example.test" }, // 위조 시도
    contentScriptSender(1, "https://attacker.test/page")
  );

  assert.deepEqual(res.items, []);
});

test("GET_HOST_MATCHES returns nothing while locked (no nagging for master password)", async () => {
  const res = await send({ type: "GET_HOST_MATCHES" }, contentScriptSender(1, "https://example.test/login"));
  assert.deepEqual(res, { ok: true, items: [] });
});

test("REQUEST_AUTOFILL decrypts and relays DO_AUTOFILL to the requesting tab only", async () => {
  seedSession([await makeCipher("1", "example", userKey)]);

  const res = await send({ type: "REQUEST_AUTOFILL", id: "1", submit: true }, contentScriptSender(9, "https://example.test/login"));

  assert.equal(res.ok, true);
  assert.equal(res.hasTotp, false);
  assert.equal(tabMessages.length, 1);
  assert.deepEqual(tabMessages[0], {
    tabId: 9,
    msg: { type: "DO_AUTOFILL", host: "example.test", username: "user-example", password: "pw", totp: null, submit: true },
    documentId: "doc-top",
  });
});

test("REQUEST_AUTOFILL includes the current TOTP code and reports hasTotp when the item has a seed", async () => {
  const cipher = await makeCipher("1", "example", userKey);
  cipher.login.totp = await encryptString("GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ", userKey);
  seedSession([cipher]);

  const res = await send({ type: "REQUEST_AUTOFILL", id: "1" }, contentScriptSender(9, "https://example.test/login"));

  assert.equal(res.ok, true);
  assert.equal(res.hasTotp, true);
  assert.match(tabMessages[0].msg.totp, /^\d{6}$/);
});

test("REQUEST_AUTOFILL from an iframe is checked against the frame's own url and sent only to that frame", async () => {
  seedSession([await makeCipher("1", "example", userKey)]);

  // 최상위 페이지는 일치하지만 요청한 iframe은 다른 출처 → 거부
  const bad = await send(
    { type: "REQUEST_AUTOFILL", id: "1" },
    contentScriptSender(9, "https://example.test/login", { frameId: 3, documentId: "doc-3", url: "https://attacker.test/frame" })
  );
  assert.equal(bad.ok, false);
  assert.equal(tabMessages.length, 0);

  const good = await send(
    { type: "REQUEST_AUTOFILL", id: "1" },
    contentScriptSender(9, "https://portal.test/", { frameId: 4, documentId: "doc-4", url: "https://example.test/embed-login" })
  );
  assert.equal(good.ok, true);
  assert.equal(tabMessages[0].documentId, "doc-4");
});

test("REQUEST_AUTOFILL refuses an item whose saved site does not match the current tab", async () => {
  seedSession([await makeCipher("1", "example", userKey)]); // uris: https://example.test

  const res = await send({ type: "REQUEST_AUTOFILL", id: "1" }, contentScriptSender(9, "https://attacker.test/login"));

  assert.equal(res.ok, false);
  assert.equal(tabMessages.length, 0);
});

test("REQUEST_AUTOFILL fails while locked instead of throwing", async () => {
  const res = await send({ type: "REQUEST_AUTOFILL", id: "1" }, contentScriptSender(9, "https://example.test/login"));
  assert.deepEqual(res, { ok: false, error: "Locked" });
});

test("PENDING_SAVE then GET_PENDING_SAVE round-trips a new login for the same tab/host", async () => {
  seedSession([]);
  const sender = contentScriptSender(3, "https://newsite.test/login");

  await send({ type: "PENDING_SAVE", username: "me@example.test", password: "hunter2" }, sender);
  const res = await send({ type: "GET_PENDING_SAVE" }, sender);

  assert.deepEqual(res.pending, { host: "newsite.test", username: "me@example.test", password: "hunter2" });
});

test("GET_PENDING_SAVE is one-shot: a second read returns null", async () => {
  seedSession([]);
  const sender = contentScriptSender(3, "https://newsite.test/login");
  await send({ type: "PENDING_SAVE", username: "me@example.test", password: "hunter2" }, sender);

  await send({ type: "GET_PENDING_SAVE" }, sender);
  const second = await send({ type: "GET_PENDING_SAVE" }, sender);

  assert.equal(second.pending, null);
});

test("PENDING_SAVE does not queue when that username is already saved for the site", async () => {
  seedSession([await makeCipher("1", "example", userKey)]); // username: user-example, uri: example.test
  const sender = contentScriptSender(3, "https://example.test/login");

  await send({ type: "PENDING_SAVE", username: "user-example", password: "hunter2" }, sender);
  const res = await send({ type: "GET_PENDING_SAVE" }, sender);

  assert.equal(res.pending, null);
});

test("PENDING_SAVE ignores an oversized captured value instead of storing it", async () => {
  seedSession([]);
  const sender = contentScriptSender(3, "https://newsite.test/login");

  await send({ type: "PENDING_SAVE", username: "me@example.test", password: "x".repeat(5000) }, sender);
  const res = await send({ type: "GET_PENDING_SAVE" }, sender);

  assert.equal(res.pending, null);
});

test("GET_PENDING_SAVE refuses a stale entry if the tab navigated to a different site meanwhile", async () => {
  seedSession([]);
  await send({ type: "PENDING_SAVE", username: "me@example.test", password: "hunter2" }, contentScriptSender(3, "https://siteA.test/login"));

  const res = await send({ type: "GET_PENDING_SAVE" }, contentScriptSender(3, "https://siteB.test/"));

  assert.equal(res.pending, null);
});

test("SAVE_ITEM creates an encrypted cipher on the server and appends it to the session", async () => {
  seedSession([]);
  let posted;
  fetchImpl = async (url, opts) => {
    posted = { url, body: JSON.parse(opts.body) };
    return jsonResponse({ id: "created-1", type: 1, ...posted.body });
  };

  const res = await send(
    { type: "SAVE_ITEM", host: "newsite.test", username: "me@example.test", password: "hunter2" },
    contentScriptSender(3, "https://newsite.test/login")
  );

  assert.equal(res.ok, true);
  assert.equal(posted.url, "https://vault.test/api/ciphers");
  assert.equal(posted.body.type, 1);
  assert.notEqual(posted.body.login.password, "hunter2"); // 평문이 그대로 나가면 안 된다
  assert.equal(await decryptEncString(posted.body.login.password, userKey), "hunter2");
  assert.equal(await decryptEncString(posted.body.login.username, userKey), "me@example.test");

  const afterSync = await send({ type: "GET_ITEMS" });
  assert.ok(afterSync.items.some((i) => i.id === "created-1"));
});

test("SAVE_ITEM rejects a host that does not match the sender tab (spoofed host)", async () => {
  seedSession([]);
  const res = await send(
    { type: "SAVE_ITEM", host: "victim.test", username: "me@example.test", password: "hunter2" },
    contentScriptSender(3, "https://attacker.test/login")
  );
  assert.equal(res.ok, false);
});

const OTPAUTH_URI = "otpauth://totp/example.test:me?secret=GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ&issuer=example.test";

test("SAVE_TOTP attaches the otpauth secret to the matching saved item", async () => {
  const cipher = await makeCipher("1", "example", userKey); // uris: https://example.test, no totp yet
  seedSession([cipher]);
  let posted;
  fetchImpl = async (url, opts) => {
    posted = { url, method: opts.method, body: JSON.parse(opts.body) };
    return jsonResponse({ id: "1", type: 1, ...posted.body });
  };

  const res = await send(
    { type: "SAVE_TOTP", host: "example.test", otpauth: OTPAUTH_URI },
    contentScriptSender(3, "https://example.test/2fa-setup")
  );

  assert.equal(res.ok, true);
  assert.equal(posted.url, "https://vault.test/api/ciphers/1");
  assert.equal(posted.method, "PUT");
  assert.equal(await decryptEncString(posted.body.login.totp, userKey), OTPAUTH_URI);
  // 기존 아이디/비번은 그대로 유지된다 (재암호화하지 않음)
  assert.deepEqual(posted.body.login.password, cipher.login.password);

  const secrets = await send({ type: "GET_ITEM_SECRETS", id: "1" });
  assert.match(secrets.totp.code, /^\d{6}$/);
});

test("SAVE_TOTP rejects a malformed otpauth value", async () => {
  seedSession([await makeCipher("1", "example", userKey)]);
  const res = await send(
    { type: "SAVE_TOTP", host: "example.test", otpauth: "javascript:alert(1)" },
    contentScriptSender(3, "https://example.test/2fa-setup")
  );
  assert.equal(res.ok, false);
});

test("SAVE_TOTP rejects a host that does not match the sender tab", async () => {
  seedSession([await makeCipher("1", "example", userKey)]);
  const res = await send(
    { type: "SAVE_TOTP", host: "example.test", otpauth: OTPAUTH_URI },
    contentScriptSender(3, "https://attacker.test/2fa-setup")
  );
  assert.equal(res.ok, false);
});

test("SAVE_TOTP refuses when no saved item matches the site", async () => {
  seedSession([]);
  const res = await send(
    { type: "SAVE_TOTP", host: "example.test", otpauth: OTPAUTH_URI },
    contentScriptSender(3, "https://example.test/2fa-setup")
  );
  assert.equal(res.ok, false);
  assert.match(res.error, /없습니다/);
});

test("SAVE_TOTP refuses when two saved items match the site (can't tell which one)", async () => {
  seedSession([await makeCipher("1", "example", userKey), await makeCipher("2", "example", userKey)]);
  const res = await send(
    { type: "SAVE_TOTP", host: "example.test", otpauth: OTPAUTH_URI },
    contentScriptSender(3, "https://example.test/2fa-setup")
  );
  assert.equal(res.ok, false);
  assert.match(res.error, /특정할 수 없습니다/);
});

test("IMPORT_ITEMS creates new items and skips ones already saved for the same site+username", async () => {
  seedSession([await makeCipher("1", "example", userKey)]); // username: user-example, uri: https://example.test
  const posted = [];
  fetchImpl = async (url, opts) => {
    const body = JSON.parse(opts.body);
    posted.push(body);
    return jsonResponse({ id: `new-${posted.length}`, type: 1, ...body });
  };

  const res = await send({
    type: "IMPORT_ITEMS",
    entries: [
      { name: "Example", url: "https://example.test", username: "user-example", password: "dup", notes: "", otpauth: "" }, // already saved
      { name: "NewSite", url: "https://newsite.test", username: "me", password: "hunter2", notes: "n", otpauth: "" },
    ],
  });

  assert.deepEqual(res, { ok: true, imported: 1, skipped: 1, failed: 0 });
  assert.equal(posted.length, 1);
  assert.equal(await decryptEncString(posted[0].login.password, userKey), "hunter2");

  const items = await send({ type: "GET_ITEMS" });
  assert.ok(items.items.some((i) => i.name === "NewSite"));
});

test("IMPORT_ITEMS counts entries whose url can't be parsed as failed instead of throwing", async () => {
  seedSession([]);
  const res = await send({ type: "IMPORT_ITEMS", entries: [{ url: "", password: "pw" }] });
  assert.deepEqual(res, { ok: true, imported: 0, skipped: 0, failed: 1 });
});

test("IMPORT_ITEMS rejects an empty or oversized entry list", async () => {
  seedSession([]);
  assert.equal((await send({ type: "IMPORT_ITEMS", entries: [] })).ok, false);
  assert.equal((await send({ type: "IMPORT_ITEMS", entries: new Array(2001).fill({ url: "https://a.test", password: "p" }) })).ok, false);
});

test("IMPORT_ITEMS fails while locked instead of throwing", async () => {
  const res = await send({ type: "IMPORT_ITEMS", entries: [{ url: "https://a.test", password: "p" }] });
  assert.deepEqual(res, { ok: false, error: "Locked" });
});

test("a content script may not send IMPORT_ITEMS (extension-page only)", async () => {
  seedSession([]);
  const res = await send(
    { type: "IMPORT_ITEMS", entries: [{ url: "https://a.test", password: "p" }] },
    contentScriptSender(1, "https://evil.test/page")
  );
  assert.deepEqual(res, { ok: false, error: "forbidden" });
});

test("GET_HOST_MATCHES puts the most recently autofilled account first", async () => {
  seedSession([await makeCipher("1", "example", userKey), await makeCipher("2", "example", userKey)]);
  const sender = contentScriptSender(9, "https://example.test/login");

  const before = await send({ type: "GET_HOST_MATCHES" }, sender);
  assert.deepEqual(before.items.map((i) => i.id), ["1", "2"]);

  await send({ type: "REQUEST_AUTOFILL", id: "2" }, sender);
  const after = await send({ type: "GET_HOST_MATCHES" }, sender);
  assert.deepEqual(after.items.map((i) => i.id), ["2", "1"]);
  assert.equal(typeof after.items[0].lastUsedAt, "number");
  assert.equal(after.items[1].lastUsedAt, null);
});

// 가짜 Vaultwarden: 2FA를 요구하고, twoFactorRemember=1이면 기억 토큰을 발급해 다음 로그인에서 받아준다.
async function fakeTwoFactorServer({ email, password }) {
  const iterations = 5000;
  const stretched = await stretchKey(await deriveMasterKey(password, email, iterations));
  // encryptString은 UTF-8 문자열을 받으므로 ASCII 범위 바이트로 64바이트 user key를 만든다.
  const rawUserKey = String.fromCharCode(...crypto.getRandomValues(new Uint8Array(64)).map((b) => b & 0x7f));
  const protectedKey = await encryptString(rawUserKey, stretched);
  const tokenRequests = [];
  fetchImpl = async (url, opts) => {
    if (url.endsWith("/identity/accounts/prelogin")) return jsonResponse({ kdf: 0, kdfIterations: iterations });
    if (url.endsWith("/api/sync?excludeDomains=true")) {
      const bytes = new TextEncoder().encode(rawUserKey);
      const userKey = { encKey: bytes.slice(0, 32), macKey: bytes.slice(32, 64) };
      return jsonResponse({ ciphers: [await makeCipher("c1", "example", userKey)] });
    }
    const body = new URLSearchParams(opts.body);
    tokenRequests.push(body);
    const provider = body.get("twoFactorProvider");
    const ok =
      (provider === "0" && body.get("twoFactorToken") === "123456") ||
      (provider === "5" && body.get("twoFactorToken") === "remember-me");
    if (!ok) return jsonResponse({ error: "invalid_grant", TwoFactorProviders: ["0"] }, 400);
    return jsonResponse({
      access_token: "a",
      refresh_token: "r",
      expires_in: 3600,
      Key: protectedKey,
      ...(body.get("twoFactorRemember") === "1" && { TwoFactorToken: "remember-me" }),
    });
  };
  return tokenRequests;
}

test("after one OTP login the device is remembered, so the next login skips the OTP", async () => {
  const creds = { serverUrl: "https://vault.test", email: "me@example.test", password: "pw" };
  const requests = await fakeTwoFactorServer(creds);

  assert.deepEqual(await send({ type: "LOGIN", ...creds }), { ok: false, twoFactorRequired: true });
  assert.equal((await send({ type: "LOGIN", ...creds, twoFactorCode: "123456" })).ok, true);
  assert.equal(requests.at(-1).get("twoFactorRemember"), "1");

  await send({ type: "LOCK" });
  assert.equal((await send({ type: "LOGIN", ...creds })).ok, true);
  assert.equal(requests.at(-1).get("twoFactorProvider"), "5");
});

test("a remembered 2FA token the server rejects is dropped and the OTP is asked again", async () => {
  const creds = { serverUrl: "https://vault.test", email: "me@example.test", password: "pw" };
  const requests = await fakeTwoFactorServer(creds);
  const stretched = await stretchKey(await deriveMasterKey(creds.password, creds.email, 5000));
  store.local.rememberedTwoFactor = { "https://vault.test|me@example.test": await encryptString("revoked", stretched) };

  assert.deepEqual(await send({ type: "LOGIN", ...creds }), { ok: false, twoFactorRequired: true });
  assert.equal(requests.at(-1).get("twoFactorProvider"), "5");
  assert.deepEqual(store.local.rememberedTwoFactor, {});
});

async function loginWithOtp() {
  const creds = { serverUrl: "https://vault.test", email: "me@example.test", password: "pw" };
  const requests = await fakeTwoFactorServer(creds);
  assert.equal((await send({ type: "LOGIN", ...creds, twoFactorCode: "123456" })).ok, true);
  return { creds, requests };
}

const serverDown = () => {
  fetchImpl = async () => {
    throw new Error("offline");
  };
};

test("LOCK keeps an encrypted local vault, so UNLOCK needs only the master password (no server, no OTP)", async () => {
  await loginWithOtp();
  const vault = store.local.vault;
  assert.ok(vault.protectedKey.startsWith("2."));
  assert.ok(vault.encRefreshToken.startsWith("2."), "refresh token must be stored encrypted");
  assert.ok(!JSON.stringify(vault).includes('"r"'), "no plaintext refresh token on disk");

  await send({ type: "LOCK" });
  assert.equal((await send({ type: "GET_STATUS" })).locked, true);
  assert.equal((await send({ type: "GET_STATUS" })).canUnlock, true);

  serverDown();
  assert.equal((await send({ type: "UNLOCK", password: "wrong" })).ok, false);
  assert.equal((await send({ type: "UNLOCK", password: "pw" })).ok, true);
  const items = await send({ type: "GET_ITEMS" });
  assert.deepEqual(items.items.map((i) => i.id), ["c1"]);
});

test("PIN unlocks after LOCK, and five wrong PINs disable it", async () => {
  await loginWithOtp();
  assert.equal((await send({ type: "SET_PIN", pin: "12" })).ok, false);
  assert.equal((await send({ type: "SET_PIN", pin: "2468" })).ok, true);
  assert.ok(store.session.pin, "PIN-wrapped key lives in session (memory) storage only");
  assert.equal(store.local.pin, undefined);

  await send({ type: "LOCK" });
  serverDown();
  assert.equal((await send({ type: "GET_STATUS" })).pinEnabled, true);
  assert.equal((await send({ type: "UNLOCK_PIN", pin: "2468" })).ok, true);

  await send({ type: "LOCK" });
  for (let i = 0; i < 4; i++) assert.equal((await send({ type: "UNLOCK_PIN", pin: "0000" })).pinDisabled, undefined);
  const last = await send({ type: "UNLOCK_PIN", pin: "0000" });
  assert.equal(last.pinDisabled, true);
  assert.equal((await send({ type: "GET_STATUS" })).pinEnabled, false);
  assert.equal((await send({ type: "UNLOCK_PIN", pin: "2468" })).ok, false);
});

test("LOGOUT forgets the local vault and PIN", async () => {
  await loginWithOtp();
  await send({ type: "SET_PIN", pin: "2468" });
  await send({ type: "LOGOUT" });
  const status = await send({ type: "GET_STATUS" });
  assert.equal(status.locked, true);
  assert.equal(status.canUnlock, false);
  assert.equal(store.local.vault, undefined);
  assert.equal(store.session.pin, undefined);
});

test("auto-lock timer follows the chosen minutes and is not extended by merely opening login pages", async () => {
  seedSession([await makeCipher("1", "example", userKey)]);
  const page = contentScriptSender(9, "https://example.test/login");
  const settle = () => new Promise((r) => setTimeout(r, 20));

  await send({ type: "GET_HOST_MATCHES" }, page);
  await settle();
  assert.equal(alarms["auto-lock"], undefined);

  await send({ type: "REQUEST_AUTOFILL", id: "1" }, page);
  await settle();
  assert.deepEqual(alarms["auto-lock"], { delayInMinutes: 15 });

  assert.equal((await send({ type: "SET_LOCK_MINUTES", minutes: 7 })).ok, false);
  await send({ type: "SET_LOCK_MINUTES", minutes: 60 });
  await settle();
  assert.deepEqual(alarms["auto-lock"], { delayInMinutes: 60 });

  await send({ type: "SET_LOCK_MINUTES", minutes: 0 });
  await settle();
  assert.equal(alarms["auto-lock"], undefined);
});

test("concurrent wrong PINs are counted one by one, so the attempt limit cannot be raced", async () => {
  await loginWithOtp();
  await send({ type: "SET_PIN", pin: "2468" });
  await send({ type: "LOCK" });
  serverDown();
  const results = await Promise.all(Array.from({ length: 8 }, () => send({ type: "UNLOCK_PIN", pin: "0000" })));
  assert.equal(results.filter((r) => r.pinDisabled).length, 1);
  assert.equal(store.session.pin, undefined, "a late failure must not resurrect the wiped PIN");
  assert.equal((await send({ type: "UNLOCK_PIN", pin: "2468" })).ok, false);
});

test("an iframe on another host cannot consume the top page's pending save offer", async () => {
  seedSession([]);
  await send({ type: "PENDING_SAVE", username: "u", password: "p" }, contentScriptSender(9, "https://example.test/"));
  const ad = await send({ type: "GET_PENDING_SAVE" }, contentScriptSender(9, "https://example.test/", { frameId: 2, documentId: "ad", url: "https://ads.test/x" }));
  assert.equal(ad.pending, null);
  const top = await send({ type: "GET_PENDING_SAVE" }, contentScriptSender(9, "https://example.test/"));
  assert.equal(top.pending.username, "u");
});

test("the remembered 2FA token is stored encrypted, not in plaintext", async () => {
  await loginWithOtp();
  const stored = Object.values(store.local.rememberedTwoFactor);
  assert.equal(stored.length, 1);
  assert.ok(stored[0].startsWith("2."));
  assert.notEqual(stored[0], "remember-me");
});

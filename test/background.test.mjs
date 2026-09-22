// Regression tests for src/background.js driven through mocked chrome.* and fetch.
// No network, no real secrets: all keys are random and generated per run.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { encryptString, decryptEncString, bytesToB64 } from "../src/lib/crypto.js";

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
    async sendMessage(tabId, msg) {
      tabMessages.push({ tabId, msg });
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

const contentScriptSender = (tabId, url) => ({ id: EXT_ID, tab: { id: tabId, url }, url });

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
  assert.equal(tabMessages.length, 1);
  assert.deepEqual(tabMessages[0], {
    tabId: 9,
    msg: { type: "DO_AUTOFILL", username: "user-example", password: "pw", submit: true },
  });
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

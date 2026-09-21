// Regression tests for src/background.js driven through mocked chrome.* and fetch.
// No network, no real secrets: all keys are random and generated per run.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { encryptString, bytesToB64 } from "../src/lib/crypto.js";

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
  fetchImpl = async () => {
    throw new Error("unexpected fetch");
  };
});

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

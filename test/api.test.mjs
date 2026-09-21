// Regression tests for src/lib/api.js: prelogin KDF validation and device id fallback.
import { test, beforeEach } from "node:test";
import assert from "node:assert/strict";
import { VaultwardenClient } from "../src/lib/api.js";

let fetchImpl;
const jsonResponse = (body, status = 200) => ({ ok: status < 400, status, json: async () => body });
globalThis.fetch = (url, opts) => fetchImpl(url, opts);

beforeEach(() => {
  delete globalThis.chrome;
});

const preloginWith = (data) => {
  fetchImpl = async () => jsonResponse(data);
  return new VaultwardenClient("https://vault.test").prelogin("user@example.test");
};

test("prelogin accepts a sane integer iteration count", async () => {
  assert.deepEqual(await preloginWith({ kdf: 0, kdfIterations: 600000 }), { kdf: 0, kdfIterations: 600000 });
});

for (const [label, value] of [
  ["a numeric string", "600000"],
  ["NaN", NaN],
  ["a float", 600000.5],
  ["null-ish object", {}],
  ["Infinity", Infinity],
  ["above the upper bound", 10_000_001],
  ["below the lower bound", 4999],
]) {
  test(`prelogin rejects kdfIterations that is ${label}`, async () => {
    await assert.rejects(preloginWith({ kdf: 0, kdfIterations: value }), /KDF/);
  });
}

test("prelogin accepts the upper bound exactly", async () => {
  assert.equal((await preloginWith({ kdf: 0, kdfIterations: 10_000_000 })).kdfIterations, 10_000_000);
});

test("login falls back to an ephemeral device id when chrome.storage throws", async (t) => {
  const warn = t.mock.method(console, "warn", () => {});
  globalThis.chrome = {
    storage: {
      local: {
        get: async () => {
          throw new Error("storage unavailable");
        },
        set: async () => {},
      },
    },
  };
  let sentBody;
  fetchImpl = async (_url, opts) => {
    sentBody = new URLSearchParams(opts.body);
    return jsonResponse({ access_token: "a", refresh_token: "r" });
  };

  const data = await new VaultwardenClient("https://vault.test").login("user@example.test", "hash");

  assert.equal(data.access_token, "a");
  assert.match(sentBody.get("deviceIdentifier"), /^[0-9a-f-]{36}$/);
  assert.equal(warn.mock.callCount(), 1);
});

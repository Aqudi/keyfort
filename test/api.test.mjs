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

// Vaultwarden answers a 2FA-protected login with 400 + TwoFactorProviders.
const TWO_FACTOR_REQUIRED = {
  error: "invalid_grant",
  error_description: "Two factor required.",
  TwoFactorProviders: [0],
};

test("login flags a 2FA challenge with the offered providers", async () => {
  fetchImpl = async () => jsonResponse(TWO_FACTOR_REQUIRED, 400);
  await assert.rejects(new VaultwardenClient("https://vault.test").login("user@example.test", "hash"), (err) => {
    assert.equal(err.twoFactorRequired, true);
    assert.deepEqual(err.twoFactorProviders, [0]);
    return true;
  });
});

test("login does not flag ordinary auth failures as 2FA", async () => {
  fetchImpl = async () => jsonResponse({ error: "invalid_grant", error_description: "Username or password is incorrect." }, 400);
  await assert.rejects(new VaultwardenClient("https://vault.test").login("user@example.test", "hash"), (err) => {
    assert.notEqual(err.twoFactorRequired, true);
    return true;
  });
});

test("login sends the authenticator code as twoFactorToken/twoFactorProvider", async () => {
  let sentBody;
  fetchImpl = async (_url, opts) => {
    sentBody = new URLSearchParams(opts.body);
    return jsonResponse({ access_token: "a", refresh_token: "r" });
  };
  await new VaultwardenClient("https://vault.test").login("user@example.test", "hash", { token: "123456", provider: 0 });
  assert.equal(sentBody.get("twoFactorToken"), "123456");
  assert.equal(sentBody.get("twoFactorProvider"), "0");
  assert.equal(sentBody.get("twoFactorRemember"), "0");
});

test("login asks the server to remember this device when twoFactor.remember is set", async () => {
  let sentBody;
  fetchImpl = async (_url, opts) => {
    sentBody = new URLSearchParams(opts.body);
    return jsonResponse({ access_token: "a", refresh_token: "r" });
  };
  await new VaultwardenClient("https://vault.test").login("user@example.test", "hash", { token: "123456", provider: 0, remember: true });
  assert.equal(sentBody.get("twoFactorRemember"), "1");
});

test("createCipher posts the cipher and returns the created resource", async () => {
  let sentUrl, sentOpts;
  fetchImpl = async (url, opts) => {
    sentUrl = url;
    sentOpts = opts;
    return jsonResponse({ id: "new-id", type: 1 });
  };
  const cipher = { type: 1, name: "enc-name" };
  const result = await new VaultwardenClient("https://vault.test").createCipher("tok", cipher);
  assert.equal(sentUrl, "https://vault.test/api/ciphers");
  assert.equal(sentOpts.method, "POST");
  assert.equal(sentOpts.headers.authorization, "Bearer tok");
  assert.deepEqual(JSON.parse(sentOpts.body), cipher);
  assert.deepEqual(result, { id: "new-id", type: 1 });
});

test("createCipher throws the server's error message on failure", async () => {
  fetchImpl = async () => jsonResponse({ Message: "bad cipher" }, 400);
  await assert.rejects(
    new VaultwardenClient("https://vault.test").createCipher("tok", {}),
    /bad cipher/
  );
});

test("updateCipher puts the cipher to its id and returns the updated resource", async () => {
  let sentUrl, sentOpts;
  fetchImpl = async (url, opts) => {
    sentUrl = url;
    sentOpts = opts;
    return jsonResponse({ id: "abc 123", type: 1 });
  };
  const cipher = { type: 1, name: "enc-name" };
  const result = await new VaultwardenClient("https://vault.test").updateCipher("tok", "abc 123", cipher);
  assert.equal(sentUrl, "https://vault.test/api/ciphers/abc%20123");
  assert.equal(sentOpts.method, "PUT");
  assert.equal(sentOpts.headers.authorization, "Bearer tok");
  assert.deepEqual(JSON.parse(sentOpts.body), cipher);
  assert.deepEqual(result, { id: "abc 123", type: 1 });
});

test("updateCipher throws the server's error message on failure", async () => {
  fetchImpl = async () => jsonResponse({ Message: "bad cipher" }, 400);
  await assert.rejects(new VaultwardenClient("https://vault.test").updateCipher("tok", "1", {}), /bad cipher/);
});

test("createFolder posts the encrypted name and returns the created folder", async () => {
  let sentUrl, sentOpts;
  fetchImpl = async (url, opts) => {
    sentUrl = url;
    sentOpts = opts;
    return jsonResponse({ id: "folder-1", name: "enc-name" });
  };
  const result = await new VaultwardenClient("https://vault.test").createFolder("tok", "enc-name");
  assert.equal(sentUrl, "https://vault.test/api/folders");
  assert.equal(sentOpts.method, "POST");
  assert.deepEqual(JSON.parse(sentOpts.body), { name: "enc-name" });
  assert.deepEqual(result, { id: "folder-1", name: "enc-name" });
});

test("createFolder throws the server's error message on failure", async () => {
  fetchImpl = async () => jsonResponse({ Message: "bad folder" }, 400);
  await assert.rejects(new VaultwardenClient("https://vault.test").createFolder("tok", "enc-name"), /bad folder/);
});

test("refreshToken attaches the HTTP status to the thrown error", async () => {
  // Vaultwarden refresh tokens rotate (single-use); background.js's ensureFreshToken needs the
  // status to tell "this token is permanently dead" (400/401) apart from a transient/offline failure.
  fetchImpl = async () => jsonResponse({ error: "invalid_grant" }, 400);
  await assert.rejects(
    () => new VaultwardenClient("https://vault.test").refreshToken("dead-token"),
    (err) => err.status === 400 && /refresh failed: 400/.test(err.message)
  );
});

test("deleteCipher sends a DELETE to the cipher's id", async () => {
  let sentUrl, sentOpts;
  fetchImpl = async (url, opts) => {
    sentUrl = url;
    sentOpts = opts;
    return jsonResponse({});
  };
  await new VaultwardenClient("https://vault.test").deleteCipher("tok", "abc 123");
  assert.equal(sentUrl, "https://vault.test/api/ciphers/abc%20123");
  assert.equal(sentOpts.method, "DELETE");
});

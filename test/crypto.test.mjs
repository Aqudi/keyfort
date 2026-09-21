// Regression tests for src/lib/crypto.js. Run: node --test test/
import { test } from "node:test";
import assert from "node:assert/strict";
import {
  encryptString,
  decryptEncString,
  decryptSymmetricKey,
  generateTotp,
  b64ToBytes,
  bytesToB64,
} from "../src/lib/crypto.js";

const randomKeys = () => ({
  encKey: crypto.getRandomValues(new Uint8Array(32)),
  macKey: crypto.getRandomValues(new Uint8Array(32)),
});

// Builds a MAC-less "0.iv|ct" EncString encrypted with keys.encKey.
async function encryptWithoutMac(plainBytes, { encKey }) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const ct = new Uint8Array(await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, plainBytes));
  return `0.${bytesToB64(iv)}|${bytesToB64(ct)}`;
}

// Flips the lowest bit of the first byte of one part (0=iv, 1=ct, 2=mac).
function flipBit(encStr, partIndex) {
  const [type, rest] = [encStr.slice(0, 2), encStr.slice(2)];
  const parts = rest.split("|");
  const bytes = b64ToBytes(parts[partIndex]);
  bytes[0] ^= 1;
  parts[partIndex] = bytesToB64(bytes);
  return type + parts.join("|");
}

test("round-trips a type 2 EncString", async () => {
  const keys = randomKeys();
  const enc = await encryptString("hunter2 \u{1F511} 비밀", keys);
  assert.match(enc, /^2\.[^|]+\|[^|]+\|[^|]+$/);
  assert.equal(await decryptEncString(enc, keys), "hunter2 \u{1F511} 비밀");
});

test("decryptEncString rejects a MAC-less type 0 EncString when macKey is present", async () => {
  const keys = randomKeys();
  const enc = await encryptWithoutMac(new TextEncoder().encode("forged"), keys);
  await assert.rejects(decryptEncString(enc, keys), /MAC/);
});

test("decryptSymmetricKey rejects a MAC-less type 0 EncString when macKey is present", async () => {
  const stretched = randomKeys();
  const enc = await encryptWithoutMac(crypto.getRandomValues(new Uint8Array(64)), stretched);
  await assert.rejects(decryptSymmetricKey(enc, stretched), /MAC/);
});

for (const [label, index] of [["iv", 0], ["ciphertext", 1], ["mac", 2]]) {
  test(`decryptEncString rejects a 1-bit tamper of the ${label}`, async () => {
    const keys = randomKeys();
    const enc = await encryptString("secret", keys);
    await assert.rejects(decryptEncString(flipBit(enc, index), keys), /MAC verification failed/);
  });
}

// RFC 6238 Appendix B, SHA-1 seed "12345678901234567890" (ASCII) in base32.
const RFC6238_SHA1_SECRET_B32 = "GEZDGNBVGY3TQOJQGEZDGNBVGY3TQOJQ";
const RFC6238_VECTORS = [
  [59, "94287082"],
  [1111111109, "07081804"],
  [1111111111, "14050471"],
  [1234567890, "89005924"],
  [2000000000, "69279037"],
];

for (const [unixSeconds, expected] of RFC6238_VECTORS) {
  test(`generates RFC 6238 SHA-1 8-digit code ${expected} at t=${unixSeconds}`, async (t) => {
    t.mock.method(Date, "now", () => unixSeconds * 1000);
    const { code } = await generateTotp(RFC6238_SHA1_SECRET_B32, { digits: 8 });
    assert.equal(code, expected);
  });
}

test("decryptEncString throws when no macKey is supplied (no fail-open)", async () => {
  const keys = randomKeys();
  const enc = await encryptString("secret", keys);
  await assert.rejects(decryptEncString(enc, { encKey: keys.encKey }), /MAC key required/);
});

test("decryptSymmetricKey throws when no macKey is supplied (no fail-open)", async () => {
  const stretched = randomKeys();
  const enc = await encryptString("x".repeat(64), stretched);
  await assert.rejects(decryptSymmetricKey(enc, { encKey: stretched.encKey }), /MAC key required/);
});

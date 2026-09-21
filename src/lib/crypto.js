// src/lib/crypto.js
// Bitwarden/Vaultwarden-compatible client-side crypto using WebCrypto.
// Implements: PBKDF2 master key derivation, HKDF stretching, AES-256-CBC +
// HMAC-SHA256 EncString encrypt/decrypt, and master password hash.

const te = new TextEncoder();
const td = new TextDecoder();

export function b64ToBytes(b64) {
  const bin = atob(b64);
  const bytes = new Uint8Array(bin.length);
  for (let i = 0; i < bin.length; i++) bytes[i] = bin.charCodeAt(i);
  return bytes;
}

export function bytesToB64(bytes) {
  let bin = "";
  const arr = bytes instanceof Uint8Array ? bytes : new Uint8Array(bytes);
  for (let i = 0; i < arr.length; i++) bin += String.fromCharCode(arr[i]);
  return btoa(bin);
}

function concatBytes(...arrs) {
  const total = arrs.reduce((n, a) => n + a.length, 0);
  const out = new Uint8Array(total);
  let off = 0;
  for (const a of arrs) {
    out.set(a, off);
    off += a.length;
  }
  return out;
}

// PBKDF2-SHA256(password, salt, iterations, 32 bytes) -> masterKey (raw bytes)
export async function deriveMasterKey(password, email, iterations = 600000) {
  const salt = te.encode(email.trim().toLowerCase());
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    te.encode(password),
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    { name: "PBKDF2", salt, iterations, hash: "SHA-256" },
    keyMaterial,
    256
  );
  return new Uint8Array(bits);
}

// masterPasswordHash = base64(PBKDF2-SHA256(masterKey, password, 1, 32 bytes))
export async function hashMasterKey(masterKey, password) {
  const keyMaterial = await crypto.subtle.importKey(
    "raw",
    masterKey,
    "PBKDF2",
    false,
    ["deriveBits"]
  );
  const bits = await crypto.subtle.deriveBits(
    {
      name: "PBKDF2",
      salt: te.encode(password),
      iterations: 1,
      hash: "SHA-256",
    },
    keyMaterial,
    256
  );
  return bytesToB64(new Uint8Array(bits));
}

// HKDF-Expand(prk=masterKey, info, 32 bytes) using HMAC-SHA256, no extract step
// (Bitwarden's stretchKey uses HKDF-Expand only, treating masterKey as the PRK).
async function hkdfExpand(prk, info, length = 32) {
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    prk,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const infoBytes = te.encode(info);
  const t1 = await crypto.subtle.sign(
    "HMAC",
    hmacKey,
    concatBytes(infoBytes, new Uint8Array([1]))
  );
  return new Uint8Array(t1).slice(0, length);
}

// Returns { encKey: 32 bytes, macKey: 32 bytes } stretched from masterKey
export async function stretchKey(masterKey) {
  const encKey = await hkdfExpand(masterKey, "enc", 32);
  const macKey = await hkdfExpand(masterKey, "mac", 32);
  return { encKey, macKey };
}

// Parse an EncString "2.iv|ct|mac" (base64 parts) -> {iv, ct, mac}
export function parseEncString(str) {
  if (!str) return null;
  const [typePart, rest] = [str.slice(0, str.indexOf(".")), str.slice(str.indexOf(".") + 1)];
  const type = parseInt(typePart, 10);
  const parts = rest.split("|");
  if (type === 2) {
    // AesCbc256_HmacSha256_B64
    return { type, iv: b64ToBytes(parts[0]), ct: b64ToBytes(parts[1]), mac: b64ToBytes(parts[2]) };
  }
  if (type === 0) {
    // AesCbc256_B64 (no mac) - rare
    return { type, iv: b64ToBytes(parts[0]), ct: b64ToBytes(parts[1]), mac: null };
  }
  throw new Error("Unsupported EncString type: " + type);
}

async function hmacVerify(macKey, data, expectedMac) {
  const key = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", key, data));
  if (sig.length !== expectedMac.length) return false;
  let diff = 0;
  for (let i = 0; i < sig.length; i++) diff |= sig[i] ^ expectedMac[i];
  return diff === 0;
}

// AES-256-CBC decrypt. macKey is mandatory and the EncString MUST carry a valid
// MAC (rejects type-0 style downgrade and fail-open on a missing key). Returns plaintext bytes.
async function decryptCbcVerified(parsed, encKey, macKey, macFailMessage) {
  if (!macKey) throw new Error("MAC key required");
  if (!parsed.mac) throw new Error("MAC required");
  const ok = await hmacVerify(macKey, concatBytes(parsed.iv, parsed.ct), parsed.mac);
  if (!ok) throw new Error(macFailMessage);
  const key = await crypto.subtle.importKey("raw", encKey, { name: "AES-CBC" }, false, ["decrypt"]);
  return new Uint8Array(await crypto.subtle.decrypt({ name: "AES-CBC", iv: parsed.iv }, key, parsed.ct));
}

// Decrypt an EncString given {encKey, macKey} (32 bytes each). Returns string.
export async function decryptEncString(encStr, { encKey, macKey }) {
  if (!encStr) return null;
  const parsed = parseEncString(encStr);
  const plain = await decryptCbcVerified(
    parsed,
    encKey,
    macKey,
    "MAC verification failed (wrong key or tampered data)"
  );
  return td.decode(plain);
}

// Decrypt a symmetric key EncString (the user's "Key" from login response) into
// raw bytes (64 bytes: 32 enc + 32 mac), using the stretched master key.
export async function decryptSymmetricKey(encStr, stretched) {
  const parsed = parseEncString(encStr);
  const plain = await decryptCbcVerified(
    parsed,
    stretched.encKey,
    stretched.macKey,
    "MAC verification failed while decrypting user key"
  );
  return { encKey: plain.slice(0, 32), macKey: plain.slice(32, 64) };
}

// Encrypt plaintext string into an EncString "2.iv|ct|mac" using {encKey, macKey}.
export async function encryptString(plaintext, { encKey, macKey }) {
  const iv = crypto.getRandomValues(new Uint8Array(16));
  const key = await crypto.subtle.importKey("raw", encKey, { name: "AES-CBC" }, false, ["encrypt"]);
  const ctBuf = await crypto.subtle.encrypt({ name: "AES-CBC", iv }, key, te.encode(plaintext));
  const ct = new Uint8Array(ctBuf);
  const hmacKey = await crypto.subtle.importKey(
    "raw",
    macKey,
    { name: "HMAC", hash: "SHA-256" },
    false,
    ["sign"]
  );
  const mac = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, concatBytes(iv, ct)));
  return `2.${bytesToB64(iv)}|${bytesToB64(ct)}|${bytesToB64(mac)}`;
}

// TOTP (RFC 6238), HMAC-SHA1, 30s period, 6 digits, base32 secret.
const BASE32_ALPHABET = "ABCDEFGHIJKLMNOPQRSTUVWXYZ234567";

export function base32Decode(input) {
  const clean = input.replace(/=+$/, "").toUpperCase().replace(/\s/g, "");
  let bits = "";
  for (const ch of clean) {
    const idx = BASE32_ALPHABET.indexOf(ch);
    if (idx === -1) continue;
    bits += idx.toString(2).padStart(5, "0");
  }
  const bytes = [];
  for (let i = 0; i + 8 <= bits.length; i += 8) {
    bytes.push(parseInt(bits.slice(i, i + 8), 2));
  }
  return new Uint8Array(bytes);
}

export async function generateTotp(secretInput, { period = 30, digits = 6 } = {}) {
  // secretInput may be a raw base32 secret, or an otpauth:// URI.
  let secret = secretInput;
  let p = period,
    d = digits,
    algo = "SHA-1";
  if (secretInput.startsWith("otpauth://")) {
    const url = new URL(secretInput);
    secret = url.searchParams.get("secret") || "";
    p = parseInt(url.searchParams.get("period") || "30", 10);
    d = parseInt(url.searchParams.get("digits") || "6", 10);
    const alg = (url.searchParams.get("algorithm") || "SHA1").toUpperCase();
    algo = alg === "SHA256" ? "SHA-256" : alg === "SHA512" ? "SHA-512" : "SHA-1";
  }
  const key = base32Decode(secret);
  const counter = Math.floor(Date.now() / 1000 / p);
  const counterBytes = new Uint8Array(8);
  let c = BigInt(counter);
  for (let i = 7; i >= 0; i--) {
    counterBytes[i] = Number(c & 0xffn);
    c >>= 8n;
  }
  const hmacKey = await crypto.subtle.importKey("raw", key, { name: "HMAC", hash: algo }, false, ["sign"]);
  const sig = new Uint8Array(await crypto.subtle.sign("HMAC", hmacKey, counterBytes));
  const offset = sig[sig.length - 1] & 0x0f;
  const binCode =
    ((sig[offset] & 0x7f) << 24) |
    ((sig[offset + 1] & 0xff) << 16) |
    ((sig[offset + 2] & 0xff) << 8) |
    (sig[offset + 3] & 0xff);
  const code = (binCode % 10 ** d).toString().padStart(d, "0");
  const secondsRemaining = p - (Math.floor(Date.now() / 1000) % p);
  return { code, secondsRemaining, period: p };
}

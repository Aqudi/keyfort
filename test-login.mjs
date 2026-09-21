// test-login.mjs - verify crypto + API against local Vaultwarden.
import { deriveMasterKey, hashMasterKey, stretchKey, decryptSymmetricKey, decryptEncString } from "./src/lib/crypto.js";
import { VaultwardenClient } from "./src/lib/api.js";

// Node fetch doesn't trust our mkcert CA by default; disable TLS verification for this local test only.
process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const SERVER = process.env.VW_SERVER ?? "https://localhost:8443";
const EMAIL = process.env.VW_EMAIL;
const PASSWORD = process.env.VW_PASSWORD;
if (!EMAIL || !PASSWORD) {
  console.error("Usage: VW_EMAIL=<email> VW_PASSWORD=<master password> [VW_SERVER=https://localhost:8443] node test-login.mjs");
  process.exit(1);
}

async function main() {
  const client = new VaultwardenClient(SERVER);
  const { kdfIterations } = await client.prelogin(EMAIL);
  console.log("KDF iterations:", kdfIterations);

  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, kdfIterations);
  const mpHash = await hashMasterKey(masterKey, PASSWORD);

  const loginData = await client.login(EMAIL, mpHash);
  console.log("Login OK. Token type:", loginData.token_type);

  const stretched = await stretchKey(masterKey);
  const userKey = await decryptSymmetricKey(loginData.Key, stretched);
  console.log("User symmetric key derived, encKey length:", userKey.encKey.length);

  const syncData = await client.sync(loginData.access_token);
  console.log("Sync OK. Ciphers count:", syncData.ciphers?.length ?? syncData.Ciphers?.length ?? 0);
  console.log("Profile email:", syncData.profile?.email ?? syncData.Profile?.Email);
}

main().catch((e) => {
  console.error("FAILED:", e.message, e.raw ?? "");
  process.exit(1);
});

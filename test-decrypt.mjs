import { deriveMasterKey, hashMasterKey, stretchKey, decryptSymmetricKey, decryptEncString, generateTotp } from "./src/lib/crypto.js";
import { VaultwardenClient } from "./src/lib/api.js";

process.env.NODE_TLS_REJECT_UNAUTHORIZED = "0";

const SERVER = process.env.VW_SERVER ?? "https://localhost:8443";
const EMAIL = process.env.VW_EMAIL;
const PASSWORD = process.env.VW_PASSWORD;
if (!EMAIL || !PASSWORD) {
  console.error("Usage: VW_EMAIL=<email> VW_PASSWORD=<master password> [VW_SERVER=https://localhost:8443] node test-decrypt.mjs");
  process.exit(1);
}

async function main() {
  const client = new VaultwardenClient(SERVER);
  const { kdfIterations } = await client.prelogin(EMAIL);
  const masterKey = await deriveMasterKey(PASSWORD, EMAIL, kdfIterations);
  const mpHash = await hashMasterKey(masterKey, PASSWORD);
  const loginData = await client.login(EMAIL, mpHash);
  const stretched = await stretchKey(masterKey);
  const userKey = await decryptSymmetricKey(loginData.Key, stretched);

  const syncData = await client.sync(loginData.access_token);
  const ciphers = syncData.ciphers ?? syncData.Ciphers ?? [];
  console.log("Ciphers:", ciphers.length);

  for (const c of ciphers) {
    const name = await decryptEncString(c.name ?? c.Name, userKey);
    const login = c.login ?? c.Login;
    const username = login?.username ?? login?.Username;
    const password = login?.password ?? login?.Password;
    const totpSeed = login?.totp ?? login?.Totp;
    const decUsername = username ? await decryptEncString(username, userKey) : null;
    const decPassword = password ? await decryptEncString(password, userKey) : null;
    const decTotpSeed = totpSeed ? await decryptEncString(totpSeed, userKey) : null;
    console.log({ name, decUsername, decPassword, decTotpSeed });
    if (decTotpSeed) {
      const totp = await generateTotp(decTotpSeed);
      console.log("TOTP now:", totp.code, "expires in", totp.secondsRemaining, "s");
    }
  }
}

main().catch((e) => {
  console.error("FAILED:", e.message, e.stack);
  process.exit(1);
});

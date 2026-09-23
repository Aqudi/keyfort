// Regression tests for src/lib/importers.js: Chromium/1Password CSV header normalization.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCsv } from "../src/lib/csv.js";
import { normalizeImportRows } from "../src/lib/importers.js";

test("normalizes a Chrome/Arc/Edge/Brave export (name,url,username,password,note)", () => {
  const rows = parseCsv("name,url,username,password,note\nGitHub,https://github.com,me,pw1,my note\n");
  assert.deepEqual(normalizeImportRows(rows), [
    { name: "GitHub", url: "https://github.com", username: "me", password: "pw1", notes: "my note", otpauth: "" },
  ]);
});

test("normalizes a 1Password export (Title,Url,Username,Password,OTPAuth,Notes)", () => {
  const rows = parseCsv(
    "Title,Url,Username,Password,OTPAuth,Favorite,Archived,Tags,Notes\n" +
      "GitHub,https://github.com,me,pw1,otpauth://totp/GitHub:me?secret=ABC,false,false,,my note\n"
  );
  assert.deepEqual(normalizeImportRows(rows), [
    {
      name: "GitHub",
      url: "https://github.com",
      username: "me",
      password: "pw1",
      notes: "my note",
      otpauth: "otpauth://totp/GitHub:me?secret=ABC",
    },
  ]);
});

test("drops rows without a url or a password", () => {
  const rows = parseCsv("name,url,username,password\nNoUrl,,me,pw\nNoPassword,https://a.test,me,\nGood,https://a.test,me,pw\n");
  assert.deepEqual(normalizeImportRows(rows).map((r) => r.name), ["Good"]);
});

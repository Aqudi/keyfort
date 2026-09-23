// Regression tests for src/lib/csv.js: RFC4180-ish CSV parsing.
import { test } from "node:test";
import assert from "node:assert/strict";
import { parseCsv } from "../src/lib/csv.js";

test("parses a plain header + rows", () => {
  const rows = parseCsv("name,url,username,password\nGitHub,https://github.com,me,pw1\n");
  assert.deepEqual(rows, [{ name: "GitHub", url: "https://github.com", username: "me", password: "pw1" }]);
});

test("handles a quoted field containing a comma", () => {
  const rows = parseCsv('name,notes\nSite,"a, b, c"\n');
  assert.equal(rows[0].notes, "a, b, c");
});

test("handles an escaped double-quote inside a quoted field", () => {
  const rows = parseCsv('name,notes\nSite,"say ""hi"""\n');
  assert.equal(rows[0].notes, 'say "hi"');
});

test("handles a newline embedded in a quoted field", () => {
  const rows = parseCsv('name,notes\nSite,"line1\nline2"\n');
  assert.equal(rows.length, 1);
  assert.equal(rows[0].notes, "line1\nline2");
});

test("handles CRLF line endings", () => {
  const rows = parseCsv("name,url\r\nSite,https://a.test\r\n");
  assert.deepEqual(rows, [{ name: "Site", url: "https://a.test" }]);
});

test("skips blank rows and works without a trailing newline", () => {
  const rows = parseCsv("name,url\nSite,https://a.test\n\nSite2,https://b.test");
  assert.deepEqual(rows.map((r) => r.name), ["Site", "Site2"]);
});

test("lower-cases and trims header names", () => {
  const rows = parseCsv(" Name , URL \nSite,https://a.test\n");
  assert.deepEqual(Object.keys(rows[0]), ["name", "url"]);
});

test("returns an empty array for an empty file", () => {
  assert.deepEqual(parseCsv(""), []);
});

test("returns an empty array for a header-only file", () => {
  assert.deepEqual(parseCsv("name,url\n"), []);
});

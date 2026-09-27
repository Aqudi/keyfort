// Regression tests for src/lib/site.js: hostname parsing and Bitwarden-style URI match detection.
import { test } from "node:test";
import assert from "node:assert/strict";
import { uriHostname, isSameSite, uriMatches, URI_MATCH } from "../src/lib/site.js";

test("uriHostname extracts the host from a full URL", () => {
  assert.equal(uriHostname("https://example.test/login?x=1"), "example.test");
});

test("uriHostname extracts the host from a scheme-less value", () => {
  assert.equal(uriHostname("example.test"), "example.test");
});

test("uriHostname returns null for a value with no usable host", () => {
  assert.equal(uriHostname(""), null);
});

test("isSameSite matches identical hosts", () => {
  assert.equal(isSameSite("example.test", "example.test"), true);
});

test("isSameSite matches a subdomain against its parent", () => {
  assert.equal(isSameSite("login.example.test", "example.test"), true);
});

test("isSameSite matches sibling subdomains sharing a base domain (the old suffix-only check missed this)", () => {
  assert.equal(isSameSite("mail.google.com", "accounts.google.com"), true);
});

test("isSameSite does not match unrelated domains", () => {
  assert.equal(isSameSite("example.test", "attacker.test"), false);
});

test("isSameSite treats a known two-level TLD as part of the base domain", () => {
  assert.equal(isSameSite("shop.example.co.kr", "blog.example.co.kr"), true);
  assert.equal(isSameSite("example.co.kr", "other.co.kr"), false);
});

test("uriMatches defaults to Domain matching when match is null/undefined", () => {
  assert.equal(uriMatches("https://example.test", null, "https://login.example.test/path"), true);
  assert.equal(uriMatches("https://example.test", undefined, "https://attacker.test"), false);
});

test("uriMatches Host requires the exact same hostname, not a subdomain", () => {
  assert.equal(uriMatches("https://example.test", URI_MATCH.HOST, "https://example.test/login"), true);
  assert.equal(uriMatches("https://example.test", URI_MATCH.HOST, "https://login.example.test"), false);
});

test("uriMatches StartsWith checks a literal prefix of the current URL", () => {
  assert.equal(uriMatches("https://example.test/app", URI_MATCH.STARTS_WITH, "https://example.test/app/login"), true);
  assert.equal(uriMatches("https://example.test/app", URI_MATCH.STARTS_WITH, "https://example.test/other"), false);
});

test("uriMatches Exact requires the full URL to be identical", () => {
  assert.equal(uriMatches("https://example.test/login", URI_MATCH.EXACT, "https://example.test/login"), true);
  assert.equal(uriMatches("https://example.test/login", URI_MATCH.EXACT, "https://example.test/login?x=1"), false);
});

test("uriMatches RegularExpression tests the saved value as a regex against the current URL", () => {
  assert.equal(uriMatches("^https://[a-z]+\\.example\\.test/", URI_MATCH.REGULAR_EXPRESSION, "https://app.example.test/x"), true);
  assert.equal(uriMatches("^https://[a-z]+\\.example\\.test/", URI_MATCH.REGULAR_EXPRESSION, "https://example.test/x"), false);
});

test("uriMatches RegularExpression fails closed (no match) on an invalid pattern instead of throwing", () => {
  assert.equal(uriMatches("(unterminated", URI_MATCH.REGULAR_EXPRESSION, "https://example.test"), false);
});

test("uriMatches Never always refuses, even for an identical URL", () => {
  assert.equal(uriMatches("https://example.test", URI_MATCH.NEVER, "https://example.test"), false);
});

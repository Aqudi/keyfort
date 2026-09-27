// Regression tests for src/lib/duplicates.js: grouping login items that look like the
// same account, for the options page's duplicate-cleanup UI.
import { test } from "node:test";
import assert from "node:assert/strict";
import { findDuplicateGroups } from "../src/lib/duplicates.js";

const item = (id, username, uri, extra = {}) => ({
  id,
  name: id,
  username,
  hasTotp: false,
  lastUsedAt: null,
  uris: [{ uri, match: null }],
  ...extra,
});

test("groups two items with the same username and the same site", () => {
  const groups = findDuplicateGroups([
    item("1", "me@example.test", "https://example.test"),
    item("2", "me@example.test", "https://login.example.test"), // 서브도메인이라도 같은 사이트
  ]);
  assert.equal(groups.length, 1);
  assert.deepEqual(groups[0].map((i) => i.id).sort(), ["1", "2"]);
});

test("does not group items with different usernames", () => {
  const groups = findDuplicateGroups([item("1", "me@example.test", "https://example.test"), item("2", "you@example.test", "https://example.test")]);
  assert.deepEqual(groups, []);
});

test("does not group items on unrelated sites even with the same username", () => {
  const groups = findDuplicateGroups([item("1", "me@example.test", "https://example.test"), item("2", "me@example.test", "https://other.test")]);
  assert.deepEqual(groups, []);
});

test("groups three-or-more items sharing an account into a single group", () => {
  const groups = findDuplicateGroups([
    item("1", "me@example.test", "https://example.test"),
    item("2", "me@example.test", "https://example.test"),
    item("3", "me@example.test", "https://example.test"),
  ]);
  assert.equal(groups.length, 1);
  assert.equal(groups[0].length, 3);
});

test("items without a username are never grouped", () => {
  const groups = findDuplicateGroups([item("1", null, "https://example.test"), item("2", null, "https://example.test")]);
  assert.deepEqual(groups, []);
});

test("username comparison is case-insensitive", () => {
  const groups = findDuplicateGroups([item("1", "Me@Example.test", "https://example.test"), item("2", "me@example.test", "https://example.test")]);
  assert.equal(groups.length, 1);
});

test("a single item, or an empty list, produces no groups", () => {
  assert.deepEqual(findDuplicateGroups([]), []);
  assert.deepEqual(findDuplicateGroups([item("1", "me@example.test", "https://example.test")]), []);
});

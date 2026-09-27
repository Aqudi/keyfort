// src/lib/duplicates.js - groups saved login items that look like the same account
// (same username + same base domain) so the options page can offer to clean them up.
import { isSameSite, uriHostname } from "./site.js";

// 저장된 항목끼리 비교하는 거라 URI별 match 값(Never 등, "지금 이 페이지에 채울지")은 상관없다 —
// "같은 사이트 계정인지"만 본다.
function isDuplicatePair(a, b) {
  if (!a.username || !b.username || a.username.toLowerCase() !== b.username.toLowerCase()) return false;
  return a.uris.some((ua) => b.uris.some((ub) => isSameSite(uriHostname(ua.uri), uriHostname(ub.uri))));
}

export function findDuplicateGroups(items) {
  const used = new Set();
  const groups = [];
  for (let i = 0; i < items.length; i++) {
    if (used.has(items[i].id)) continue;
    const group = [items[i]];
    for (let j = i + 1; j < items.length; j++) {
      if (!used.has(items[j].id) && isDuplicatePair(items[i], items[j])) {
        group.push(items[j]);
        used.add(items[j].id);
      }
    }
    if (group.length > 1) {
      used.add(items[i].id);
      groups.push(group);
    }
  }
  return groups;
}

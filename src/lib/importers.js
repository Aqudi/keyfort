// src/lib/importers.js - Chrome/Arc/Edge/Brave(Chromium 공통 내보내기 포맷)와 1Password CSV export를
// 같은 형태로 정규화한다. 헤더 이름만 다르고 내용은 사실상 같아서 브랜드별 파서를 따로 안 둔다.
const FIELD_ALIASES = {
  name: ["name", "title"],
  url: ["url", "website", "login_uri"],
  username: ["username", "login_username"],
  password: ["password", "login_password"],
  notes: ["note", "notes", "extra"],
  otpauth: ["otpauth", "otp_auth", "totp"],
};

function pick(row, aliases) {
  for (const key of aliases) {
    if (row[key]) return row[key];
  }
  return "";
}

// url/password가 없는 행은 로그인 항목으로 의미가 없어 버린다(예: 카드/신원 등 다른 타입이 섞인 export).
export function normalizeImportRows(rows) {
  return rows
    .map((row) => ({
      name: pick(row, FIELD_ALIASES.name),
      url: pick(row, FIELD_ALIASES.url),
      username: pick(row, FIELD_ALIASES.username),
      password: pick(row, FIELD_ALIASES.password),
      notes: pick(row, FIELD_ALIASES.notes),
      otpauth: pick(row, FIELD_ALIASES.otpauth),
    }))
    .filter((e) => e.url && e.password);
}

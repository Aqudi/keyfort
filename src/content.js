// src/content.js - detects login forms and performs autofill on request.

function findLoginFields() {
  const passwordInputs = Array.from(
    document.querySelectorAll('input[type="password"]')
  ).filter((el) => el.offsetParent !== null);

  if (passwordInputs.length === 0) return null;
  const passwordInput = passwordInputs[0];

  // find a plausible username/email field: any text/email input before the
  // password field within the same form, or the closest preceding one on page.
  const form = passwordInput.closest("form");
  const scope = form || document;
  const candidates = Array.from(
    scope.querySelectorAll(
      'input[type="text"], input[type="email"], input:not([type])'
    )
  ).filter((el) => el.offsetParent !== null);

  let usernameInput = null;
  if (candidates.length > 0) {
    // Prefer one that appears before the password field in the DOM.
    const pwIndex = candidates.length;
    usernameInput =
      candidates.find((el) => {
        const pos = el.compareDocumentPosition(passwordInput);
        return !!(pos & Node.DOCUMENT_POSITION_FOLLOWING);
      }) || candidates[0];
  }

  return { usernameInput, passwordInput };
}

function setNativeValue(input, value) {
  const proto = Object.getPrototypeOf(input);
  const desc = Object.getOwnPropertyDescriptor(proto, "value");
  if (desc && desc.set) {
    desc.set.call(input, value);
  } else {
    input.value = value;
  }
  input.dispatchEvent(new Event("input", { bubbles: true }));
  input.dispatchEvent(new Event("change", { bubbles: true }));
}

chrome.runtime.onMessage.addListener((msg, sender, sendResponse) => {
  if (msg.type === "DO_AUTOFILL") {
    const fields = findLoginFields();
    if (!fields) {
      sendResponse({ ok: false, error: "로그인 폼을 찾지 못했습니다." });
      return;
    }
    if (fields.usernameInput && msg.username) {
      setNativeValue(fields.usernameInput, msg.username);
    }
    if (fields.passwordInput && msg.password) {
      setNativeValue(fields.passwordInput, msg.password);
    }
    sendResponse({ ok: true });
  }
  return true;
});

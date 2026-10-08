// The page functions. The service worker runs them in the top frame of a tab
// with chrome.scripting.executeScript, which sends only the source text of one
// function. So each must not use anything from outside its own body, and the
// two share no helper: readLogin repeats the field choice of fillLogin.

// Fills a login. It returns only booleans, a count, and a reason, never a
// value.
//
// mode "login" (the default): one username field and one password field.
// mode "new": a new password from Apassy. It fills each password field that is
// not autocomplete=current-password (a sign-up form asks twice), and the
// username field before the first of them. A page with no such field gets
// nothing.

/* exported fillLogin */
function fillLogin(origin, username, password, mode) {
  const isNew = mode === "new";
  if (location.origin !== origin) {
    const refused = { ok: false, reason: "origin", username: false, password: false };
    if (isNew) refused.passwords = 0;
    return refused;
  }

  const TEXT_TYPES = ["text", "email", "tel"];
  const USER_WORDS = /user|e-?mail|login|account|identifier|sign-?in/i;
  // A password field that a "show password" button turned into a text field.
  const PASSWORD_WORDS = /pass|pwd|secret/i;
  const passwordLike = (el) => PASSWORD_WORDS.test([
    el.name, el.id, el.getAttribute("autocomplete"), el.getAttribute("aria-label"), el.placeholder,
  ].filter(Boolean).join(" "));
  const valueSetter = Object.getOwnPropertyDescriptor(HTMLInputElement.prototype, "value").set;

  // Every input of the document and of its open shadow roots, in page order.
  function allInputs(root, out) {
    for (const el of root.querySelectorAll("*")) {
      if (el instanceof HTMLInputElement) out.push(el);
      if (el.shadowRoot) allInputs(el.shadowRoot, out);
    }
    return out;
  }

  function usable(el) {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    if (typeof el.checkVisibility === "function" &&
        !el.checkVisibility({ visibilityProperty: true })) return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  }

  function tokens(el) {
    return (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
  }

  function hasToken(el, ...names) {
    const list = tokens(el);
    return names.some((name) => list.includes(name));
  }

  function namedLikeUser(el) {
    const words = [
      el.name, el.id, el.getAttribute("aria-label"), el.placeholder,
    ].filter(Boolean).join(" ");
    return USER_WORDS.test(words);
  }

  function before(a, b) {
    return Boolean(b.compareDocumentPosition(a) & Node.DOCUMENT_POSITION_PRECEDING);
  }

  function pickPassword(inputs) {
    const fields = inputs.filter((el) => el.type === "password");
    if (fields.length === 0) return null;
    const current = fields.find((el) => hasToken(el, "current-password"));
    if (current) return current;
    const notNew = fields.filter((el) => !hasToken(el, "new-password"));
    return notNew[0] || fields[0];
  }

  // The nearest text field before the password field, in the same form, or in
  // the same document or shadow root when the form has none.
  function pickUsernameNear(inputs, passwordField) {
    const form = passwordField.form;
    const root = passwordField.getRootNode();
    const earlier = inputs.filter((el) =>
      TEXT_TYPES.includes(el.type) && !passwordLike(el) && before(el, passwordField));
    let candidates = form ? earlier.filter((el) => el.form === form) : [];
    if (candidates.length === 0) {
      candidates = earlier.filter((el) => el.getRootNode() === root);
    }
    const strong = candidates.filter((el) => hasToken(el, "username", "email"));
    if (strong.length) return strong[strong.length - 1];
    const named = candidates.filter(namedLikeUser);
    if (named.length) return named[named.length - 1];
    return candidates[candidates.length - 1] || null;
  }

  // A first step of a login that asks only for the username.
  function pickUsernameAlone(inputs) {
    const text = inputs.filter((el) => TEXT_TYPES.includes(el.type) && !passwordLike(el));
    return text.find((el) => hasToken(el, "username", "email")) ||
      text.find((el) => el.type === "email") ||
      text.find((el) => USER_WORDS.test([el.name, el.id].filter(Boolean).join(" "))) ||
      null;
  }

  function put(el, value) {
    el.focus();
    valueSetter.call(el, value);
    el.dispatchEvent(new Event("input", { bubbles: true, composed: true }));
    el.dispatchEvent(new Event("change", { bubbles: true, composed: true }));
  }

  const inputs = allInputs(document, []).filter(usable);
  let passwordFields;
  if (isNew) {
    passwordFields = inputs.filter((el) =>
      el.type === "password" && !hasToken(el, "current-password"));
  } else {
    const one = pickPassword(inputs);
    passwordFields = one ? [one] : [];
  }
  let usernameField = null;
  if (passwordFields.length) {
    usernameField = pickUsernameNear(inputs, passwordFields[0]);
  } else if (!isNew) {
    usernameField = pickUsernameAlone(inputs);
  }

  const result = { ok: false, reason: "no_fields", username: false, password: false };
  if (isNew) result.passwords = 0;
  if (usernameField && username) {
    put(usernameField, username);
    result.username = true;
  }
  if (password) {
    for (const field of passwordFields) {
      put(field, password);
      result.password = true;
      if (isNew) result.passwords += 1;
    }
  }
  if (result.username || result.password) {
    result.ok = true;
    result.reason = "";
  }
  username = "";
  password = "";
  return result;
}

// Reads the login that the owner typed on the page: the same username field
// and the same password field that fillLogin picks in mode "login". It returns
// the typed password only when includePassword is true; the service worker
// asks for it only to send "save" to Apassy, never for the popup.
//
// passwordFields counts the usable password fields, newPasswordFields those
// that fillLogin fills in mode "new" (not autocomplete=current-password).

/* exported readLogin */
function readLogin(origin, includePassword) {
  const result = {
    ok: false, reason: "origin", username: "", hasPassword: false,
    passwordFields: 0, newPasswordFields: 0,
  };
  if (location.origin !== origin) return result;

  const TEXT_TYPES = ["text", "email", "tel"];
  const USER_WORDS = /user|e-?mail|login|account|identifier|sign-?in/i;
  // A password field that a "show password" button turned into a text field.
  const PASSWORD_WORDS = /pass|pwd|secret/i;
  const passwordLike = (el) => PASSWORD_WORDS.test([
    el.name, el.id, el.getAttribute("autocomplete"), el.getAttribute("aria-label"), el.placeholder,
  ].filter(Boolean).join(" "));

  function allInputs(root, out) {
    for (const el of root.querySelectorAll("*")) {
      if (el instanceof HTMLInputElement) out.push(el);
      if (el.shadowRoot) allInputs(el.shadowRoot, out);
    }
    return out;
  }

  function usable(el) {
    if (el.disabled || el.readOnly || el.type === "hidden") return false;
    if (typeof el.checkVisibility === "function" &&
        !el.checkVisibility({ visibilityProperty: true })) return false;
    const box = el.getBoundingClientRect();
    return box.width > 0 && box.height > 0;
  }

  function hasToken(el, ...names) {
    const list = (el.getAttribute("autocomplete") || "").toLowerCase().split(/\s+/);
    return names.some((name) => list.includes(name));
  }

  function namedLikeUser(el) {
    const words = [
      el.name, el.id, el.getAttribute("aria-label"), el.placeholder,
    ].filter(Boolean).join(" ");
    return USER_WORDS.test(words);
  }

  function before(a, b) {
    return Boolean(b.compareDocumentPosition(a) & Node.DOCUMENT_POSITION_PRECEDING);
  }

  function pickPassword(fields) {
    if (fields.length === 0) return null;
    const current = fields.find((el) => hasToken(el, "current-password"));
    if (current) return current;
    const notNew = fields.filter((el) => !hasToken(el, "new-password"));
    return notNew[0] || fields[0];
  }

  function pickUsernameNear(inputs, passwordField) {
    const form = passwordField.form;
    const root = passwordField.getRootNode();
    const earlier = inputs.filter((el) =>
      TEXT_TYPES.includes(el.type) && !passwordLike(el) && before(el, passwordField));
    let candidates = form ? earlier.filter((el) => el.form === form) : [];
    if (candidates.length === 0) {
      candidates = earlier.filter((el) => el.getRootNode() === root);
    }
    const strong = candidates.filter((el) => hasToken(el, "username", "email"));
    if (strong.length) return strong[strong.length - 1];
    const named = candidates.filter(namedLikeUser);
    if (named.length) return named[named.length - 1];
    return candidates[candidates.length - 1] || null;
  }

  function pickUsernameAlone(inputs) {
    const text = inputs.filter((el) => TEXT_TYPES.includes(el.type) && !passwordLike(el));
    return text.find((el) => hasToken(el, "username", "email")) ||
      text.find((el) => el.type === "email") ||
      text.find((el) => USER_WORDS.test([el.name, el.id].filter(Boolean).join(" "))) ||
      null;
  }

  const inputs = allInputs(document, []).filter(usable);
  const passwords = inputs.filter((el) => el.type === "password");
  const passwordField = pickPassword(passwords);
  const usernameField = passwordField
    ? pickUsernameNear(inputs, passwordField)
    : pickUsernameAlone(inputs);

  result.ok = true;
  result.reason = "";
  result.username = usernameField ? usernameField.value : "";
  result.hasPassword = Boolean(passwordField && passwordField.value);
  result.passwordFields = passwords.length;
  result.newPasswordFields = passwords.filter((el) => !hasToken(el, "current-password")).length;
  if (includePassword === true) {
    result.password = passwordField ? passwordField.value : "";
  }
  return result;
}

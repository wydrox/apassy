// The popup: shows the logins of the page and asks the service worker to fill
// one, to save the login typed on the page, or to make a new one. It never
// receives a password, and never a one-time code: "Fill code" only names the
// login; the service worker puts the code into the page.
//
// The footer turns Apassy passkeys on or off for this browser. On asks the
// browser for site access (https sites, and localhost for a local test site),
// which only a click of the owner can do.

const main = document.getElementById("main");
const site = document.getElementById("site");

const NEW_LENGTH = { min: 12, max: 64, standard: 20 };
const NO_PASSWORD = "Type your password on the page first.";
const NO_NEW_FIELD = "This page has no field for a new password.";

let current = null;
// What Escape does in the current view, or null.
let onEscape = null;
// Counts the views, so that a late answer does not draw over a newer view.
let view = 0;

function send(message) {
  return chrome.runtime.sendMessage(message).catch(() => ({
    ok: false, code: "host_failed", message: "Apassy did not answer. Try again.",
  }));
}

function element(tag, className, text) {
  const node = document.createElement(tag);
  if (className) node.className = className;
  if (text !== undefined) node.textContent = text;
  return node;
}

function note(text, isError) {
  const node = element("p", isError ? "note error" : "note", text);
  node.id = "note";
  return node;
}

function show(...nodes) {
  view += 1;
  main.replaceChildren(...nodes);
  main.dataset.state = current ? current.state : "";
}

function renderState(reply) {
  current = reply;
  onEscape = null;
  site.textContent = reply.host || "";
  switch (reply.state) {
    case "host_missing": {
      const command = element("code", "command", "apassy setup browser");
      command.id = "command";
      const how = element("p", "note", "In Apassy, open Settings > General > Browser extension and click Connect. Or run in Terminal:");
      show(note(reply.message), how, command);
      break;
    }
    case "none_open":
    case "vault_locked": {
      const button = element("button", "action", "Open Apassy");
      button.id = "open";
      button.addEventListener("click", async () => {
        button.disabled = true;
        await send({ type: "show" });
        window.close();
      });
      show(note(reply.message), button);
      button.focus();
      break;
    }
    case "empty":
      show(note(`No login for ${reply.host}. Add a detail named Website with this address to a login in Apassy.`), actions());
      break;
    case "list":
      renderList();
      break;
    default:
      show(note(reply.message, !["not_running", "unsupported_page", "no_page"].includes(reply.state)));
  }
}

function renderList(message, isError) {
  const list = element("ul");
  list.id = "logins";
  list.setAttribute("aria-label", "Logins");
  for (const login of current.logins) {
    const button = element("button", "login");
    button.type = "button";
    button.dataset.item = String(login.item);
    button.append(element("span", "title", login.title || "Login"));
    if (login.username) button.append(element("span", "username", login.username));
    button.addEventListener("click", () => fill(login));
    const row = element("li");
    row.append(button);
    if (login.hasTotp === true) {
      const code = element("button", "code", "Fill code");
      code.type = "button";
      code.dataset.item = String(login.item);
      code.setAttribute("aria-label", `Fill the one-time code of ${login.title || "Login"}`);
      code.addEventListener("click", () => fillCode(login));
      row.classList.add("with-code");
      row.append(code);
    }
    list.append(row);
  }
  list.addEventListener("keydown", moveFocus);
  onEscape = null;
  show(...(message ? [note(message, isError)] : []), list, actions());
  const first = list.querySelector("button");
  if (first) first.focus();
}

function moveFocus(event) {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  const rows = [...main.querySelectorAll("button.login")];
  if (rows.length === 0) return;
  const at = rows.indexOf(document.activeElement);
  const step = event.key === "ArrowDown" ? 1 : -1;
  const next = at < 0 ? 0 : (at + step + rows.length) % rows.length;
  rows[next].focus();
  event.preventDefault();
}

async function fill(login) {
  if (!current || main.dataset.busy === "1") return;
  main.dataset.busy = "1";
  show(note("Confirm with Touch ID or your passphrase in Apassy."));
  const result = await send({ type: "fill", tabId: current.tabId, url: current.url, item: login.item });
  delete main.dataset.busy;
  if (result && result.ok) {
    show(note(result.message || "Filled."));
  } else {
    renderList((result && result.message) || "Apassy could not fill this page.", true);
  }
}

// The service worker asks Apassy for the code and fills it into the page. The
// popup gets a code and a message, never the one-time code.
async function fillCode(login) {
  if (!current || main.dataset.busy === "1") return;
  main.dataset.busy = "1";
  show(note("Confirm with Touch ID or your passphrase in Apassy."));
  const result = await send({ type: "fill_code", tabId: current.tabId, url: current.url, item: login.item });
  delete main.dataset.busy;
  if (result && result.ok) {
    show(note(result.message || "Code filled."));
  } else {
    renderList((result && result.message) || "Apassy could not fill the code.", true);
  }
}

// "Save this login" and "New password", under the list.
function actions() {
  const row = element("div", "actions");
  const save = element("button", "secondary", "Save this login");
  save.type = "button";
  save.id = "save-open";
  save.addEventListener("click", () => openForm(renderSave));
  const create = element("button", "secondary", "New password");
  create.type = "button";
  create.id = "new-open";
  create.addEventListener("click", () => openForm(renderNew));
  row.append(save, create);
  return row;
}

function backLink(refresh) {
  const link = element("button", "link", "Back");
  link.type = "button";
  link.id = "back";
  link.addEventListener("click", () => goBack(refresh));
  return link;
}

// Back to the list. After a new login, ask Apassy again, so that it shows.
function goBack(refresh) {
  if (main.dataset.busy === "1") return;
  if (refresh) {
    current = null;
    onEscape = null;
    show(note("Asking Apassy…"));
    send({ type: "state" }).then(renderState);
  } else if (current) {
    renderState(current);
  }
}

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape" || !onEscape || main.dataset.busy === "1") return;
  event.preventDefault();
  onEscape();
});

function textField(id, label, value) {
  const wrap = element("label", "field");
  const box = element("input");
  box.type = "text";
  box.id = id;
  box.value = value;
  box.autocomplete = "off";
  box.spellcheck = false;
  wrap.append(element("span", "label", label), box);
  return { wrap, box };
}

function clampLength(raw) {
  const text = String(raw).trim();
  const number = Math.round(Number(text));
  if (!text || !Number.isFinite(number)) return NEW_LENGTH.standard;
  return Math.min(NEW_LENGTH.max, Math.max(NEW_LENGTH.min, number));
}

// Reads the page (the typed username, and whether it has a password), then
// draws one of the two forms.
async function openForm(render) {
  if (!current || main.dataset.busy === "1") return;
  show(note("Reading the page…"), backLink());
  onEscape = () => goBack();
  const mine = view;
  const page = await send({ type: "peek", tabId: current.tabId, url: current.url });
  if (mine !== view) return;
  if (!page || !page.ok) {
    show(note((page && page.message) || "Apassy could not read this page.", true), backLink());
    return;
  }
  render(page, {
    title: current.host || "",
    username: String(page.username || "").trim(),
    length: NEW_LENGTH.standard,
    symbols: true,
  });
}

// One form view: the fields, a hint, the submit button, and Back.
function drawForm({ id, fields, hint, submit, message, isError, onSubmit }) {
  const form = element("form", "form");
  form.id = id;
  form.noValidate = true;
  const buttons = element("div", "buttons");
  buttons.append(submit, backLink());
  form.append(...fields, element("p", "hint", hint), buttons);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    if (!submit.disabled) onSubmit();
  });
  onEscape = () => goBack();
  show(...(message ? [note(message, isError)] : []), form);
  return form;
}

// Title and username are required.
const missing = (values) => !values.title.trim() || !values.username.trim();

function focusFirst(title, username, submit) {
  const empty = [title, username].find((box) => !box.value.trim());
  (empty || (submit.disabled ? title : submit)).focus();
}

function renderSave(page, values, message, isError) {
  const title = textField("title", "Title", values.title);
  const username = textField("username", "Username", values.username);
  const submit = element("button", "action", "Save");
  submit.type = "submit";
  submit.id = "save";
  if (!page.hasPassword) {
    submit.disabled = true;
    if (!message) {
      message = NO_PASSWORD;
      isError = true;
    }
  }
  const read = () => ({ ...values, title: title.box.value, username: username.box.value });
  drawForm({
    id: "save-form",
    fields: [title.wrap, username.wrap],
    hint: "The password comes from the page.",
    submit,
    message,
    isError,
    onSubmit: () => {
      const now = read();
      if (missing(now)) renderSave(page, now, "Enter a title and a username.", true);
      else submitSave(page, now);
    },
  });
  focusFirst(title.box, username.box, submit);
}

async function submitSave(page, values) {
  if (!current || main.dataset.busy === "1") return;
  main.dataset.busy = "1";
  show(note("Confirm in Apassy."));
  const result = await send({
    type: "save",
    tabId: current.tabId,
    url: current.url,
    title: values.title.trim(),
    username: values.username.trim(),
  });
  delete main.dataset.busy;
  if (result && result.ok) {
    show(note(result.message || "Saved."), backLink(true));
    onEscape = () => goBack(true);
    document.getElementById("back").focus();
  } else if (result && result.code === "no_password") {
    renderSave({ ...page, hasPassword: false }, values);
  } else {
    renderSave(page, values, (result && result.message) || "Apassy could not save this login.", true);
  }
}

function renderNew(page, values, message, isError) {
  const title = textField("title", "Title", values.title);
  const username = textField("username", "Username", values.username);

  const lengthWrap = element("label", "field length");
  const length = element("input");
  length.type = "number";
  length.id = "length";
  length.min = String(NEW_LENGTH.min);
  length.max = String(NEW_LENGTH.max);
  length.step = "1";
  length.value = String(values.length);
  length.addEventListener("change", () => { length.value = String(clampLength(length.value)); });
  lengthWrap.append(element("span", "label", "Length"), length);

  const symbolsWrap = element("label", "check");
  const symbols = element("input");
  symbols.type = "checkbox";
  symbols.id = "symbols";
  symbols.checked = values.symbols;
  symbolsWrap.append(symbols, element("span", "", "Use symbols"));

  const row = element("div", "row");
  row.append(lengthWrap, symbolsWrap);

  const submit = element("button", "action", "Create and fill");
  submit.type = "submit";
  submit.id = "create";
  if (!page.newPasswordFields) {
    submit.disabled = true;
    if (!message) {
      message = NO_NEW_FIELD;
      isError = true;
    }
  }
  const read = () => ({
    title: title.box.value,
    username: username.box.value,
    length: clampLength(length.value),
    symbols: symbols.checked,
  });
  drawForm({
    id: "new-form",
    fields: [title.wrap, username.wrap, row],
    hint: "Apassy makes the password and keeps it before the page gets it.",
    submit,
    message,
    isError,
    onSubmit: () => {
      const now = read();
      if (missing(now)) renderNew(page, now, "Enter a title and a username.", true);
      else submitNew(page, now);
    },
  });
  focusFirst(title.box, username.box, submit);
}

async function submitNew(page, values) {
  if (!current || main.dataset.busy === "1") return;
  main.dataset.busy = "1";
  show(note("Confirm with Touch ID or your passphrase in Apassy."));
  const result = await send({
    type: "create",
    tabId: current.tabId,
    url: current.url,
    title: values.title.trim(),
    username: values.username.trim(),
    length: values.length,
    symbols: values.symbols,
  });
  delete main.dataset.busy;
  if (result && (result.ok || Number.isInteger(result.item))) {
    // The login is in Apassy, even when the page did not get it: do not
    // offer to make it again.
    show(note(result.message, !result.ok), backLink(true));
    onEscape = () => goBack(true);
    document.getElementById("back").focus();
  } else {
    renderNew(page, values, (result && result.message) || "Apassy could not make the login.", true);
  }
}

// The origins of the passkey scripts: optional_host_permissions of the manifest.
const PASSKEY_ORIGINS = chrome.runtime.getManifest().optional_host_permissions || [];
const passkeysRow = document.getElementById("passkeys-row");
const passkeysBox = document.getElementById("passkeys");
const passkeysNote = document.getElementById("passkeys-note");

function drawPasskeys(reply) {
  const on = Boolean(reply && reply.on === true);
  passkeysBox.checked = on;
  passkeysBox.disabled = false;
  passkeysNote.textContent = reply && reply.ok === false
    ? reply.message
    : on
      ? "Sites ask Apassy for passkeys. Each use asks for Touch ID or your passphrase."
      : "Off: sites use the passkeys of the browser.";
  passkeysNote.classList.toggle("error", Boolean(reply && reply.ok === false));
}

passkeysBox.addEventListener("change", async () => {
  passkeysBox.disabled = true;
  if (passkeysBox.checked) {
    // The browser shows its prompt only for a click of the owner, so ask
    // first; then tell the service worker, which waits for the grant even
    // when the prompt closes this popup.
    const asking = chrome.permissions.request({ origins: PASSKEY_ORIGINS });
    send({ type: "passkeys", on: true });
    let granted = false;
    try {
      granted = await asking;
    } catch (_) {
      granted = false;
    }
    drawPasskeys(await send(granted ? { type: "passkeys", on: true } : { type: "passkeys_state" }));
  } else {
    const reply = await send({ type: "passkeys", on: false });
    try {
      await chrome.permissions.remove({ origins: PASSKEY_ORIGINS });
    } catch (_) { /* already removed */ }
    drawPasskeys(reply);
  }
});

send({ type: "passkeys_state" }).then((reply) => {
  drawPasskeys(reply);
  passkeysRow.hidden = false;
});

send({ type: "state" }).then(renderState);

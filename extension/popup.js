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
    ok: false,
    code: "host_failed",
    message: "Apassy did not answer. Try again.",
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
  document.getElementById("connection").textContent = [
    "host_missing",
    "host_failed",
    "not_running",
  ].includes(reply.state)
    ? "Not connected"
    : "Connected to your Mac";
  switch (reply.state) {
    case "host_missing": {
      const command = element("code", "command", "apassy setup browser");
      command.id = "command";
      const how = element(
        "p",
        "note",
        "In Apassy, open Settings > Tools > Browser extension and click Connect. Or run in Terminal:",
      );
      show(
        element("h2", "", "Connect Apassy"),
        note(reply.message),
        how,
        command,
      );
      break;
    }
    case "not_running":
    case "none_open":
    case "vault_locked": {
      const button = element("button", "action", "Open Apassy");
      button.id = "open";
      button.addEventListener("click", async () => {
        button.disabled = true;
        const result = await send({ type: "show" });
        button.disabled = false;
        if (result.ok)
          show(
            note(
              "Apassy was asked to open. Return after opening or unlocking your vault, then choose an account to fill.",
            ),
            backLink(true),
          );
        else
          show(
            note(
              result.message ||
                "Apassy could not open. Open it from Applications, then return here.",
              true,
            ),
            backLink(true),
          );
      });
      show(
        element(
          "h2",
          "",
          reply.state === "vault_locked"
            ? "Your vault is locked"
            : "Open Apassy on your Mac",
        ),
        note(reply.message),
        button,
      );
      button.focus();
      break;
    }
    case "empty":
      show(
        element("h2", "", `No logins for ${reply.host}`),
        note(
          "Save the login you entered on this page, or create a password for a new account.",
        ),
        actions(),
        element(
          "p",
          "hint",
          "Already saved? A missing Website field prevents matching. Open the login in Apassy and add this site's address.",
        ),
      );
      break;
    case "list":
      renderList();
      break;
    case "host_failed":
    case "timeout": {
      const retry = element("button", "action", "Try again");
      retry.addEventListener("click", () => goBack(true));
      show(
        element("h2", "", "Apassy did not answer"),
        note(reply.message, true),
        retry,
      );
      break;
    }
    default:
      show(
        note(
          reply.message,
          !["not_running", "unsupported_page", "no_page"].includes(reply.state),
        ),
      );
  }
}

function renderList(message, isError) {
  if (!message && current.recent) {
    message = current.recent.message;
    isError = !current.recent.ok;
  }
  const list = element("ul");
  list.id = "logins";
  list.setAttribute("aria-label", "Logins");
  for (const login of current.logins) {
    const button = element("button", "login");
    button.type = "button";
    button.dataset.item = String(login.item);
    const identity = element("span", "identity");
    identity.append(
      element("span", "title", login.title || "Login"),
      element("span", "username", login.username),
    );
    button.append(
      element("span", "mark", (login.title || "L").slice(0, 1).toUpperCase()),
      identity,
      element("span", "fill-label", "Fill"),
    );
    button.title = `${login.title || "Login"} · ${login.username}`;
    button.addEventListener("click", (event) => fill(login, event));
    const row = element("li");
    row.append(button);
    const details = element("button", "details", "…");
    details.type = "button";
    details.setAttribute("aria-label", `Details for ${login.title || "Login"}`);
    details.addEventListener("click", () => renderDetails(login));
    row.append(details);
    list.append(row);
  }
  const search = element("input");
  search.type = "search";
  search.placeholder = "Find an account for this site";
  search.setAttribute("aria-label", "Find an account for this site");
  const count = element(
    "p",
    "count",
    `${current.logins.length} accounts for this site`,
  );
  search.addEventListener("input", () => {
    let visible = 0;
    [...list.children].forEach((row, i) => {
      const login = current.logins[i];
      row.hidden = !`${login.title} ${login.username}`
        .toLowerCase()
        .includes(search.value.trim().toLowerCase());
      if (!row.hidden) visible++;
    });
    count.textContent = visible
      ? `${visible} accounts for this site`
      : "No account matches your search";
  });
  list.addEventListener("keydown", moveFocus);
  onEscape = null;
  show(
    ...(message ? [note(message, isError)] : []),
    search,
    count,
    list,
    element("p", "hint", "Choose an account, then approve on your Mac."),
    actions(),
  );
  const first = list.querySelector("button");
  if (first) first.focus();
}

function moveFocus(event) {
  if (event.key !== "ArrowDown" && event.key !== "ArrowUp") return;
  const rows = [...main.querySelectorAll("#logins li:not([hidden]) button.login")];
  if (rows.length === 0) return;
  const at = rows.indexOf(document.activeElement);
  const step = event.key === "ArrowDown" ? 1 : -1;
  const next = at < 0 ? 0 : (at + step + rows.length) % rows.length;
  rows[next].focus();
  event.preventDefault();
}

function accountContext(login) {
  const box = element("div", "context");
  box.append(
    element("strong", "", current.host || ""),
    element("span", "", `${login.title || "Login"} · ${login.username || ""}`),
  );
  return box;
}
function renderDetails(login) {
  const update = element("button", "secondary update-login", "Update login");
  update.addEventListener("click", () =>
    openForm((page) => renderUpdate(page, login), "update"),
  );
  const buttons = element("div", "buttons");
  buttons.append(update);
  if (login.hasTotp) {
    const code = element("button", "code", "Fill code");
    code.dataset.item = String(login.item);
    code.addEventListener("click", (e) => fillCode(login, e));
    buttons.append(code);
  }
  show(
    element("h2", "", "Account details"),
    accountContext(login),
    buttons,
    backLink(),
  );
  onEscape = () => goBack();
}
// All popup fill/save/create/update triggers pass through this trusted-gesture gate.
async function ownerAction(event, message, login) {
  if (!event?.isTrusted || !current || main.dataset.busy === "1") return null;
  main.dataset.busy = "1";
  const open = element("button", "secondary", "Show Apassy");
  open.addEventListener("click", () => send({ type: "show" }));
  show(
    element("h2", "", "Check Touch ID on your Mac"),
    accountContext(login),
    note("Approve in Apassy, or use your vault passphrase if asked."),
    element("p", "hint", "Nothing has been filled yet."),
    open,
  );
  try {
    return await send({
      tabId: current.tabId,
      url: current.url,
      target: current.target,
      ...message,
      trustedGesture: true,
    });
  } finally {
    delete main.dataset.busy;
  }
}
async function fill(login, event) {
  const result = await ownerAction(
    event,
    { type: "fill", item: login.item },
    login,
  );
  if (!result) return;
  if (result.ok)
    show(
      element("h2", "success", "Login filled"),
      note(result.message || "Continue on this page."),
      backLink(),
    );
  else
    renderList(
      result.message || "Apassy could not fill this page.",
      !["cancelled"].includes(result.code),
    );
}
async function fillCode(login, event) {
  const result = await ownerAction(
    event,
    { type: "fill_code", item: login.item },
    login,
  );
  if (!result) return;
  if (result.ok)
    show(
      element("h2", "success", "Code filled"),
      note("Continue on this page."),
      backLink(),
    );
  else renderList(result.message || "Apassy could not fill the code.", true);
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
async function openForm(render, purpose = "login") {
  if (!current || main.dataset.busy === "1") return;
  show(note("Reading the page…"), backLink());
  onEscape = () => goBack();
  const mine = view;
  const page = await send({
    type: "peek",
    tabId: current.tabId,
    url: current.url,
    target: current.target,
    purpose,
  });
  if (mine !== view) return;
  if (!page || !page.ok) {
    show(
      note((page && page.message) || "Apassy could not read this page.", true),
      backLink(),
    );
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
  form.append(
    element("h2", "", id === "save-form" ? "Save this login" : "New login"),
    ...fields,
    element("p", "hint", hint),
    buttons,
  );
  // requestSubmit() creates a trusted submit event even without a user gesture.
  // Enter activates this button too; only its trusted click authorizes an action.
  submit.addEventListener("click", (event) => {
    event.preventDefault();
    if (event.isTrusted && !submit.disabled) onSubmit(event);
  });
  form.addEventListener("submit", (event) => event.preventDefault());
  onEscape = () => goBack();
  show(...(message ? [note(message, isError)] : []), form);
  return form;
}

// Title and username are required.
const missing = (values) => !values.title.trim() || !values.username.trim();
const missingMessage = (values) =>
  !values.title.trim() && !values.username.trim()
    ? "Enter a title and a username."
    : !values.title.trim()
      ? "Enter a title."
      : "Enter a username.";

function focusFirst(title, username, submit) {
  const empty = [title, username].find((box) => !box.value.trim());
  for (const box of [title, username]) {
    if (
      !box.value.trim() &&
      /^Enter /.test(document.getElementById("note")?.textContent || "")
    ) {
      box.setAttribute("aria-invalid", "true");
      box.setAttribute("aria-describedby", "note");
    }
  }
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
  const read = () => ({
    ...values,
    title: title.box.value,
    username: username.box.value,
  });
  drawForm({
    id: "save-form",
    fields: [title.wrap, username.wrap],
    hint: "Approve saving on your Mac. The password comes from the selected form on this page.",
    submit,
    message,
    isError,
    onSubmit: (event) => {
      const now = read();
      if (missing(now)) renderSave(page, now, missingMessage(now), true);
      else submitSave(page, now, event);
    },
  });
  focusFirst(title.box, username.box, submit);
}

async function submitSave(page, values, event) {
  const result = await ownerAction(
    event,
    {
      type: "save",
      title: values.title.trim(),
      username: values.username.trim(),
    },
    values,
  );
  if (!result) return;
  if (result && result.ok) {
    show(
      element("h2", "success", "Login saved"),
      accountContext(values),
      note(result.message || "Saved."),
      backLink(true),
    );
    onEscape = () => goBack(true);
    document.getElementById("back").focus();
  } else if (result && result.code === "no_password") {
    renderSave({ ...page, hasPassword: false }, values);
  } else {
    renderSave(
      page,
      values,
      (result && result.message) || "Apassy could not save this login.",
      true,
    );
  }
}

function renderUpdate(page, login) {
  const submit = element("button", "action", "Update this login");
  submit.type = "button";
  submit.disabled = !page.hasPassword;
  submit.addEventListener("click", async (event) => {
    const result = await ownerAction(
      event,
      { type: "update", item: login.item, username: login.username },
      login,
    );
    if (!result) return;
    // After an uncertain answer, require review in Apassy. Never retry or create a duplicate automatically.
    show(
      note(
        result.message || "Check this login in Apassy before trying again.",
        !result.ok,
      ),
      backLink(true),
    );
    onEscape = () => goBack(true);
  });
  const buttons = element("div", "buttons");
  buttons.append(submit, backLink());
  show(
    element("h2", "", "Update this login?"),
    accountContext(login),
    note(
      `Update the password for ${login.username} in ${login.title || "Login"}?`,
    ),
    element(
      "p",
      page.hasPassword ? "hint" : "note error",
      page.hasPassword
        ? "The password comes from the selected form on this page. Website, passkey and one-time code stay in Apassy."
        : NO_PASSWORD,
    ),
    buttons,
  );
  onEscape = () => goBack();
  submit.focus();
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
  length.addEventListener("change", () => {
    length.value = String(clampLength(length.value));
  });
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
    hint: "Approve on your Mac. Apassy saves the password before filling this page.",
    submit,
    message,
    isError,
    onSubmit: (event) => {
      const now = read();
      if (missing(now)) renderNew(page, now, missingMessage(now), true);
      else submitNew(page, now, event);
    },
  });
  focusFirst(title.box, username.box, submit);
}

async function submitNew(page, values, event) {
  const result = await ownerAction(
    event,
    {
      type: "create",
      title: values.title.trim(),
      username: values.username.trim(),
      length: values.length,
      symbols: values.symbols,
    },
    values,
  );
  if (!result) return;
  if (result && (result.ok || Number.isInteger(result.item))) {
    // The login is in Apassy, even when the page did not get it: do not
    // offer to make it again.
    show(
      element(
        "h2",
        result.ok ? "success" : "",
        result.ok ? "Login created" : "Login saved, page not filled",
      ),
      accountContext(values),
      note(result.message, !result.ok),
      backLink(true),
    );
    onEscape = () => goBack(true);
    document.getElementById("back").focus();
  } else {
    renderNew(
      page,
      values,
      (result && result.message) || "Apassy could not make the login.",
      true,
    );
  }
}

// The origins of the passkey scripts: optional_host_permissions of the manifest.
const PASSKEY_ORIGINS =
  chrome.runtime.getManifest().optional_host_permissions || [];
const passkeysRow = document.getElementById("passkeys-row");
const passkeysBox = document.getElementById("passkeys");
const passkeysNote = document.getElementById("passkeys-note");

function drawPasskeys(reply) {
  const on = Boolean(reply && reply.on === true);
  passkeysBox.checked = on;
  passkeysBox.disabled = false;
  passkeysNote.textContent =
    reply && reply.ok === false
      ? reply.message
      : on
        ? "Sites ask Apassy for passkeys. Each use asks for Touch ID or your passphrase."
        : "Off: sites use the passkeys of the browser.";
  passkeysNote.classList.toggle("error", Boolean(reply && reply.ok === false));
}

passkeysBox.addEventListener("click", async (event) => {
  if (!event.isTrusted) {
    event.preventDefault();
    return;
  }
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
    drawPasskeys(
      await send(
        granted ? { type: "passkeys", on: true } : { type: "passkeys_state" },
      ),
    );
  } else {
    const reply = await send({ type: "passkeys", on: false });
    // Site access can also serve the separately enabled login suggestions.
    // Turning off passkeys unregisters their scripts without revoking another feature's grant.
    drawPasskeys(reply);
  }
});

send({ type: "passkeys_state" }).then((reply) => {
  drawPasskeys(reply);
  passkeysRow.hidden = false;
});

send({ type: "state" }).then(renderState);

const suggestionsRow = document.getElementById("suggestions-row");
const suggestionsBox = document.getElementById("suggestions");
const suggestionsNote = document.getElementById("suggestions-note");
let suggestionsUrl = "",
  suggestionsSiteOff = false;
async function drawSuggestions() {
  const reply = await send({ type: "login_access_state" });
  suggestionsUrl = reply.url || "";
  suggestionsSiteOff = reply.siteOff;
  suggestionsBox.checked = reply.on === true;
  suggestionsBox.disabled = false;
  suggestionsRow.hidden = false;
  suggestionsNote.textContent = reply.on
    ? "Account metadata appears on sites with access. Every fill and save needs approval on your Mac."
    : "Off. Use the Apassy toolbar to fill a login.";
  document.getElementById("access-prompt").hidden = reply.broad || !reply.on;
  const siteToggle = document.getElementById("site-toggle");
  siteToggle.textContent = reply.siteOff
    ? "Suggest on this site again"
    : "Not on this site";
  siteToggle.hidden = !/^https:\/\/|^http:\/\/localhost(?::[0-9]+)?\//.test(
    suggestionsUrl,
  );
}
async function grantSites(event) {
  if (!event.isTrusted) return;
  // Call synchronously inside the user gesture; permission prompts can close the popup.
  const asking = chrome.permissions.request({ origins: PASSKEY_ORIGINS });
  if (await asking.catch(() => false)) {
    await send({ type: "login_access", on: true });
    await drawSuggestions();
  }
}
document.getElementById("allow-sites").addEventListener("click", grantSites);
suggestionsBox.addEventListener("click", async (event) => {
  if (!event.isTrusted) {
    event.preventDefault();
    return;
  }
  const on = suggestionsBox.checked;
  suggestionsBox.disabled = true;
  await send({ type: "login_access", on });
  await drawSuggestions();
});
document
  .getElementById("site-toggle")
  .addEventListener("click", async (event) => {
    if (!event.isTrusted) return;
    await send({
      type: "login_site",
      url: suggestionsUrl,
      on: suggestionsSiteOff,
    });
    await drawSuggestions();
  });
document.getElementById("settings-link").addEventListener("click", () => {
  if (main.dataset.busy === "1") return;
  const settings = document.getElementById("settings");
  settings.hidden = !settings.hidden;
  main.hidden = !settings.hidden;
  document.getElementById("settings-link").textContent = settings.hidden
    ? "Settings"
    : "Back to accounts";
});
drawSuggestions();

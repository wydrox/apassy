import {
  AMBIGUOUS_SAMPLE_TEXT,
  CATEGORIES,
  CONFLICTING_SAMPLE_TEXT,
  SAMPLE_RULE_TEXT,
  UNSUPPORTED_SAMPLE_TEXT,
  createWalkthrough,
} from "./model.mjs";

const wt = createWalkthrough();

const ui = {
  view: "vault",
  selectedItemId: null,
  pendingDeleteId: null,
  search: "",
};

const EXTRA_BY_CATEGORY = {
  api_key: [],
  login: ["username"],
  ssh_key: ["publicLabel"],
  database: ["username", "host", "databaseName"],
  custom: ["fieldName"],
};

const statusEl = document.getElementById("status");
const lockStateEl = document.getElementById("lock-state");
const categoryListsEl = document.getElementById("category-lists");
const itemDetailEl = document.getElementById("item-detail");
const supportedSampleEl = document.getElementById("supported-sample");
const draftStatusEl = document.getElementById("draft-status");
const draftOriginalEl = document.getElementById("draft-original");
const draftClausesEl = document.getElementById("draft-clauses");
const draftQuestionsEl = document.getElementById("draft-questions");
const draftExamplesEl = document.getElementById("draft-examples");
const activeRuleEl = document.getElementById("active-rule");
const agentListEl = document.getElementById("agent-list");
const inboxEl = document.getElementById("inbox");
const historyEl = document.getElementById("history");
const notificationHealthEl = document.getElementById("notification-health");
const ruleTextEl = document.getElementById("rule-text");
const itemSearchEl = document.getElementById("item-search");
const addCategoryEl = document.getElementById("add-category");

function el(tag, attrs = {}, children = []) {
  const node = document.createElement(tag);
  for (const [key, value] of Object.entries(attrs)) {
    if (value === null || value === undefined || value === false) continue;
    if (key === "className") node.className = value;
    else if (key === "text") node.textContent = value;
    else if (key === "htmlFor") node.htmlFor = value;
    else if (key === "checked" || key === "disabled" || key === "hidden") node[key] = value;
    else node.setAttribute(key, value === true ? "" : String(value));
  }
  for (const child of children) {
    if (child === null || child === undefined) continue;
    node.append(typeof child === "string" ? document.createTextNode(child) : child);
  }
  return node;
}

function setStatus(message, kind = "") {
  statusEl.textContent = message;
  statusEl.classList.remove("is-error", "is-ok");
  if (kind === "error") statusEl.classList.add("is-error");
  if (kind === "ok") statusEl.classList.add("is-ok");
}

function report(result, successMessage) {
  if (!result || result.ok === false) {
    setStatus(result?.error ?? "The action failed.", "error");
    return false;
  }
  if (successMessage) setStatus(successMessage, "ok");
  return true;
}

function showView(name) {
  ui.view = name;
  for (const panel of document.querySelectorAll("[data-view-panel]")) {
    panel.hidden = panel.getAttribute("data-view-panel") !== name;
  }
  for (const button of document.querySelectorAll(".nav-button")) {
    const current = button.getAttribute("data-view") === name;
    if (current) button.setAttribute("aria-current", "page");
    else button.removeAttribute("aria-current");
  }
  const heading = document.querySelector(`#view-${name} h1`);
  if (heading) heading.setAttribute("tabindex", "-1");
  render();
  if (heading) heading.focus();
}

function render() {
  renderLock();
  renderVault();
  renderItem();
  renderRules();
  renderAgents();
  renderActivity();
  syncExtraFields();
}

function renderLock() {
  const locked = wt.isLocked();
  lockStateEl.textContent = locked
    ? "The vault is locked. Item details are hidden. Pending demo authority is not valid."
    : "The vault is open. Open vault is not owner authentication.";
  document.getElementById("lock-button").disabled = locked;
  document.getElementById("unlock-button").disabled = !locked;
}

function renderVault() {
  const items = wt.listItems(ui.search);
  categoryListsEl.replaceChildren();
  for (const category of CATEGORIES) {
    const group = items.filter((item) => item.category === category.id);
    const list = el("ul", { className: "item-list" });
    if (group.length === 0) {
      list.append(el("li", { className: "empty", text: "No items in this category." }));
    } else {
      for (const item of group) {
        const open = el("button", { type: "button", className: "secondary", text: "Open item" });
        open.addEventListener("click", () => {
          ui.selectedItemId = item.id;
          ui.pendingDeleteId = null;
          showView("item");
        });
        list.append(
          el("li", { className: "item-row" }, [
            el("div", {}, [
              el("strong", { text: item.name }),
              el("p", {
                className: "item-meta",
                text: metaLine(item),
              }),
            ]),
            open,
          ]),
        );
      }
    }
    categoryListsEl.append(
      el("section", { className: "category-block" }, [
        el("h2", { text: category.label }),
        list,
      ]),
    );
  }
}

function metaLine(item) {
  const parts = [item.project, item.service].filter(Boolean);
  return parts.length > 0 ? parts.join(" · ") : "No project or service label";
}

function renderItem() {
  itemDetailEl.replaceChildren();
  if (!ui.selectedItemId) {
    itemDetailEl.append(el("p", { className: "empty", text: "Select an item in the vault." }));
    return;
  }
  const details = wt.getItemDetails(ui.selectedItemId);
  if (!details.ok) {
    itemDetailEl.append(el("p", { className: "empty", text: details.error }));
    return;
  }
  if (details.hidden) {
    itemDetailEl.append(
      el("section", { className: "panel" }, [
        el("h2", { text: details.name }),
        el("p", { text: details.message }),
      ]),
    );
    return;
  }

  const valueText = details.revealed ? details.displayValue : details.maskedValue;
  const reveal = el("button", {
    type: "button",
    text: details.revealed ? "Hide demo value" : "Show demo value",
  });
  reveal.addEventListener("click", () => {
    if (details.revealed) {
      report(wt.hideItemValue(details.id), "The demo value is hidden.");
    } else {
      report(wt.revealItem(details.id), details.revealWarning);
    }
    render();
  });
  const copy = el("button", {
    type: "button",
    className: "secondary",
    text: "Copy (demo)",
    disabled: !details.revealed,
  });
  copy.addEventListener("click", () => {
    const result = wt.demoCopyItem(details.id);
    if (report(result, result.warning)) render();
  });

  const save = buildEditForm(details);
  const deletePanel = buildDeletePanel(details);

  itemDetailEl.append(
    el("section", { className: "panel" }, [
      el("h2", { text: details.name }),
      el("p", { className: "muted", text: details.categoryLabel }),
      el("p", { text: details.agentUseLabel }),
      el("div", { className: "value-box" }, [
        el("p", { className: "muted", text: "Synthetic value" }),
        el("p", {
          className: details.revealed ? "" : "masked",
          text: valueText,
        }),
        details.revealed
          ? el("p", { className: "warning", text: details.revealWarning })
          : null,
        el("p", { className: "muted", text: details.copyWarning }),
      ]),
      el("div", { className: "actions wrap" }, [reveal, copy]),
      definitionList([
        ["Project", details.project || "None"],
        ["Service", details.service || "None"],
        ["Username", details.username || "None"],
        ["Host", details.host || "None"],
        ["Database", details.databaseName || "None"],
        ["Field name", details.fieldName || "None"],
        ["Public label", details.publicLabel || "None"],
        ["Notes", details.notes || "None"],
        ["Revision", String(details.revision)],
      ]),
    ]),
    save,
    deletePanel,
  );
}

function buildEditForm(details) {
  const form = el("form", { className: "panel stack-form" });
  form.append(el("h2", { text: "Edit item" }));
  const name = fieldInput("edit-name", "Name", details.name, "text");
  const service = fieldInput("edit-service", "Service", details.service, "text");
  const project = fieldInput("edit-project", "Project", details.project, "text");
  const notes = fieldArea("edit-notes", "Notes", details.notes);
  form.append(name.wrap, service.wrap, project.wrap);
  const extras = EXTRA_BY_CATEGORY[details.category] ?? [];
  const extraInputs = {};
  if (extras.includes("username")) {
    extraInputs.username = fieldInput("edit-username", "Username", details.username, "text");
    form.append(extraInputs.username.wrap);
  }
  if (extras.includes("host")) {
    extraInputs.host = fieldInput("edit-host", "Host", details.host, "text");
    form.append(extraInputs.host.wrap);
  }
  if (extras.includes("databaseName")) {
    extraInputs.databaseName = fieldInput(
      "edit-database-name",
      "Database name",
      details.databaseName,
      "text",
    );
    form.append(extraInputs.databaseName.wrap);
  }
  if (extras.includes("publicLabel")) {
    extraInputs.publicLabel = fieldInput(
      "edit-public-label",
      "Public label",
      details.publicLabel,
      "text",
    );
    form.append(extraInputs.publicLabel.wrap);
  }
  if (extras.includes("fieldName")) {
    extraInputs.fieldName = fieldInput("edit-field-name", "Field name", details.fieldName, "text");
    form.append(extraInputs.fieldName.wrap);
  }
  form.append(notes.wrap);
  const actions = el("div", { className: "actions" }, [
    el("button", { type: "submit", text: "Save item" }),
  ]);
  form.append(actions);
  form.addEventListener("submit", (event) => {
    event.preventDefault();
    const payload = {
      name: name.input.value,
      service: service.input.value,
      project: project.input.value,
      notes: notes.input.value,
    };
    for (const key of Object.keys(extraInputs)) {
      payload[key] = extraInputs[key].input.value;
    }
    if (report(wt.updateItem(details.id, payload), "The item was updated.")) {
      ui.pendingDeleteId = null;
      render();
    }
  });
  return form;
}

function buildDeletePanel(details) {
  const panel = el("section", { className: "panel" }, [
    el("h2", { text: "Delete item" }),
    el("p", { className: "hint", text: "Delete removes the item from this demo memory." }),
  ]);
  if (ui.pendingDeleteId === details.id) {
    const confirmBtn = el("button", { type: "button", className: "danger", text: "Confirm delete" });
    const cancelBtn = el("button", { type: "button", className: "secondary", text: "Cancel" });
    confirmBtn.addEventListener("click", () => {
      if (report(wt.deleteItem(details.id), "The item was deleted.")) {
        ui.selectedItemId = null;
        ui.pendingDeleteId = null;
        showView("vault");
      }
    });
    cancelBtn.addEventListener("click", () => {
      ui.pendingDeleteId = null;
      render();
    });
    panel.append(el("div", { className: "actions wrap" }, [confirmBtn, cancelBtn]));
  } else {
    const del = el("button", { type: "button", className: "danger", text: "Delete item" });
    del.addEventListener("click", () => {
      ui.pendingDeleteId = details.id;
      render();
      const confirmBtn = itemDetailEl.querySelector(".danger");
      if (confirmBtn) confirmBtn.focus();
    });
    panel.append(del);
  }
  return panel;
}

function fieldInput(id, label, value, type) {
  const input = el("input", {
    id,
    name: id,
    type,
    autocomplete: "off",
  });
  input.value = value ?? "";
  return {
    input,
    wrap: el("div", { className: "field" }, [el("label", { htmlFor: id, text: label }), input]),
  };
}

function fieldArea(id, label, value) {
  const input = el("textarea", {
    id,
    name: id,
    rows: "3",
    autocomplete: "off",
  });
  input.value = value ?? "";
  return {
    input,
    wrap: el("div", { className: "field field-wide" }, [
      el("label", { htmlFor: id, text: label }),
      input,
    ]),
  };
}

function definitionList(rows) {
  const dl = el("dl", { className: "dl" });
  for (const [term, value] of rows) {
    dl.append(
      el("div", {}, [
        el("dt", { text: term }),
        el("dd", { text: value }),
      ]),
    );
  }
  return dl;
}

function renderRules() {
  supportedSampleEl.textContent = SAMPLE_RULE_TEXT;
  const draft = wt.getRuleDraft();
  if (!draft) {
    draftStatusEl.textContent = "A review shows clauses, questions, and examples.";
    draftOriginalEl.textContent = "No draft yet.";
    draftClausesEl.replaceChildren(el("p", { className: "empty", text: "No clauses." }));
    draftQuestionsEl.replaceChildren(el("p", { className: "empty", text: "No questions." }));
    draftExamplesEl.replaceChildren(el("p", { className: "empty", text: "No examples." }));
  } else {
    const ready = draft.status === "ready_for_review" && draft.confirmed
      ? "Confirmed. Activate is available."
      : draft.status === "ready_for_review"
        ? "Ready for review. Confirm the interpretation before activation."
        : "Not ready. The fixture interpreter does not activate this text.";
    draftStatusEl.textContent = `${statusLabel(draft.status)}. ${ready} Interpreter: ${draft.interpreter}.`;
    draftOriginalEl.textContent = draft.originalText || "No draft yet.";
    renderClauses(draft);
    renderQuestions(draft);
    renderExamples(draft);
  }
  renderActiveRule();
  document.getElementById("confirm-rule").disabled = !(
    draft && draft.status === "ready_for_review" && !draft.confirmed
  );
  document.getElementById("activate-rule").disabled = !(
    draft && draft.status === "ready_for_review" && draft.confirmed
  );
}

function statusLabel(status) {
  if (status === "ready_for_review") return "Ready for review";
  if (status === "needs_clarification") return "Needs clarification";
  if (status === "blocked") return "Blocked";
  return status;
}

function renderClauses(draft) {
  if (!draft.clauses || draft.clauses.length === 0) {
    draftClausesEl.replaceChildren(
      el("p", { className: "empty", text: "No clauses. The interpreter did not invent a parse." }),
    );
    return;
  }
  const table = el("div", { className: "clause-table" });
  for (const clause of draft.clauses) {
    table.append(
      el("article", { className: "clause-row" }, [
        el("p", { className: "kind", text: clause.kindLabel }),
        el("div", {}, [
          el("p", { text: clause.text }),
          el("p", { className: "muted", text: clause.meaning }),
        ]),
      ]),
    );
  }
  draftClausesEl.replaceChildren(table);
}

function renderQuestions(draft) {
  const items = [...(draft.questions ?? []), ...(draft.issues ?? []).map((issue) => issue.message)];
  const unique = [...new Set(items)];
  if (unique.length === 0) {
    draftQuestionsEl.replaceChildren(el("p", { className: "empty", text: "No open questions." }));
    return;
  }
  const list = el("ul");
  for (const item of unique) {
    list.append(el("li", { text: item }));
  }
  draftQuestionsEl.replaceChildren(list);
}

function renderExamples(draft) {
  if (!draft.examples) {
    draftExamplesEl.replaceChildren(el("p", { className: "empty", text: "No examples for this text." }));
    return;
  }
  draftExamplesEl.replaceChildren(
    definitionList([
      ["Permit", draft.examples.allow],
      ["Wait", draft.examples.ask],
      ["Deny", draft.examples.deny],
    ]),
  );
}

function renderActiveRule() {
  const rule = wt.getActiveRule();
  if (!rule) {
    activeRuleEl.replaceChildren(el("p", { className: "empty", text: "No active rule." }));
    return;
  }
  activeRuleEl.replaceChildren(
    el("p", {}, [
      el("span", { className: `pill ${pillClass(rule.status)}`, text: rule.status }),
    ]),
    definitionList([
      ["Agent", rule.agentName],
      ["Item", rule.itemName],
      ["Destination", rule.destination],
      ["Denied", rule.deniedDestinations.join(", ")],
      ["Operation", rule.operation],
      ["Expiry", `${rule.expiryIso} (${rule.timeZone})`],
      ["Uses", `${rule.useCount} of ${rule.usageLimit}`],
      ["Interpreter", rule.interpreter],
      ["Version", String(rule.version)],
    ]),
    el("blockquote", { className: "sample-quote", text: rule.originalText }),
  );
}

function pillClass(value) {
  if (value === "allow" || value === "active" || value === "completed" || value === "attempted") {
    return "pill-allow";
  }
  if (value === "require_approval" || value === "pending" || value === "warning") {
    return "pill-ask";
  }
  return "pill-deny";
}

function renderAgents() {
  agentListEl.replaceChildren();
  const enrolled = new Map(wt.listAgents().map((agent) => [agent.id, agent]));
  for (const known of wt.listKnownAgents()) {
    const current = enrolled.get(known.id);
    const status = current?.status ?? "not enrolled";
    const actions = el("div", { className: "actions wrap" });
    if (status === "enrolled") {
      const revoke = el("button", { type: "button", className: "danger", text: "Revoke agent" });
      revoke.addEventListener("click", () => {
        if (report(wt.revokeAgent(known.id), `${known.name} is revoked.`)) render();
      });
      actions.append(revoke);
    } else {
      const enroll = el("button", { type: "button", text: "Enroll agent" });
      enroll.addEventListener("click", () => {
        if (report(wt.enrollAgent(known.id), `${known.name} is enrolled.`)) render();
      });
      actions.append(enroll);
    }
    agentListEl.append(
      el("article", { className: "agent-row" }, [
        el("div", {}, [
          el("h2", { text: known.name }),
          el("p", { text: known.summary }),
          el("p", { className: "muted", text: `Status: ${status}` }),
        ]),
        actions,
      ]),
    );
  }
}

function renderActivity() {
  const health = wt.getNotificationHealth();
  notificationHealthEl.textContent = health.label;
  renderInbox();
  renderHistory();
}

function renderInbox() {
  const alerts = wt.listAlerts();
  const requests = new Map(wt.listRequests().map((request) => [request.id, request]));
  const enrolled = new Set(
    wt.listAgents().filter((agent) => agent.status === "enrolled").map((agent) => agent.id),
  );
  if (alerts.length === 0) {
    inboxEl.replaceChildren(el("p", { className: "empty", text: "No alerts." }));
    return;
  }
  inboxEl.replaceChildren();
  for (const alert of alerts) {
    const request = requests.get(alert.requestId);
    const canDecide = request && request.status === "pending" && request.approvable;
    const decision = request?.decision ?? alert.decision;
    const message = request?.message ?? alert.message;
    const badge = inboxBadge(request, alert);
    const title = inboxTitle(request, alert);
    const firstResult =
      request &&
      request.initialDecision &&
      request.initialDecision !== request.decision
        ? `First result: ${decisionLabel(request.initialDecision)}.`
        : null;
    const actions = el("div", { className: "actions wrap" });
    if (canDecide) {
      const approve = el("button", { type: "button", text: "Approve once" });
      approve.addEventListener("click", () => {
        if (report(wt.approveOnce(alert.requestId), "The request was approved once.")) render();
      });
      const deny = el("button", { type: "button", className: "secondary", text: "Deny request" });
      deny.addEventListener("click", () => {
        if (report(wt.denyRequest(alert.requestId), "The request was denied.")) render();
      });
      actions.append(approve, deny);
    }
    if (enrolled.has(alert.agentId)) {
      const revoke = el("button", { type: "button", className: "danger", text: "Revoke agent" });
      revoke.addEventListener("click", () => {
        if (report(wt.revokeAgent(alert.agentId), `${alert.agentName} is revoked.`)) render();
      });
      actions.append(revoke);
    }
    inboxEl.append(
      el("article", { className: "alert-card" }, [
        el("p", {}, [
          el("span", { className: `pill ${pillClass(decision)}`, text: badge }),
          " ",
          el("strong", { text: title }),
        ]),
        el("p", { text: message }),
        firstResult ? el("p", { className: "muted", text: firstResult }) : null,
        el("p", {
          className: "muted",
          text: `${alert.agentName} · ${alert.itemName} · ${alert.destination} · ${alert.operation} · delivery ${alert.deliveryStatus}`,
        }),
        actions,
      ]),
    );
  }
}

function decisionLabel(decision) {
  if (decision === "allow") return "Permit";
  if (decision === "require_approval") return "Wait";
  return "Deny";
}

function inboxBadge(request, alert) {
  if (request?.status === "completed" && request.approvalConsumed) return "Approved";
  if (request?.status === "invalidated") return "Not valid";
  return decisionLabel(request?.decision ?? alert.decision);
}

function inboxTitle(request, alert) {
  if (!request) return alert.title;
  if (request.status === "pending") return "Request waits for a decision";
  if (request.status === "invalidated") return "Request is not valid";
  if (request.status === "completed" && request.approvalConsumed) return "Request complete";
  if (request.decision === "allow") return "Permitted request";
  if (request.status === "denied" || request.decision === "deny") return "Request denied";
  return alert.title;
}

function renderHistory() {
  const events = wt.listActivity();
  if (events.length === 0) {
    historyEl.replaceChildren(el("p", { className: "empty", text: "No history." }));
    return;
  }
  historyEl.replaceChildren();
  for (const event of events) {
    historyEl.append(
      el("article", { className: "history-item" }, [
        el("p", { text: event.message }),
        el("p", { className: "muted", text: `${event.atIso} · ${event.type}` }),
      ]),
    );
  }
}

function syncExtraFields() {
  const category = addCategoryEl.value;
  const extras = new Set(EXTRA_BY_CATEGORY[category] ?? []);
  for (const field of document.querySelectorAll("#add-item-form .extra-field")) {
    const name = field.getAttribute("data-extra");
    field.hidden = !extras.has(name);
  }
}

function fillRule(text) {
  ruleTextEl.value = text;
  ruleTextEl.focus();
  setStatus("The sample text is in the editor. Review the rule next.");
}

function readAddForm(form) {
  const data = new FormData(form);
  const category = String(data.get("category") ?? "");
  const payload = {
    name: String(data.get("name") ?? ""),
    category,
    service: String(data.get("service") ?? ""),
    project: String(data.get("project") ?? ""),
    notes: String(data.get("notes") ?? ""),
  };
  for (const key of EXTRA_BY_CATEGORY[category] ?? []) {
    const map = {
      username: "username",
      host: "host",
      databaseName: "databaseName",
      publicLabel: "publicLabel",
      fieldName: "fieldName",
    };
    const fieldName = map[key];
    payload[fieldName] = String(data.get(fieldName) ?? "");
  }
  return payload;
}

document.querySelectorAll(".nav-button").forEach((button) => {
  button.addEventListener("click", () => showView(button.getAttribute("data-view")));
});

document.getElementById("lock-button").addEventListener("click", () => {
  if (report(wt.lock(), "The vault is locked. Item details are hidden.")) {
    ui.pendingDeleteId = null;
    render();
  }
});

document.getElementById("unlock-button").addEventListener("click", () => {
  if (report(wt.unlock(), "The vault is open. This control is not owner authentication.")) render();
});

document.getElementById("reset-button").addEventListener("click", () => {
  if (report(wt.reset(), "Fixture data is loaded again. Earlier demo state is gone.")) {
    ui.selectedItemId = null;
    ui.pendingDeleteId = null;
    ui.search = "";
    itemSearchEl.value = "";
    ruleTextEl.value = "";
    showView("vault");
  }
});

document.getElementById("search-form").addEventListener("submit", (event) => {
  event.preventDefault();
  ui.search = itemSearchEl.value;
  render();
  const count = wt.listItems(ui.search).length;
  const noun = count === 1 ? "item matches" : "items match";
  setStatus(`The search is complete. ${count} ${noun}.`);
});

document.getElementById("search-clear").addEventListener("click", () => {
  ui.search = "";
  itemSearchEl.value = "";
  render();
  itemSearchEl.focus();
  setStatus("Search is cleared.");
});

document.getElementById("add-item-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const result = wt.createItem(readAddForm(event.currentTarget));
  if (report(result, `The walkthrough added ${result.item?.name ?? "the item"}.`)) {
    event.currentTarget.reset();
    addCategoryEl.value = "api_key";
    ui.selectedItemId = result.item.id;
    showView("item");
  }
});

addCategoryEl.addEventListener("change", syncExtraFields);

document.getElementById("fill-supported").addEventListener("click", () => fillRule(SAMPLE_RULE_TEXT));
document.getElementById("fill-ambiguous").addEventListener("click", () => fillRule(AMBIGUOUS_SAMPLE_TEXT));
document.getElementById("fill-conflicting").addEventListener("click", () => fillRule(CONFLICTING_SAMPLE_TEXT));
document.getElementById("fill-unsupported").addEventListener("click", () => fillRule(UNSUPPORTED_SAMPLE_TEXT));

document.getElementById("rule-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const result = wt.interpretRule(ruleTextEl.value);
  if (!report(result)) return;
  if (result.draft.status === "ready_for_review") {
    setStatus("The fixture interpreter produced a reviewable sample draft.", "ok");
  } else {
    setStatus("The fixture interpreter refused this text. See questions and issues.", "error");
  }
  render();
});

document.getElementById("confirm-rule").addEventListener("click", () => {
  if (report(wt.confirmRuleDraft(), "The owner demo confirmation is recorded.")) render();
});

document.getElementById("activate-rule").addEventListener("click", () => {
  if (report(wt.activateRule(), "The sample rule is active in this walkthrough.")) render();
});

document.getElementById("simulate-form").addEventListener("submit", (event) => {
  event.preventDefault();
  const scenario = document.getElementById("scenario").value;
  const result = wt.simulateScenario(scenario);
  if (!result.ok) {
    setStatus(result.error, "error");
    return;
  }
  setStatus(result.request.message, result.request.decision === "deny" ? "error" : "ok");
  render();
});

document.getElementById("notify-fail").addEventListener("click", () => {
  if (report(wt.setNotificationHealthy(false), "Notification delivery will fail. Waiting requests stay in the inbox.")) {
    render();
  }
});

document.getElementById("notify-ok").addEventListener("click", () => {
  if (report(wt.setNotificationHealthy(true), "The demo notification channel is healthy.")) render();
});

document.addEventListener("keydown", (event) => {
  if (event.key !== "Escape") return;
  if (ui.pendingDeleteId) {
    ui.pendingDeleteId = null;
    render();
    setStatus("Delete is canceled.");
  }
});

supportedSampleEl.textContent = SAMPLE_RULE_TEXT;
render();
setStatus("The walkthrough is ready. Use demo data only.");

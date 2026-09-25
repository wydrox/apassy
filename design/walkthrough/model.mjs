/**
 * Pure in-memory model for the Apassy synthetic owner walkthrough.
 * No storage, network, clipboard, encryption, or model calls.
 */

export const INTERPRETER_ID = "fixture-interpreter-v1";
export const POLICY_SCHEMA = "walkthrough-policy-v1";
export const DEFAULT_NOW_ISO = "2026-09-16T16:00:00.000Z";
export const SAMPLE_EXPIRY_ISO = "2026-09-18T23:59:59-04:00";
export const SAMPLE_TIME_ZONE = "America/New_York";
export const SAMPLE_USAGE_LIMIT = 3;
export const SAMPLE_OPERATION = "read_report";
export const SAMPLE_DESTINATION = "staging";
export const DENIED_DESTINATION = "production";
export const REPORTING_AGENT_ID = "reporting-agent";
export const OTHER_AGENT_ID = "other-agent";
export const REPORTING_ITEM_ID = "item-reporting-api";
export const MASKED_VALUE = "••••••••";

export const CATEGORIES = Object.freeze([
  Object.freeze({
    id: "api_key",
    label: "API key or token",
    agentUse: "fixture",
  }),
  Object.freeze({
    id: "login",
    label: "Username and password login",
    agentUse: "storage_only",
  }),
  Object.freeze({
    id: "ssh_key",
    label: "SSH key",
    agentUse: "storage_only",
  }),
  Object.freeze({
    id: "database",
    label: "Database credential",
    agentUse: "storage_only",
  }),
  Object.freeze({
    id: "custom",
    label: "Custom secret fields",
    agentUse: "storage_only",
  }),
]);

export const REFUSAL_REASON = Object.freeze({
  unfamiliar: "unfamiliar_text",
  ambiguous: "ambiguous_text",
  conflicting: "conflicting_text",
  unsupported: "unsupported_text",
});

export const SAMPLE_RULE_TEXT =
  "My reporting agent can use this credential for Project A, against staging, until Friday. Never use it for production. Ask me if the request does not fit the task.";

export const AMBIGUOUS_SAMPLE_TEXT =
  "Let the agent use the credential until Friday.";

export const CONFLICTING_SAMPLE_TEXT =
  "My reporting agent can use this credential for Project A against staging and production. Never use it for production.";

export const UNSUPPORTED_SAMPLE_TEXT =
  "My reporting agent can run any SQL on any database and send the password to the agent.";

export const KNOWN_AGENTS = Object.freeze([
  Object.freeze({
    id: REPORTING_AGENT_ID,
    name: "Reporting agent",
    summary: "Synthetic agent for Project A reports.",
  }),
  Object.freeze({
    id: OTHER_AGENT_ID,
    name: "Other agent",
    summary: "Synthetic agent with no sample grant.",
  }),
]);

const SECRET_INPUT_KEYS = Object.freeze([
  "secret",
  "password",
  "token",
  "value",
  "privateKey",
  "passphrase",
  "credential",
  "syntheticValue",
  "key",
]);

const ITEM_INPUT_KEYS = Object.freeze([
  "name",
  "category",
  "service",
  "project",
  "notes",
  "username",
  "host",
  "databaseName",
  "fieldName",
  "publicLabel",
]);

const DEFAULT_NOW_MS = Date.parse(DEFAULT_NOW_ISO);
const SAMPLE_EXPIRY_MS = Date.parse(SAMPLE_EXPIRY_ISO);

const FIXTURE_ITEMS = Object.freeze([
  Object.freeze({
    id: REPORTING_ITEM_ID,
    name: "Project A reporting service",
    category: "api_key",
    service: "reporting-api",
    project: "Project A",
    notes: "Fixture API key for staging reports.",
    username: "",
    host: "",
    databaseName: "",
    fieldName: "",
    publicLabel: "",
  }),
  Object.freeze({
    id: "item-dashboard-login",
    name: "Project A dashboard login",
    category: "login",
    service: "reporting-dashboard",
    project: "Project A",
    notes: "Stored login. Agent use is not available in this walkthrough.",
    username: "report-owner",
    host: "",
    databaseName: "",
    fieldName: "",
    publicLabel: "",
  }),
  Object.freeze({
    id: "item-jump-ssh",
    name: "Jump host key",
    category: "ssh_key",
    service: "jump-host",
    project: "Project A",
    notes: "Stored SSH key. Agent use is not available in this walkthrough.",
    username: "",
    host: "",
    databaseName: "",
    fieldName: "",
    publicLabel: "project-a-jump",
  }),
  Object.freeze({
    id: "item-staging-db",
    name: "Project A staging database",
    category: "database",
    service: "postgres-staging",
    project: "Project A",
    notes: "Stored database credential. This walkthrough does not run a connector.",
    username: "report_reader",
    host: "db.staging.example.invalid",
    databaseName: "project_a",
    fieldName: "",
    publicLabel: "",
  }),
  Object.freeze({
    id: "item-custom-token",
    name: "Internal note token",
    category: "custom",
    service: "",
    project: "Project A",
    notes: "Stored custom field. Agent use is not available in this walkthrough.",
    username: "",
    host: "",
    databaseName: "",
    fieldName: "note_token",
    publicLabel: "",
  }),
]);

export function normalizeRuleText(text) {
  return String(text ?? "")
    .trim()
    .replace(/\s+/g, " ");
}

export function categoryById(id) {
  return CATEGORIES.find((category) => category.id === id) ?? null;
}

export function createWalkthrough(options = {}) {
  const state = emptyState(options.now);

  const api = {
    listCategories() {
      return CATEGORIES.map((category) => ({ ...category }));
    },

    listKnownAgents() {
      return KNOWN_AGENTS.map((agent) => ({ ...agent }));
    },

    getNowIso() {
      return new Date(state.nowMs).toISOString();
    },

    setNow(value) {
      const ms = parseTime(value);
      if (ms === null) {
        return fail("invalid_time", "The demo clock value is not valid.");
      }
      state.nowMs = ms;
      record(state, {
        type: "clock",
        message: "The demo clock changed.",
        nowIso: new Date(state.nowMs).toISOString(),
      });
      return ok({ nowIso: new Date(state.nowMs).toISOString() });
    },

    isLocked() {
      return state.locked;
    },

    getEpoch() {
      return state.epoch;
    },

    getNotificationHealth() {
      return {
        healthy: state.notificationHealthy,
        label: state.notificationHealthy
          ? "Notification channel is healthy in this demo."
          : "Notification channel failed in this demo.",
      };
    },

    setNotificationHealthy(healthy) {
      state.notificationHealthy = Boolean(healthy);
      record(state, {
        type: "notification_health",
        message: state.notificationHealthy
          ? "The demo notification channel is healthy."
          : "The demo notification channel failed. Waiting requests stay in the inbox.",
        healthy: state.notificationHealthy,
      });
      return ok(api.getNotificationHealth());
    },

    lock() {
      state.locked = true;
      state.epoch += 1;
      state.revealedIds.clear();
      invalidatePending(state, "vault_locked", "The vault lock made pending demo authority invalid.");
      record(state, {
        type: "lock",
        message: "The vault is locked. Item details are hidden. Pending demo authority is not valid.",
        epoch: state.epoch,
      });
      return ok({ locked: true, epoch: state.epoch });
    },

    unlock() {
      state.locked = false;
      record(state, {
        type: "unlock",
        message: "The vault is open. This control is not owner authentication.",
        epoch: state.epoch,
      });
      return ok({ locked: false, epoch: state.epoch });
    },

    reset() {
      loadFixtures(state, options.now);
      record(state, {
        type: "reset",
        message: "The walkthrough loaded fixture data again. Earlier demo state is gone.",
      });
      return ok({ reset: true });
    },

    listItems(query = "") {
      const needle = String(query ?? "").trim().toLowerCase();
      return state.items
        .filter((item) => itemMatches(item, needle))
        .map((item) => publicItem(item));
    },

    getItemDetails(id) {
      const item = findItem(state, id);
      if (!item) {
        return fail("not_found", "The item is not in the vault.");
      }
      if (state.locked) {
        return ok({
          id: item.id,
          name: item.name,
          category: item.category,
          hidden: true,
          revealed: false,
          syntheticValue: null,
          maskedValue: MASKED_VALUE,
          reason: "vault_locked",
          message: "The vault is locked. Item details are hidden.",
        });
      }
      const revealed = state.revealedIds.has(item.id);
      return ok({
        ...publicItem(item),
        hidden: false,
        revealed,
        syntheticValue: revealed ? item.syntheticValue : null,
        maskedValue: MASKED_VALUE,
        displayValue: revealed ? item.syntheticValue : MASKED_VALUE,
        revealWarning:
          "This is a demo reveal. There is no authenticated owner check.",
        copyWarning:
          "A copy takes the value outside Apassy control. This walkthrough does not write to the clipboard.",
      });
    },

    createItem(input) {
      const checked = checkItemInput(input, { requireCategory: true });
      if (!checked.ok) return checked;
      const fields = checked.fields;
      const category = categoryById(fields.category);
      if (!category) {
        return fail("invalid_category", "The category is not one of the five vault categories.");
      }
      if (!fields.name) {
        return fail("invalid_name", "The item name is required.");
      }
      const id = nextId(state, "item", "item");
      const item = buildItem(id, fields, 1, state.issuedSecrets);
      state.items.push(item);
      record(state, {
        type: "item_create",
        message: `The walkthrough added ${item.name}.`,
        itemId: item.id,
        itemName: item.name,
        category: item.category,
      });
      return ok({ item: publicItem(item) });
    },

    updateItem(id, input) {
      const item = findItem(state, id);
      if (!item) {
        return fail("not_found", "The item is not in the vault.");
      }
      const checked = checkItemInput(input, { requireCategory: false });
      if (!checked.ok) return checked;
      const fields = checked.fields;
      if (fields.category && fields.category !== item.category) {
        return fail(
          "category_locked",
          "This walkthrough does not change item category. Delete the item and add a new item.",
        );
      }
      if (Object.prototype.hasOwnProperty.call(fields, "name") && !fields.name) {
        return fail("invalid_name", "The item name is required.");
      }
      applyItemFields(item, fields);
      item.revision += 1;
      state.revealedIds.delete(item.id);
      invalidatePendingForItem(
        state,
        item.id,
        "item_revision_changed",
        "The item revision changed. Pending demo authority for this item is not valid.",
      );
      record(state, {
        type: "item_update",
        message: `The walkthrough updated ${item.name}.`,
        itemId: item.id,
        itemName: item.name,
        revision: item.revision,
      });
      return ok({ item: publicItem(item) });
    },

    deleteItem(id) {
      const index = state.items.findIndex((item) => item.id === id);
      if (index === -1) {
        return fail("not_found", "The item is not in the vault.");
      }
      const item = state.items[index];
      state.items.splice(index, 1);
      state.revealedIds.delete(id);
      if (state.activeRule && state.activeRule.itemId === id) {
        state.activeRule.status = "revoked";
      }
      if (state.draft && state.draft.itemId === id) {
        state.draft = null;
      }
      invalidatePendingForItem(
        state,
        id,
        "item_deleted",
        "The item was deleted. Pending demo authority for this item is not valid.",
      );
      record(state, {
        type: "item_delete",
        message: `The walkthrough deleted ${item.name}.`,
        itemId: item.id,
        itemName: item.name,
      });
      return ok({ deletedId: id });
    },

    revealItem(id) {
      if (state.locked) {
        return fail("vault_locked", "The vault is locked. Item details are hidden.");
      }
      const item = findItem(state, id);
      if (!item) {
        return fail("not_found", "The item is not in the vault.");
      }
      state.revealedIds.add(item.id);
      record(state, {
        type: "reveal",
        message: `A demo reveal showed the synthetic value for ${item.name}.`,
        itemId: item.id,
        itemName: item.name,
      });
      return api.getItemDetails(id);
    },

    hideItemValue(id) {
      const item = findItem(state, id);
      if (!item) {
        return fail("not_found", "The item is not in the vault.");
      }
      state.revealedIds.delete(item.id);
      return api.getItemDetails(id);
    },

    demoCopyItem(id) {
      if (state.locked) {
        return fail("vault_locked", "The vault is locked. Item details are hidden.");
      }
      const item = findItem(state, id);
      if (!item) {
        return fail("not_found", "The item is not in the vault.");
      }
      if (!state.revealedIds.has(item.id)) {
        return fail(
          "not_revealed",
          "Show the demo value before you use the copy control.",
        );
      }
      record(state, {
        type: "copy_demo",
        message: `Copy control used for ${item.name}. The walkthrough did not write to the clipboard.`,
        itemId: item.id,
        itemName: item.name,
        wroteClipboard: false,
      });
      return ok({
        wroteClipboard: false,
        warning:
          "A copy takes the value outside Apassy control. This walkthrough does not write to the clipboard.",
      });
    },

    interpretRule(text) {
      const original = String(text ?? "");
      const normalized = normalizeRuleText(original);
      const draftId = nextId(state, "draft", "draft");
      let draft;

      if (!normalized) {
        draft = blockedDraft(draftId, original, "empty", [
          issue("missing_text", "Rule text is missing."),
        ]);
      } else if (normalized === normalizeRuleText(SAMPLE_RULE_TEXT)) {
        draft = sampleDraft(state, draftId, original);
      } else if (normalized === normalizeRuleText(AMBIGUOUS_SAMPLE_TEXT)) {
        draft = ambiguousDraft(draftId, original);
      } else if (normalized === normalizeRuleText(CONFLICTING_SAMPLE_TEXT)) {
        draft = conflictingDraft(draftId, original);
      } else if (normalized === normalizeRuleText(UNSUPPORTED_SAMPLE_TEXT)) {
        draft = unsupportedDraft(draftId, original);
      } else {
        draft = blockedDraft(draftId, original, REFUSAL_REASON.unfamiliar, [
          issue(
            REFUSAL_REASON.unfamiliar,
            "The fixture interpreter does not recognize this text. It does not guess missing meaning.",
          ),
        ]);
      }

      state.draft = draft;
      record(state, {
        type: "rule_interpret",
        message: draft.status === "ready_for_review"
          ? "The fixture interpreter produced a reviewable sample draft."
          : "The fixture interpreter did not activate a rule. Review the issues.",
        draftId: draft.id,
        status: draft.status,
        reasonCode: draft.reasonCode,
      });
      return ok({ draft: publicDraft(draft) });
    },

    getRuleDraft() {
      return state.draft ? publicDraft(state.draft) : null;
    },

    confirmRuleDraft() {
      if (!state.draft) {
        return fail("no_draft", "There is no rule draft to confirm.");
      }
      if (state.draft.status !== "ready_for_review") {
        return fail(
          "not_ready",
          "This draft is not ready. The fixture interpreter does not activate unclear or unsupported text.",
        );
      }
      if (state.locked) {
        return fail("vault_locked", "The vault is locked. Demo confirmation is not available.");
      }
      const live = sampleBindingIssues(state);
      if (live.length > 0) {
        state.draft.status = "needs_clarification";
        state.draft.issues = live;
        state.draft.confirmed = false;
        return fail("not_ready", live[0].message);
      }
      state.draft.confirmed = true;
      state.draft.confirmation = {
        atIso: new Date(state.nowMs).toISOString(),
        expiryIso: SAMPLE_EXPIRY_ISO,
        timeZone: SAMPLE_TIME_ZONE,
        interpreter: INTERPRETER_ID,
        demo: true,
      };
      record(state, {
        type: "rule_confirm",
        message: "The owner demo confirmation accepted the sample interpretation.",
        draftId: state.draft.id,
      });
      return ok({ draft: publicDraft(state.draft) });
    },

    activateRule() {
      if (!state.draft) {
        return fail("no_draft", "There is no rule draft to activate.");
      }
      if (state.locked) {
        return fail("vault_locked", "The vault is locked. Rule activation is not available.");
      }
      if (state.draft.status !== "ready_for_review") {
        return fail(
          "not_ready",
          "Activation is blocked. The fixture interpreter does not activate this text.",
        );
      }
      if (!state.draft.confirmed) {
        return fail(
          "confirmation_required",
          "Activation is blocked until the owner demo confirmation is recorded.",
        );
      }
      const live = sampleBindingIssues(state);
      if (live.length > 0) {
        state.draft.status = "needs_clarification";
        state.draft.issues = live;
        return fail("not_ready", live[0].message);
      }
      if (state.nowMs >= SAMPLE_EXPIRY_MS) {
        return fail("expired", "The sample expiry is in the past. The rule is not active.");
      }
      if (state.activeRule && state.activeRule.status === "active") {
        state.activeRule.status = "superseded";
      }
      const agent = enrolledAgent(state, REPORTING_AGENT_ID);
      const item = findItem(state, REPORTING_ITEM_ID);
      const rule = {
        id: `rule-${state.draft.id}`,
        status: "active",
        draftId: state.draft.id,
        originalText: state.draft.originalText,
        interpreter: INTERPRETER_ID,
        schema: POLICY_SCHEMA,
        version: (state.activeRule?.version ?? 0) + 1,
        agentId: agent.id,
        agentName: agent.name,
        agentGeneration: agent.generation,
        itemId: item.id,
        itemName: item.name,
        itemRevision: item.revision,
        project: "Project A",
        destination: SAMPLE_DESTINATION,
        deniedDestinations: [DENIED_DESTINATION],
        operation: SAMPLE_OPERATION,
        expiryIso: SAMPLE_EXPIRY_ISO,
        expiryMs: SAMPLE_EXPIRY_MS,
        timeZone: SAMPLE_TIME_ZONE,
        usageLimit: SAMPLE_USAGE_LIMIT,
        useCount: 0,
        onUncertain: "require_approval",
        confirmedAtIso: state.draft.confirmation.atIso,
        activatedAtIso: new Date(state.nowMs).toISOString(),
      };
      state.activeRule = rule;
      record(state, {
        type: "rule_activate",
        message: "The sample rule is active in this walkthrough.",
        ruleId: rule.id,
        version: rule.version,
        agentId: rule.agentId,
        itemId: rule.itemId,
      });
      return ok({ rule: publicRule(rule) });
    },

    getActiveRule() {
      return state.activeRule ? publicRule(state.activeRule) : null;
    },

    listAgents() {
      return state.agents.map((agent) => ({
        id: agent.id,
        name: agent.name,
        summary: agent.summary,
        status: agent.status,
        generation: agent.generation,
      }));
    },

    enrollAgent(id) {
      const known = KNOWN_AGENTS.find((agent) => agent.id === id);
      if (!known) {
        return fail("unknown_agent", "This walkthrough can enroll only the synthetic catalog agents.");
      }
      const existing = state.agents.find((agent) => agent.id === id);
      if (existing && existing.status === "enrolled") {
        return fail("already_enrolled", `${known.name} is already enrolled.`);
      }
      if (existing) {
        existing.status = "enrolled";
        existing.generation += 1;
        record(state, {
          type: "agent_enroll",
          message: `${known.name} is enrolled again. Old grants do not return.`,
          agentId: existing.id,
          agentName: existing.name,
          generation: existing.generation,
        });
        return ok({ agent: publicAgent(existing) });
      }
      const agent = {
        id: known.id,
        name: known.name,
        summary: known.summary,
        status: "enrolled",
        generation: 1,
      };
      state.agents.push(agent);
      record(state, {
        type: "agent_enroll",
        message: `${agent.name} is enrolled.`,
        agentId: agent.id,
        agentName: agent.name,
        generation: agent.generation,
      });
      return ok({ agent: publicAgent(agent) });
    },

    revokeAgent(id) {
      const agent = state.agents.find((entry) => entry.id === id);
      if (!agent || agent.status !== "enrolled") {
        return fail("not_enrolled", "The agent is not enrolled.");
      }
      agent.status = "revoked";
      if (state.activeRule && state.activeRule.agentId === id) {
        state.activeRule.status = "revoked";
      }
      invalidatePendingForAgent(
        state,
        id,
        "agent_revoked",
        "The agent is revoked. Pending demo authority for this agent is not valid.",
      );
      record(state, {
        type: "agent_revoke",
        message: `${agent.name} is revoked. Future sample use is denied.`,
        agentId: agent.id,
        agentName: agent.name,
      });
      return ok({ agent: publicAgent(agent) });
    },

    simulateScenario(scenario) {
      const plan = scenarioPlan(scenario);
      if (!plan.ok) return plan;
      return api.submitRequest(plan.request);
    },

    submitRequest(input) {
      const requestInput = normalizeRequestInput(input);
      if (!requestInput.ok) return requestInput;
      const built = buildRequestRecord(state, requestInput.request);
      const decision = decideRequest(state, built);
      built.decision = decision.decision;
      built.reasonCode = decision.reasonCode;
      built.message = decision.message;
      built.approvable = decision.approvable;
      built.status = decision.status;
      built.executed = false;
      built.approvalConsumed = false;
      built.epoch = state.epoch;
      built.digest = requestDigest(built);

      if (decision.decision === "allow") {
        consumeUse(state, built);
        built.status = "completed";
        built.executed = true;
        built.completedAtIso = new Date(state.nowMs).toISOString();
      }

      rememberInitialDecision(built);
      state.requests.push(built);

      const alert = makeAlert(state, built);
      if (decision.decision === "require_approval") {
        alert.deliveryStatus = state.notificationHealthy ? "attempted" : "failed";
        alert.deliveryMessage = state.notificationHealthy
          ? "A local demo notification was attempted. This is not proof that an owner saw it."
          : "Notification delivery failed. The request still waits in the inbox.";
      } else {
        alert.deliveryStatus = state.notificationHealthy ? "attempted" : "failed";
        alert.deliveryMessage = state.notificationHealthy
          ? "A local demo notification was attempted."
          : "Notification delivery failed. The recorded decision is still in the inbox.";
      }
      state.alerts.push(alert);
      built.alertId = alert.id;
      built.deliveryStatus = alert.deliveryStatus;

      record(state, {
        type: "request",
        message: built.message,
        requestId: built.id,
        agentId: built.agentId,
        agentName: built.agentName,
        itemId: built.itemId,
        itemName: built.itemName,
        destination: built.destination,
        operation: built.operation,
        purpose: built.purpose,
        decision: built.decision,
        reasonCode: built.reasonCode,
        status: built.status,
        deliveryStatus: built.deliveryStatus,
        approvable: built.approvable,
      });

      return ok({
        request: publicRequest(built),
        alert: publicAlert(alert),
      });
    },

    approveOnce(requestId, claimedDigest) {
      if (state.locked) {
        return fail("vault_locked", "The vault is locked. Pending demo authority is not valid.");
      }
      const request = state.requests.find((entry) => entry.id === requestId);
      if (!request) {
        return fail("not_found", "The request is not in the inbox.");
      }
      if (request.status !== "pending") {
        return fail("not_pending", "The request does not wait for approval.");
      }
      if (!request.approvable || request.decision !== "require_approval") {
        return fail("not_approvable", "This decision cannot be approved.");
      }
      if (request.epoch !== state.epoch) {
        return fail("invalidated", "Pending demo authority is not valid after lock.");
      }
      const liveDigest = requestDigest(request);
      if (liveDigest !== request.digest) {
        return fail("request_mismatch", "The request digest does not match the stored request.");
      }
      if (claimedDigest !== undefined && claimedDigest !== request.digest) {
        return fail(
          "request_mismatch",
          "The approval is bound to one exact request. This digest does not match.",
        );
      }
      if (request.approvalConsumed) {
        return fail("approval_consumed", "The approval is single-use and is already consumed.");
      }

      const live = decideRequest(state, request);
      if (live.decision === "deny") {
        applyCurrentDecision(request, {
          decision: "deny",
          reasonCode: live.reasonCode,
          status: "denied",
          message: live.message,
          approvable: false,
          atIso: new Date(state.nowMs).toISOString(),
        });
        syncAlertFromRequest(state, request);
        return fail(live.reasonCode, live.message);
      }

      request.approvalConsumed = true;
      consumeUse(state, request);
      applyCurrentDecision(request, {
        decision: "allow",
        reasonCode: "owner_approved_once",
        status: "completed",
        message: "The owner approved this exact request once. The demo use is complete.",
        approvable: false,
        atIso: new Date(state.nowMs).toISOString(),
      });
      request.executed = true;
      request.completedAtIso = request.decisionHistory.at(-1).atIso;
      syncAlertFromRequest(state, request);
      record(state, {
        type: "approve_once",
        message: request.message,
        requestId: request.id,
        agentId: request.agentId,
        agentName: request.agentName,
        itemId: request.itemId,
        itemName: request.itemName,
        decision: request.decision,
        reasonCode: request.reasonCode,
        status: request.status,
      });
      return ok({ request: publicRequest(request) });
    },

    denyRequest(requestId) {
      const request = state.requests.find((entry) => entry.id === requestId);
      if (!request) {
        return fail("not_found", "The request is not in the inbox.");
      }
      if (request.status !== "pending") {
        return fail("not_pending", "The request does not wait for a decision.");
      }
      applyCurrentDecision(request, {
        decision: "deny",
        reasonCode: "owner_denied",
        status: "denied",
        message: "The owner denied this request. The demo did not execute.",
        approvable: false,
        atIso: new Date(state.nowMs).toISOString(),
      });
      syncAlertFromRequest(state, request);
      record(state, {
        type: "deny",
        message: request.message,
        requestId: request.id,
        agentId: request.agentId,
        agentName: request.agentName,
        itemId: request.itemId,
        itemName: request.itemName,
        decision: "deny",
        reasonCode: "owner_denied",
      });
      return ok({ request: publicRequest(request) });
    },

    listRequests() {
      return state.requests.map((request) => publicRequest(request));
    },

    listAlerts() {
      return state.alerts.map((alert) => publicAlert(alert)).reverse();
    },

    listActivity() {
      return state.activity.map((event) => ({ ...event })).reverse();
    },

    getSupportedSamples() {
      return {
        supported: SAMPLE_RULE_TEXT,
        ambiguous: AMBIGUOUS_SAMPLE_TEXT,
        conflicting: CONFLICTING_SAMPLE_TEXT,
        unsupported: UNSUPPORTED_SAMPLE_TEXT,
        interpreter: INTERPRETER_ID,
        expiryIso: SAMPLE_EXPIRY_ISO,
        timeZone: SAMPLE_TIME_ZONE,
        usageLimit: SAMPLE_USAGE_LIMIT,
      };
    },
  };

  loadFixtures(state, options.now);
  return api;
}

function emptyState(now) {
  return {
    nowMs: parseTime(now) ?? DEFAULT_NOW_MS,
    epoch: 1,
    locked: false,
    notificationHealthy: true,
    revealedIds: new Set(),
    items: [],
    agents: [],
    draft: null,
    activeRule: null,
    requests: [],
    alerts: [],
    activity: [],
    issuedSecrets: new Set(),
    seq: {
      item: 1,
      request: 1,
      alert: 1,
      event: 1,
      draft: 1,
    },
  };
}

function loadFixtures(state, now) {
  const nowMs = parseTime(now) ?? DEFAULT_NOW_MS;
  state.nowMs = nowMs;
  state.epoch = 1;
  state.locked = false;
  state.notificationHealthy = true;
  state.revealedIds = new Set();
  state.items = FIXTURE_ITEMS.map((fields) => buildItem(fields.id, fields, 1));
  state.agents = [];
  state.draft = null;
  state.activeRule = null;
  state.requests = [];
  state.alerts = [];
  state.activity = [];
  state.issuedSecrets = new Set(state.items.map((item) => item.syntheticValue));
  state.seq = {
    item: 1,
    request: 1,
    alert: 1,
    event: 1,
    draft: 1,
  };
}

function parseTime(value) {
  if (value === undefined || value === null || value === "") {
    return null;
  }
  if (typeof value === "number" && Number.isFinite(value)) {
    return value;
  }
  const ms = Date.parse(String(value));
  return Number.isFinite(ms) ? ms : null;
}

function nextId(state, kind, prefix) {
  const n = state.seq[kind]++;
  return `${prefix}-${n}`;
}

function ok(extra) {
  return { ok: true, ...extra };
}

function fail(code, error) {
  return { ok: false, code, error };
}

function issue(code, message) {
  return { code, message };
}

function record(state, event) {
  const safe = {
    id: nextId(state, "event", "event"),
    atIso: new Date(state.nowMs).toISOString(),
    ...event,
  };
  assertNoSecret(state, safe);
  state.activity.push(safe);
}

function assertNoSecret(state, value) {
  const text = JSON.stringify(value);
  for (const secret of state.issuedSecrets) {
    if (secret && text.includes(secret)) {
      throw new Error("Activity or alert contained a synthetic secret value.");
    }
  }
}

function buildItem(id, fields, revision, issuedSecrets) {
  const category = categoryById(fields.category);
  const item = {
    id,
    name: String(fields.name ?? "").trim(),
    category: fields.category,
    service: String(fields.service ?? "").trim(),
    project: String(fields.project ?? "").trim(),
    notes: String(fields.notes ?? "").trim(),
    username: String(fields.username ?? "").trim(),
    host: String(fields.host ?? "").trim(),
    databaseName: String(fields.databaseName ?? "").trim(),
    fieldName: String(fields.fieldName ?? "").trim(),
    publicLabel: String(fields.publicLabel ?? "").trim(),
    revision,
    agentUse: category?.agentUse ?? "storage_only",
    syntheticValue: syntheticValue(fields.category, id),
  };
  if (issuedSecrets) issuedSecrets.add(item.syntheticValue);
  return item;
}

function applyItemFields(item, fields) {
  for (const key of [
    "name",
    "service",
    "project",
    "notes",
    "username",
    "host",
    "databaseName",
    "fieldName",
    "publicLabel",
  ]) {
    if (Object.prototype.hasOwnProperty.call(fields, key) && fields[key] !== undefined) {
      item[key] = String(fields[key] ?? "").trim();
    }
  }
}

function syntheticValue(category, id) {
  const token = String(category).replaceAll("_", "-").toUpperCase();
  return `SYNTH-${token}-${id}-NOT-A-SECRET`;
}

function publicItem(item) {
  const category = categoryById(item.category);
  return {
    id: item.id,
    name: item.name,
    category: item.category,
    categoryLabel: category?.label ?? item.category,
    service: item.service,
    project: item.project,
    notes: item.notes,
    username: item.username,
    host: item.host,
    databaseName: item.databaseName,
    fieldName: item.fieldName,
    publicLabel: item.publicLabel,
    revision: item.revision,
    agentUse: item.agentUse,
    agentUseLabel:
      item.agentUse === "fixture"
        ? "Fixture agent use is available for the sample reporting path."
        : "This item is stored. Agent use is not available in this walkthrough.",
  };
}

function itemMatches(item, needle) {
  if (!needle) return true;
  const category = categoryById(item.category);
  const haystack = [
    item.name,
    item.category,
    category?.label ?? "",
    item.service,
    item.project,
    item.notes,
    item.username,
    item.host,
    item.databaseName,
    item.fieldName,
    item.publicLabel,
  ]
    .join(" ")
    .toLowerCase();
  return haystack.includes(needle);
}

function findItem(state, id) {
  return state.items.find((item) => item.id === id) ?? null;
}

function checkItemInput(input, { requireCategory }) {
  const raw = input && typeof input === "object" ? input : {};
  for (const key of Object.keys(raw)) {
    if (SECRET_INPUT_KEYS.includes(key)) {
      return fail(
        "secret_input",
        "This walkthrough does not accept secret input. It assigns a fixed synthetic value.",
      );
    }
    if (!ITEM_INPUT_KEYS.includes(key)) {
      return fail("unknown_field", `Field ${key} is not accepted.`);
    }
  }
  const fields = {};
  for (const key of ITEM_INPUT_KEYS) {
    if (Object.prototype.hasOwnProperty.call(raw, key)) {
      fields[key] = raw[key];
    }
  }
  if (requireCategory && !fields.category) {
    return fail("invalid_category", "The category is required.");
  }
  if (fields.category && !categoryById(fields.category)) {
    return fail("invalid_category", "The category is not one of the five vault categories.");
  }
  if (Object.prototype.hasOwnProperty.call(fields, "name")) {
    fields.name = String(fields.name ?? "").trim();
  }
  return ok({ fields });
}

function enrolledAgent(state, id) {
  return state.agents.find((agent) => agent.id === id && agent.status === "enrolled") ?? null;
}

function publicAgent(agent) {
  return {
    id: agent.id,
    name: agent.name,
    summary: agent.summary,
    status: agent.status,
    generation: agent.generation,
  };
}

function publicDraft(draft) {
  return clone(draft);
}

function publicRule(rule) {
  return {
    id: rule.id,
    status: rule.status,
    originalText: rule.originalText,
    interpreter: rule.interpreter,
    schema: rule.schema,
    version: rule.version,
    agentId: rule.agentId,
    agentName: rule.agentName,
    agentGeneration: rule.agentGeneration,
    itemId: rule.itemId,
    itemName: rule.itemName,
    itemRevision: rule.itemRevision,
    project: rule.project,
    destination: rule.destination,
    deniedDestinations: [...rule.deniedDestinations],
    operation: rule.operation,
    expiryIso: rule.expiryIso,
    timeZone: rule.timeZone,
    usageLimit: rule.usageLimit,
    useCount: rule.useCount,
    remainingUses: Math.max(0, rule.usageLimit - rule.useCount),
    onUncertain: rule.onUncertain,
    confirmedAtIso: rule.confirmedAtIso,
    activatedAtIso: rule.activatedAtIso,
  };
}

function publicRequest(request) {
  return {
    id: request.id,
    agentId: request.agentId,
    agentName: request.agentName,
    itemId: request.itemId,
    itemName: request.itemName,
    itemRevision: request.itemRevision,
    destination: request.destination,
    operation: request.operation,
    purpose: request.purpose,
    decision: request.decision,
    reasonCode: request.reasonCode,
    status: request.status,
    message: request.message,
    initialDecision: request.initialDecision ?? request.decision,
    initialReasonCode: request.initialReasonCode ?? request.reasonCode,
    decisionHistory: clone(request.decisionHistory ?? []),
    approvable: request.approvable,
    executed: request.executed,
    approvalConsumed: request.approvalConsumed,
    digest: request.digest,
    deliveryStatus: request.deliveryStatus,
    epoch: request.epoch,
    createdAtIso: request.createdAtIso,
    completedAtIso: request.completedAtIso ?? null,
    alertId: request.alertId ?? null,
  };
}

function publicAlert(alert) {
  return { ...alert };
}

function clone(value) {
  return JSON.parse(JSON.stringify(value));
}

function sampleBindingIssues(state) {
  const issues = [];
  if (!enrolledAgent(state, REPORTING_AGENT_ID)) {
    issues.push(
      issue(
        "agent_not_enrolled",
        "The reporting agent is not enrolled. Enroll the agent, then review the rule again.",
      ),
    );
  }
  if (!findItem(state, REPORTING_ITEM_ID)) {
    issues.push(
      issue(
        "item_missing",
        "Project A reporting service is not in the vault. The sample cannot bind to it.",
      ),
    );
  }
  return issues;
}

function sampleDraft(state, draftId, original) {
  const bindingIssues = sampleBindingIssues(state);
  const clauses = [
    {
      text: "My reporting agent",
      kind: "enforceable",
      kindLabel: "Restriction",
      meaning: "Bound to enrolled agent reporting-agent.",
    },
    {
      text: "can use this credential",
      kind: "enforceable",
      kindLabel: "Restriction",
      meaning: "Bound to Project A reporting service.",
    },
    {
      text: "for Project A",
      kind: "enforceable",
      kindLabel: "Restriction",
      meaning: "Project tag Project A.",
    },
    {
      text: "against staging",
      kind: "enforceable",
      kindLabel: "Restriction",
      meaning: "Destination staging only.",
    },
    {
      text: "until Friday",
      kind: "enforceable",
      kindLabel: "Restriction",
      meaning: `Expires ${SAMPLE_EXPIRY_ISO} in time zone ${SAMPLE_TIME_ZONE}.`,
    },
    {
      text: "Never use it for production",
      kind: "enforceable",
      kindLabel: "Restriction",
      meaning: "Explicit denial for production. This denial wins.",
    },
    {
      text: "Ask me if the request does not fit the task",
      kind: "contextual",
      kindLabel: "Contextual check",
      meaning:
        "If the task fit is unclear, the request waits for owner approval. This is a judgment, not a destination check.",
    },
  ];
  const questions = [
    "Confirm that Friday means 2026-09-18 23:59:59 America/New_York.",
    "Confirm that production stays denied.",
    "Confirm that an unclear task waits for an owner decision.",
  ];
  return {
    id: draftId,
    originalText: original,
    normalizedText: normalizeRuleText(original),
    interpreter: INTERPRETER_ID,
    status: bindingIssues.length > 0 ? "needs_clarification" : "ready_for_review",
    reasonCode: bindingIssues.length > 0 ? bindingIssues[0].code : "sample_ready",
    confirmed: false,
    confirmation: null,
    canActivate: bindingIssues.length === 0,
    itemId: REPORTING_ITEM_ID,
    agentId: REPORTING_AGENT_ID,
    clauses,
    issues: bindingIssues,
    questions: bindingIssues.length > 0 ? bindingIssues.map((entry) => entry.message) : questions,
    examples: {
      allow: "Read a Project A report from staging with a clear task.",
      ask: "Read a Project A report from staging with an unclear task.",
      deny: "Read a Project A report from production.",
    },
    bindings: {
      agentId: REPORTING_AGENT_ID,
      itemId: REPORTING_ITEM_ID,
      project: "Project A",
      destination: SAMPLE_DESTINATION,
      deniedDestinations: [DENIED_DESTINATION],
      operation: SAMPLE_OPERATION,
      expiryIso: SAMPLE_EXPIRY_ISO,
      timeZone: SAMPLE_TIME_ZONE,
      usageLimit: SAMPLE_USAGE_LIMIT,
    },
  };
}

function ambiguousDraft(draftId, original) {
  return {
    id: draftId,
    originalText: original,
    normalizedText: normalizeRuleText(original),
    interpreter: INTERPRETER_ID,
    status: "needs_clarification",
    reasonCode: REFUSAL_REASON.ambiguous,
    confirmed: false,
    confirmation: null,
    canActivate: false,
    clauses: [],
    issues: [
      issue("ambiguous_who", "Which agent is named? The text says only the agent."),
      issue("ambiguous_what", "Which credential is named? The text says only the credential."),
      issue("ambiguous_where", "Which destination is named? The text does not say staging or production."),
    ],
    questions: [
      "Name the agent from the catalog.",
      "Name the credential in the vault.",
      "Name the destination that the connector can enforce.",
    ],
    examples: null,
    bindings: null,
  };
}

function conflictingDraft(draftId, original) {
  return {
    id: draftId,
    originalText: original,
    normalizedText: normalizeRuleText(original),
    interpreter: INTERPRETER_ID,
    status: "blocked",
    reasonCode: REFUSAL_REASON.conflicting,
    confirmed: false,
    confirmation: null,
    canActivate: false,
    clauses: [
      {
        text: "against staging and production",
        kind: "conflict",
        kindLabel: "Conflict",
        meaning: "This clause permits production.",
      },
      {
        text: "Never use it for production",
        kind: "conflict",
        kindLabel: "Conflict",
        meaning: "This clause denies production.",
      },
    ],
    issues: [
      issue(
        REFUSAL_REASON.conflicting,
        "The text both permits production and denies production. The fixture interpreter does not pick a side.",
      ),
    ],
    questions: [
      "Remove the production permission, or remove the production denial. Then review the text again.",
    ],
    examples: null,
    bindings: null,
  };
}

function unsupportedDraft(draftId, original) {
  return {
    id: draftId,
    originalText: original,
    normalizedText: normalizeRuleText(original),
    interpreter: INTERPRETER_ID,
    status: "blocked",
    reasonCode: REFUSAL_REASON.unsupported,
    confirmed: false,
    confirmation: null,
    canActivate: false,
    clauses: [
      {
        text: "run any SQL on any database",
        kind: "unsupported",
        kindLabel: "Unsupported",
        meaning: "Arbitrary SQL is not a bounded connector operation in this walkthrough.",
      },
      {
        text: "send the password to the agent",
        kind: "unsupported",
        kindLabel: "Unsupported",
        meaning: "Raw secret delivery to an agent is outside the walkthrough contract.",
      },
    ],
    issues: [
      issue(
        REFUSAL_REASON.unsupported,
        "The fixture interpreter does not support arbitrary SQL or raw secret delivery.",
      ),
    ],
    questions: [
      "Use the supported sample. It permits a named report operation against staging.",
    ],
    examples: null,
    bindings: null,
  };
}

function blockedDraft(draftId, original, reasonCode, issues) {
  return {
    id: draftId,
    originalText: original,
    normalizedText: normalizeRuleText(original),
    interpreter: INTERPRETER_ID,
    status: "blocked",
    reasonCode,
    confirmed: false,
    confirmation: null,
    canActivate: false,
    clauses: [],
    issues,
    questions: issues.map((entry) => entry.message),
    examples: null,
    bindings: null,
  };
}

function scenarioPlan(scenario) {
  const name = String(scenario ?? "").trim();
  if (name === "normal") {
    return ok({
      request: {
        agentId: REPORTING_AGENT_ID,
        itemId: REPORTING_ITEM_ID,
        destination: SAMPLE_DESTINATION,
        operation: SAMPLE_OPERATION,
        purpose: "weekly Project A report",
      },
    });
  }
  if (name === "uncertain") {
    return ok({
      request: {
        agentId: REPORTING_AGENT_ID,
        itemId: REPORTING_ITEM_ID,
        destination: SAMPLE_DESTINATION,
        operation: SAMPLE_OPERATION,
        purpose: "unclear task",
      },
    });
  }
  if (name === "production") {
    return ok({
      request: {
        agentId: REPORTING_AGENT_ID,
        itemId: REPORTING_ITEM_ID,
        destination: DENIED_DESTINATION,
        operation: SAMPLE_OPERATION,
        purpose: "weekly Project A report",
      },
    });
  }
  return fail("unknown_scenario", "The demo request is not one of normal, uncertain, or production.");
}

function normalizeRequestInput(input) {
  const raw = input && typeof input === "object" ? input : {};
  for (const key of Object.keys(raw)) {
    if (SECRET_INPUT_KEYS.includes(key)) {
      return fail("secret_input", "This walkthrough does not accept secret input on a request.");
    }
  }
  const agentId = String(raw.agentId ?? "").trim();
  const itemId = String(raw.itemId ?? "").trim();
  const destination = String(raw.destination ?? "").trim();
  const operation = String(raw.operation ?? "").trim();
  const purpose = String(raw.purpose ?? "").trim();
  if (!agentId || !itemId || !destination || !operation || !purpose) {
    return fail("invalid_request", "Agent, item, destination, operation, and purpose are required.");
  }
  return ok({
    request: { agentId, itemId, destination, operation, purpose },
  });
}

function buildRequestRecord(state, input) {
  const agent =
    state.agents.find((entry) => entry.id === input.agentId) ??
    KNOWN_AGENTS.find((entry) => entry.id === input.agentId);
  const item = findItem(state, input.itemId);
  return {
    id: nextId(state, "request", "req"),
    agentId: input.agentId,
    agentName: agent?.name ?? input.agentId,
    agentGeneration: enrolledAgent(state, input.agentId)?.generation ?? null,
    itemId: input.itemId,
    itemName: item?.name ?? input.itemId,
    itemRevision: item?.revision ?? null,
    destination: input.destination,
    operation: input.operation,
    purpose: input.purpose,
    createdAtIso: new Date(state.nowMs).toISOString(),
  };
}

function requestDigest(request) {
  return [
    request.agentId,
    request.itemId,
    String(request.itemRevision ?? ""),
    request.destination,
    request.operation,
    request.purpose,
    String(request.agentGeneration ?? ""),
  ].join("|");
}

function activeGrant(state, request) {
  const rule = state.activeRule;
  if (!rule || rule.status !== "active") return null;
  if (rule.agentId !== request.agentId) return null;
  if (rule.itemId !== request.itemId) return null;
  const agent = enrolledAgent(state, request.agentId);
  if (!agent) return null;
  if (agent.generation !== rule.agentGeneration) return null;
  return rule;
}

function decideRequest(state, request) {
  if (state.locked) {
    return {
      decision: "deny",
      reasonCode: "vault_locked",
      message: "The vault is locked. The demo did not use a credential.",
      approvable: false,
      status: "denied",
    };
  }

  const agent = enrolledAgent(state, request.agentId);
  if (!agent) {
    const known = state.agents.find((entry) => entry.id === request.agentId);
    if (known && known.status === "revoked") {
      return {
        decision: "deny",
        reasonCode: "agent_revoked",
        message: "The agent is revoked. The demo did not use a credential.",
        approvable: false,
        status: "denied",
      };
    }
    return {
      decision: "deny",
      reasonCode: "no_grant",
      message: "There is no enrolled agent grant for this request.",
      approvable: false,
      status: "denied",
    };
  }

  const item = findItem(state, request.itemId);
  if (!item) {
    return {
      decision: "deny",
      reasonCode: "item_missing",
      message: "The item is not in the vault.",
      approvable: false,
      status: "denied",
    };
  }

  const rule = activeGrant(state, request);
  if (!rule) {
    return {
      decision: "deny",
      reasonCode: "no_grant",
      message: "There is no active grant for this agent and item.",
      approvable: false,
      status: "denied",
    };
  }

  if (state.nowMs >= rule.expiryMs) {
    return {
      decision: "deny",
      reasonCode: "expired",
      message: `The sample rule expired at ${rule.expiryIso}.`,
      approvable: false,
      status: "denied",
    };
  }

  if (rule.useCount >= rule.usageLimit) {
    return {
      decision: "deny",
      reasonCode: "usage_limit",
      message: `The sample usage limit of ${rule.usageLimit} is reached.`,
      approvable: false,
      status: "denied",
    };
  }

  if (request.operation !== rule.operation) {
    return {
      decision: "deny",
      reasonCode: "unsupported_operation",
      message: "The operation is not the sample report operation.",
      approvable: false,
      status: "denied",
    };
  }

  if (rule.deniedDestinations.includes(request.destination)) {
    return {
      decision: "deny",
      reasonCode: "explicit_denial",
      message: "The rule blocks production. This denial cannot be approved.",
      approvable: false,
      status: "denied",
    };
  }

  if (request.destination !== rule.destination) {
    return {
      decision: "deny",
      reasonCode: "destination_not_permitted",
      message: "The destination is not staging.",
      approvable: false,
      status: "denied",
    };
  }

  if (isUncertainPurpose(request.purpose)) {
    return {
      decision: "require_approval",
      reasonCode: "uncertain_task",
      message: "The task fit is unclear. The request waits for an owner decision.",
      approvable: true,
      status: "pending",
    };
  }

  return {
    decision: "allow",
    reasonCode: "automatic_permit",
    message: "The bouncer permitted this normal request. The request did not need extra approval.",
    approvable: false,
    status: "completed",
  };
}

function isUncertainPurpose(purpose) {
  const text = String(purpose ?? "").toLowerCase();
  return text.includes("unclear") || text.includes("uncertain") || text.includes("does not fit");
}

function consumeUse(state, request) {
  const rule = activeGrant(state, request);
  if (rule) {
    rule.useCount += 1;
  }
}

function makeAlert(state, request) {
  const actions = [];
  if (request.status === "pending" && request.approvable) {
    actions.push("approve_once", "deny");
  }
  actions.push("revoke_agent");
  const severity =
    request.decision === "deny"
      ? "security"
      : request.decision === "require_approval"
        ? "warning"
        : "info";
  const alert = {
    id: nextId(state, "alert", "alert"),
    requestId: request.id,
    severity,
    title: alertTitle(request),
    message: request.message,
    reasonCode: request.reasonCode,
    decision: request.decision,
    status: request.status,
    initialDecision: request.initialDecision ?? request.decision,
    initialReasonCode: request.initialReasonCode ?? request.reasonCode,
    decisionHistory: clone(request.decisionHistory ?? []),
    agentId: request.agentId,
    agentName: request.agentName,
    itemId: request.itemId,
    itemName: request.itemName,
    destination: request.destination,
    operation: request.operation,
    purpose: request.purpose,
    actions,
    createdAtIso: new Date(state.nowMs).toISOString(),
    count: 1,
  };
  assertNoSecret(state, alert);
  return alert;
}

function alertTitle(request) {
  if (request.status === "completed" && request.approvalConsumed) return "Request complete";
  if (request.status === "invalidated") return "Request is not valid";
  if (request.decision === "allow") return "Permitted request";
  if (request.decision === "require_approval") return "Request waits for a decision";
  return "Request denied";
}

function rememberInitialDecision(request) {
  request.initialDecision = request.decision;
  request.initialReasonCode = request.reasonCode;
  request.decisionHistory = [
    {
      decision: request.decision,
      reasonCode: request.reasonCode,
      status: request.status,
      atIso: request.createdAtIso,
    },
  ];
}

function applyCurrentDecision(request, outcome) {
  if (!request.initialDecision) {
    rememberInitialDecision(request);
  }
  request.decision = outcome.decision;
  request.reasonCode = outcome.reasonCode;
  request.status = outcome.status;
  request.message = outcome.message;
  request.approvable = outcome.approvable;
  request.decisionHistory = request.decisionHistory ?? [];
  request.decisionHistory.push({
    decision: outcome.decision,
    reasonCode: outcome.reasonCode,
    status: outcome.status,
    atIso: outcome.atIso,
  });
}

function syncAlertFromRequest(state, request) {
  const alert = state.alerts.find((entry) => entry.id === request.alertId);
  if (!alert) return;
  const actions = [];
  if (request.status === "pending" && request.approvable) {
    actions.push("approve_once", "deny");
  }
  actions.push("revoke_agent");
  alert.decision = request.decision;
  alert.reasonCode = request.reasonCode;
  alert.status = request.status;
  alert.message = request.message;
  alert.title = alertTitle(request);
  alert.approvable = request.approvable;
  alert.actions = actions;
  alert.initialDecision = request.initialDecision;
  alert.initialReasonCode = request.initialReasonCode;
  alert.decisionHistory = clone(request.decisionHistory ?? []);
}

function invalidatePending(state, reasonCode, message) {
  for (const request of state.requests) {
    if (request.status === "pending") {
      request.status = "invalidated";
      request.approvable = false;
      request.reasonCode = reasonCode;
      request.message = message;
    }
  }
}

function invalidatePendingForItem(state, itemId, reasonCode, message) {
  for (const request of state.requests) {
    if (request.status === "pending" && request.itemId === itemId) {
      request.status = "invalidated";
      request.approvable = false;
      request.reasonCode = reasonCode;
      request.message = message;
    }
  }
}

function invalidatePendingForAgent(state, agentId, reasonCode, message) {
  for (const request of state.requests) {
    if (request.status === "pending" && request.agentId === agentId) {
      request.status = "invalidated";
      request.approvable = false;
      request.reasonCode = reasonCode;
      request.message = message;
    }
  }
}

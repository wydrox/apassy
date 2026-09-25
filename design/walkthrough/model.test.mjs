import { describe, test } from "node:test";
import assert from "node:assert/strict";
import {
  AMBIGUOUS_SAMPLE_TEXT,
  CATEGORIES,
  CONFLICTING_SAMPLE_TEXT,
  DEFAULT_NOW_ISO,
  DENIED_DESTINATION,
  MASKED_VALUE,
  OTHER_AGENT_ID,
  REPORTING_AGENT_ID,
  REPORTING_ITEM_ID,
  SAMPLE_DESTINATION,
  SAMPLE_EXPIRY_ISO,
  SAMPLE_OPERATION,
  SAMPLE_RULE_TEXT,
  SAMPLE_USAGE_LIMIT,
  UNSUPPORTED_SAMPLE_TEXT,
  createWalkthrough,
} from "./model.mjs";

function readyWalkthrough() {
  const wt = createWalkthrough();
  assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);
  const interpreted = wt.interpretRule(SAMPLE_RULE_TEXT);
  assert.equal(interpreted.ok, true);
  assert.equal(interpreted.draft.status, "ready_for_review");
  assert.equal(wt.confirmRuleDraft().ok, true);
  const activated = wt.activateRule();
  assert.equal(activated.ok, true);
  assert.equal(activated.rule.status, "active");
  return wt;
}

function activityBlob(wt) {
  return JSON.stringify({
    activity: wt.listActivity(),
    alerts: wt.listAlerts(),
    requests: wt.listRequests(),
  });
}

describe("five categories", () => {
  test("the vault lists five credential categories", () => {
    const wt = createWalkthrough();
    const categories = wt.listCategories();
    assert.equal(categories.length, 5);
    assert.deepEqual(
      categories.map((category) => category.id),
      ["api_key", "login", "ssh_key", "database", "custom"],
    );
  });

  test("fixtures include one item in each category", () => {
    const wt = createWalkthrough();
    const items = wt.listItems();
    const ids = new Set(items.map((item) => item.category));
    assert.equal(ids.size, 5);
    for (const category of CATEGORIES) {
      assert.equal(
        items.some((item) => item.category === category.id),
        true,
        `missing ${category.id}`,
      );
    }
  });
});

describe("CRUD and search", () => {
  test("create, search, update, and delete a fixture item", () => {
    const wt = createWalkthrough();
    const created = wt.createItem({
      name: "Temp reporting key",
      category: "api_key",
      service: "temp-api",
      project: "Project A",
      notes: "Disposable fixture item",
    });
    assert.equal(created.ok, true);
    assert.equal(created.item.category, "api_key");
    assert.equal(wt.listItems("temp reporting").length, 1);

    const updated = wt.updateItem(created.item.id, { name: "Temp reporting key 2" });
    assert.equal(updated.ok, true);
    assert.equal(updated.item.name, "Temp reporting key 2");
    assert.equal(updated.item.revision, 2);
    assert.equal(wt.listItems("key 2").length, 1);
    assert.equal(wt.listItems("TEMP REPORTING KEY 2").length, 1);
    assert.equal(wt.listItems("no-such-item").length, 0);

    const deleted = wt.deleteItem(created.item.id);
    assert.equal(deleted.ok, true);
    assert.equal(wt.listItems("key 2").length, 0);
  });

  test("create rejects secret input and assigns an internal synthetic value", () => {
    const wt = createWalkthrough();
    const rejected = wt.createItem({
      name: "Bad",
      category: "api_key",
      password: "please-store-this",
    });
    assert.equal(rejected.ok, false);
    assert.equal(rejected.code, "secret_input");

    const created = wt.createItem({ name: "Safe", category: "login" });
    assert.equal(created.ok, true);
    wt.revealItem(created.item.id);
    const details = wt.getItemDetails(created.item.id);
    assert.equal(details.ok, true);
    assert.match(details.syntheticValue, /^SYNTH-LOGIN-item-\d+-NOT-A-SECRET$/);
  });

  test("empty search returns every item and category change is refused", () => {
    const wt = createWalkthrough();
    assert.equal(wt.listItems("").length, 5);
    assert.equal(wt.listItems("   ").length, 5);
    const result = wt.updateItem(REPORTING_ITEM_ID, { category: "login" });
    assert.equal(result.ok, false);
    assert.equal(result.code, "category_locked");
  });
});

describe("no grant denial", () => {
  test("a request without an active grant is denied and is not approvable", () => {
    const wt = createWalkthrough();
    assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);
    const result = wt.simulateScenario("normal");
    assert.equal(result.ok, true);
    assert.equal(result.request.decision, "deny");
    assert.equal(result.request.reasonCode, "no_grant");
    assert.equal(result.request.approvable, false);
    assert.equal(result.request.executed, false);
  });

  test("an enrolled agent without the sample rule is denied", () => {
    const wt = createWalkthrough();
    assert.equal(wt.enrollAgent(OTHER_AGENT_ID).ok, true);
    const result = wt.submitRequest({
      agentId: OTHER_AGENT_ID,
      itemId: REPORTING_ITEM_ID,
      destination: SAMPLE_DESTINATION,
      operation: SAMPLE_OPERATION,
      purpose: "weekly Project A report",
    });
    assert.equal(result.ok, true);
    assert.equal(result.request.reasonCode, "no_grant");
  });
});

describe("activation blocked for unsupported prose", () => {
  test("unfamiliar, ambiguous, conflicting, and unsupported text cannot activate", () => {
    const wt = createWalkthrough();
    assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);

    const unfamiliar = wt.interpretRule("Allow Bob to do stuff on Friday maybe.");
    assert.equal(unfamiliar.draft.status, "blocked");
    assert.equal(unfamiliar.draft.reasonCode, "unfamiliar_text");
    assert.equal(wt.confirmRuleDraft().ok, false);
    assert.equal(wt.activateRule().code, "not_ready");

    const ambiguous = wt.interpretRule(AMBIGUOUS_SAMPLE_TEXT);
    assert.equal(ambiguous.draft.status, "needs_clarification");
    assert.equal(ambiguous.draft.reasonCode, "ambiguous_text");
    assert.equal(ambiguous.draft.clauses.length, 0);
    assert.equal(wt.activateRule().ok, false);

    const conflicting = wt.interpretRule(CONFLICTING_SAMPLE_TEXT);
    assert.equal(conflicting.draft.status, "blocked");
    assert.equal(conflicting.draft.reasonCode, "conflicting_text");
    assert.equal(wt.activateRule().ok, false);

    const unsupported = wt.interpretRule(UNSUPPORTED_SAMPLE_TEXT);
    assert.equal(unsupported.draft.status, "blocked");
    assert.equal(unsupported.draft.reasonCode, "unsupported_text");
    assert.equal(wt.activateRule().ok, false);
  });

  test("canonical refusal codes stay blocked and do not activate", () => {
    const wt = createWalkthrough();
    assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);

    const nearMiss = wt.interpretRule(`${SAMPLE_RULE_TEXT} Also allow production.`);
    assert.equal(nearMiss.ok, true);
    assert.equal(nearMiss.draft.status, "blocked");
    assert.equal(nearMiss.draft.reasonCode, "unfamiliar_text");
    assert.equal(nearMiss.draft.canActivate, false);
    assert.equal(wt.confirmRuleDraft().ok, false);
    assert.equal(wt.activateRule().ok, false);
    assert.equal(wt.getActiveRule(), null);

    const cases = [
      {
        text: "Allow Bob to do stuff on Friday maybe.",
        status: "blocked",
        reasonCode: "unfamiliar_text",
      },
      {
        text: AMBIGUOUS_SAMPLE_TEXT,
        status: "needs_clarification",
        reasonCode: "ambiguous_text",
      },
      {
        text: CONFLICTING_SAMPLE_TEXT,
        status: "blocked",
        reasonCode: "conflicting_text",
      },
      {
        text: UNSUPPORTED_SAMPLE_TEXT,
        status: "blocked",
        reasonCode: "unsupported_text",
      },
    ];

    for (const entry of cases) {
      const result = wt.interpretRule(entry.text);
      assert.equal(result.draft.status, entry.status, entry.reasonCode);
      assert.equal(result.draft.reasonCode, entry.reasonCode);
      assert.equal(result.draft.canActivate, false, entry.reasonCode);
      assert.equal(result.draft.confirmed, false, entry.reasonCode);
      assert.equal(wt.confirmRuleDraft().ok, false, entry.reasonCode);
      const activated = wt.activateRule();
      assert.equal(activated.ok, false, entry.reasonCode);
      assert.equal(wt.getActiveRule(), null, entry.reasonCode);
    }
  });

  test("the sample shows clause review and questions instead of a silent parse", () => {
    const wt = createWalkthrough();
    assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);
    const result = wt.interpretRule(SAMPLE_RULE_TEXT);
    assert.equal(result.draft.status, "ready_for_review");
    assert.equal(result.draft.clauses.length, 7);
    assert.equal(result.draft.questions.length > 0, true);
    assert.equal(result.draft.examples.deny.includes("production"), true);
    assert.equal(result.draft.interpreter, "fixture-interpreter-v1");
    assert.equal(result.draft.confirmed, false);
  });
});

describe("confirmation before activation", () => {
  test("the sample does not activate without owner demo confirmation", () => {
    const wt = createWalkthrough();
    assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);
    assert.equal(wt.interpretRule(SAMPLE_RULE_TEXT).ok, true);
    const blocked = wt.activateRule();
    assert.equal(blocked.ok, false);
    assert.equal(blocked.code, "confirmation_required");
    assert.equal(wt.getActiveRule(), null);
  });

  test("confirmation then activation records the sample rule", () => {
    const wt = readyWalkthrough();
    const rule = wt.getActiveRule();
    assert.equal(rule.status, "active");
    assert.equal(rule.originalText, SAMPLE_RULE_TEXT);
    assert.equal(rule.expiryIso, SAMPLE_EXPIRY_ISO);
    assert.equal(rule.usageLimit, SAMPLE_USAGE_LIMIT);
    assert.equal(rule.destination, SAMPLE_DESTINATION);
    assert.deepEqual(rule.deniedDestinations, [DENIED_DESTINATION]);
  });

  test("the sample needs the reporting agent before it is ready", () => {
    const wt = createWalkthrough();
    const interpreted = wt.interpretRule(SAMPLE_RULE_TEXT);
    assert.equal(interpreted.draft.status, "needs_clarification");
    assert.equal(wt.confirmRuleDraft().ok, false);
    assert.equal(wt.activateRule().ok, false);
  });
});

describe("normal automatic permission", () => {
  test("a normal granted staging request is permitted without approval", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("normal");
    assert.equal(result.ok, true);
    assert.equal(result.request.decision, "allow");
    assert.equal(result.request.reasonCode, "automatic_permit");
    assert.equal(result.request.status, "completed");
    assert.equal(result.request.executed, true);
    assert.equal(result.request.approvable, false);
    assert.equal(wt.getActiveRule().useCount, 1);
    assert.equal(wt.getActiveRule().remainingUses, SAMPLE_USAGE_LIMIT - 1);
  });
});

describe("uncertainty pending approval", () => {
  test("an unclear task waits and can be approved once", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("uncertain");
    assert.equal(result.request.decision, "require_approval");
    assert.equal(result.request.status, "pending");
    assert.equal(result.request.executed, false);
    assert.equal(result.request.approvable, true);
    assert.equal(result.alert.deliveryStatus, "attempted");

    const approved = wt.approveOnce(result.request.id);
    assert.equal(approved.ok, true);
    assert.equal(approved.request.status, "completed");
    assert.equal(approved.request.executed, true);
    assert.equal(approved.request.approvalConsumed, true);
  });

  test("approved request reports current completion and keeps require_approval history", () => {
    const wt = readyWalkthrough();
    const waiting = wt.simulateScenario("uncertain");
    assert.equal(waiting.request.decision, "require_approval");
    assert.equal(waiting.request.reasonCode, "uncertain_task");
    assert.equal(waiting.request.status, "pending");
    assert.equal(waiting.request.approvable, true);
    assert.equal(waiting.alert.decision, "require_approval");
    assert.equal(waiting.alert.title, "Request waits for a decision");

    const approved = wt.approveOnce(waiting.request.id);
    assert.equal(approved.ok, true);
    const request = approved.request;
    assert.equal(request.status, "completed");
    assert.equal(request.decision, "allow");
    assert.equal(request.reasonCode, "owner_approved_once");
    assert.equal(request.approvable, false);
    assert.equal(request.approvalConsumed, true);
    assert.equal(request.executed, true);
    assert.equal(request.initialDecision, "require_approval");
    assert.equal(request.initialReasonCode, "uncertain_task");
    assert.equal(request.decisionHistory[0].decision, "require_approval");
    assert.equal(request.decisionHistory[0].reasonCode, "uncertain_task");
    assert.equal(request.decisionHistory.at(-1).decision, "allow");
    assert.equal(request.decisionHistory.at(-1).reasonCode, "owner_approved_once");
    assert.equal(request.decisionHistory.at(-1).status, "completed");

    const listed = wt.listRequests().find((entry) => entry.id === request.id);
    assert.equal(listed.decision, "allow");
    assert.equal(listed.reasonCode, "owner_approved_once");
    assert.equal(listed.status, "completed");
    assert.equal(listed.approvable, false);
    assert.equal(listed.initialDecision, "require_approval");
    assert.equal(listed.initialReasonCode, "uncertain_task");

    const alert = wt.listAlerts().find((entry) => entry.requestId === request.id);
    assert.equal(alert.decision, "allow");
    assert.equal(alert.reasonCode, "owner_approved_once");
    assert.equal(alert.status, "completed");
    assert.equal(alert.title, "Request complete");
    assert.equal(alert.initialDecision, "require_approval");
    assert.equal(alert.initialReasonCode, "uncertain_task");
    assert.equal(alert.actions.includes("approve_once"), false);

    const activity = wt.listActivity();
    assert.equal(
      activity.some(
        (event) => event.type === "request" && event.decision === "require_approval",
      ),
      true,
    );
    assert.equal(
      activity.some(
        (event) =>
          event.type === "approve_once" &&
          event.decision === "allow" &&
          event.reasonCode === "owner_approved_once",
      ),
      true,
    );

    const second = wt.approveOnce(request.id);
    assert.equal(second.ok, false);
    assert.equal(second.code, "not_pending");
    assert.equal(wt.listRequests().find((entry) => entry.id === request.id).decision, "allow");
  });

  test("the owner can deny a waiting request", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("uncertain");
    const denied = wt.denyRequest(result.request.id);
    assert.equal(denied.ok, true);
    assert.equal(denied.request.status, "denied");
    assert.equal(denied.request.executed, false);
    assert.equal(denied.request.reasonCode, "owner_denied");
  });
});

describe("production hard denial not approvable", () => {
  test("production is denied immediately and approve-once fails", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("production");
    assert.equal(result.request.decision, "deny");
    assert.equal(result.request.reasonCode, "explicit_denial");
    assert.equal(result.request.status, "denied");
    assert.equal(result.request.approvable, false);
    assert.equal(result.request.executed, false);

    const approved = wt.approveOnce(result.request.id);
    assert.equal(approved.ok, false);
    assert.equal(approved.code, "not_pending");
  });
});

describe("approval single-use", () => {
  test("a second approve-once on the same request fails", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("uncertain");
    assert.equal(wt.approveOnce(result.request.id).ok, true);
    const second = wt.approveOnce(result.request.id);
    assert.equal(second.ok, false);
    assert.equal(second.code, "not_pending");
  });
});

describe("exact request binding", () => {
  test("approval of one request does not complete a different request", () => {
    const wt = readyWalkthrough();
    const first = wt.submitRequest({
      agentId: REPORTING_AGENT_ID,
      itemId: REPORTING_ITEM_ID,
      destination: SAMPLE_DESTINATION,
      operation: SAMPLE_OPERATION,
      purpose: "unclear task",
    });
    const second = wt.submitRequest({
      agentId: REPORTING_AGENT_ID,
      itemId: REPORTING_ITEM_ID,
      destination: SAMPLE_DESTINATION,
      operation: SAMPLE_OPERATION,
      purpose: "unclear task, extra parameter",
    });
    assert.notEqual(first.request.digest, second.request.digest);
    assert.equal(wt.approveOnce(first.request.id).ok, true);
    assert.equal(wt.listRequests().find((entry) => entry.id === second.request.id).status, "pending");
    assert.equal(wt.approveOnce(second.request.id).ok, true);
  });

  test("a claimed digest that does not match is refused", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("uncertain");
    const mismatch = wt.approveOnce(result.request.id, "forged-digest");
    assert.equal(mismatch.ok, false);
    assert.equal(mismatch.code, "request_mismatch");
    assert.equal(result.request.status, "pending");
    assert.equal(wt.listRequests()[0].status, "pending");
  });

  test("an item revision change invalidates a waiting request", () => {
    const wt = readyWalkthrough();
    const result = wt.simulateScenario("uncertain");
    assert.equal(wt.updateItem(REPORTING_ITEM_ID, { notes: "Changed label" }).ok, true);
    const approved = wt.approveOnce(result.request.id);
    assert.equal(approved.ok, false);
    assert.equal(approved.code, "not_pending");
    assert.equal(
      wt.listRequests().find((entry) => entry.id === result.request.id).status,
      "invalidated",
    );
  });
});

describe("revocation", () => {
  test("revoke denies future use and invalidates waiting requests", () => {
    const wt = readyWalkthrough();
    const waiting = wt.simulateScenario("uncertain");
    assert.equal(waiting.request.status, "pending");
    assert.equal(wt.revokeAgent(REPORTING_AGENT_ID).ok, true);
    assert.equal(
      wt.listRequests().find((entry) => entry.id === waiting.request.id).status,
      "invalidated",
    );
    const later = wt.simulateScenario("normal");
    assert.equal(later.request.decision, "deny");
    assert.equal(later.request.reasonCode, "agent_revoked");
    assert.equal(wt.getActiveRule().status, "revoked");
  });

  test("re-enrollment does not restore a revoked grant", () => {
    const wt = readyWalkthrough();
    assert.equal(wt.revokeAgent(REPORTING_AGENT_ID).ok, true);
    assert.equal(wt.enrollAgent(REPORTING_AGENT_ID).ok, true);
    const result = wt.simulateScenario("normal");
    assert.equal(result.request.reasonCode, "no_grant");
  });
});

describe("lock invalidation", () => {
  test("lock hides item details and invalidates pending demo authority", () => {
    const wt = readyWalkthrough();
    assert.equal(wt.revealItem(REPORTING_ITEM_ID).ok, true);
    assert.equal(wt.getItemDetails(REPORTING_ITEM_ID).revealed, true);

    const waiting = wt.simulateScenario("uncertain");
    assert.equal(waiting.request.status, "pending");

    assert.equal(wt.lock().ok, true);
    const details = wt.getItemDetails(REPORTING_ITEM_ID);
    assert.equal(details.hidden, true);
    assert.equal(details.syntheticValue, null);
    assert.equal(details.displayValue === undefined, true);
    assert.equal(details.maskedValue, MASKED_VALUE);

    const approved = wt.approveOnce(waiting.request.id);
    assert.equal(approved.ok, false);
    assert.equal(approved.code, "vault_locked");
    assert.equal(
      wt.listRequests().find((entry) => entry.id === waiting.request.id).status,
      "invalidated",
    );

    const lockedRequest = wt.simulateScenario("normal");
    assert.equal(lockedRequest.request.reasonCode, "vault_locked");

    assert.equal(wt.unlock().ok, true);
    const after = wt.getItemDetails(REPORTING_ITEM_ID);
    assert.equal(after.hidden, false);
    assert.equal(after.revealed, false);
    assert.equal(after.syntheticValue, null);
    assert.equal(wt.approveOnce(waiting.request.id).ok, false);
  });
});

describe("notification failure", () => {
  test("a failed notification keeps the waiting request", () => {
    const wt = readyWalkthrough();
    assert.equal(wt.setNotificationHealthy(false).ok, true);
    const result = wt.simulateScenario("uncertain");
    assert.equal(result.request.status, "pending");
    assert.equal(result.request.deliveryStatus, "failed");
    assert.equal(result.alert.deliveryStatus, "failed");
    assert.match(result.alert.deliveryMessage, /still waits/);
    assert.equal(result.request.executed, false);
    assert.equal(wt.approveOnce(result.request.id).ok, true);
  });
});

describe("safe secret-free activity", () => {
  test("activity, alerts, and requests do not contain synthetic secret values", () => {
    const wt = readyWalkthrough();
    const revealed = wt.revealItem(REPORTING_ITEM_ID);
    assert.equal(revealed.ok, true);
    const secret = revealed.syntheticValue;
    assert.match(secret, /^SYNTH-/);
    assert.equal(wt.demoCopyItem(REPORTING_ITEM_ID).wroteClipboard, false);
    wt.simulateScenario("normal");
    wt.simulateScenario("uncertain");
    wt.simulateScenario("production");

    const blob = activityBlob(wt);
    assert.equal(blob.includes(secret), false);
    assert.equal(/SYNTH-|NOT-A-SECRET/.test(blob), false);
    assert.equal(JSON.stringify(wt.listItems()).includes(secret), false);
  });
});

describe("sample limits and expiry", () => {
  test("the sample usage limit denies further automatic use", () => {
    const wt = readyWalkthrough();
    for (let i = 0; i < SAMPLE_USAGE_LIMIT; i += 1) {
      const result = wt.simulateScenario("normal");
      assert.equal(result.request.decision, "allow", `use ${i + 1}`);
    }
    const blocked = wt.simulateScenario("normal");
    assert.equal(blocked.request.decision, "deny");
    assert.equal(blocked.request.reasonCode, "usage_limit");
    assert.equal(blocked.request.executed, false);
    assert.equal(wt.getActiveRule().useCount, SAMPLE_USAGE_LIMIT);
    assert.equal(wt.getActiveRule().remainingUses, 0);
  });

  test("an approved request counts toward the sample usage limit", () => {
    const wt = readyWalkthrough();
    const waiting = wt.simulateScenario("uncertain");
    assert.equal(wt.approveOnce(waiting.request.id).ok, true);
    assert.equal(wt.getActiveRule().useCount, 1);
  });

  test("a request after sample expiry is denied", () => {
    const wt = readyWalkthrough();
    const clock = wt.setNow("2026-09-19T04:00:00.000Z");
    assert.equal(clock.ok, true);
    const result = wt.simulateScenario("normal");
    assert.equal(result.request.decision, "deny");
    assert.equal(result.request.reasonCode, "expired");
    assert.equal(result.request.executed, false);
  });

  test("the demo clock starts before the sample Friday expiry", () => {
    const wt = createWalkthrough();
    assert.equal(wt.getNowIso(), DEFAULT_NOW_ISO);
    assert.equal(Date.parse(DEFAULT_NOW_ISO) < Date.parse(SAMPLE_EXPIRY_ISO), true);
  });
});

describe("reset and demo copy", () => {
  test("reset reloads fixtures and drops demo state", () => {
    const wt = readyWalkthrough();
    wt.simulateScenario("normal");
    wt.createItem({ name: "Extra", category: "custom", fieldName: "x" });
    assert.equal(wt.reset().ok, true);
    assert.equal(wt.listItems().length, 5);
    assert.equal(wt.getActiveRule(), null);
    assert.equal(wt.listAgents().length, 0);
    assert.equal(wt.listRequests().length, 0);
    assert.equal(wt.isLocked(), false);
  });

  test("copy control refuses a hidden value and never claims a clipboard write", () => {
    const wt = createWalkthrough();
    const hidden = wt.demoCopyItem(REPORTING_ITEM_ID);
    assert.equal(hidden.ok, false);
    assert.equal(hidden.code, "not_revealed");
    assert.equal(wt.revealItem(REPORTING_ITEM_ID).ok, true);
    const copied = wt.demoCopyItem(REPORTING_ITEM_ID);
    assert.equal(copied.ok, true);
    assert.equal(copied.wroteClipboard, false);
  });
});

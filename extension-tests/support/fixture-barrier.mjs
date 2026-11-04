import { setTimeout as delay } from "node:timers/promises";

// Request logging precedes the host's queued scenario read. Only an answer
// acknowledges that the temporary scenario was consumed. Even if the popup's
// state handler resumes after restoration, not_running cannot lead to logins.
export async function grantWithStoppedHost(h, trigger, { wait = delay, attempts = 250 } = {}) {
  const scenario = h.scenario();
  h.setScenario({ notRunning: true });
  h.clearRequests();
  await trigger();
  let acknowledged = false;
  for (let i = 0; i < attempts; i += 1) {
    const answers = h.answers("status");
    if (answers.length) {
      if (answers.some((answer) => answer.ok !== false || answer.code !== "not_running")) {
        throw new Error("toolbar setup status did not acknowledge not_running");
      }
      acknowledged = true;
      break;
    }
    await wait(20);
  }
  if (!acknowledged) throw new Error("toolbar setup status answer did not arrive");
  // On a failed barrier, leave the stopped scenario and evidence intact.
  await h.closeRealPopup();
  h.setScenario(scenario);
  h.clearRequests();
}

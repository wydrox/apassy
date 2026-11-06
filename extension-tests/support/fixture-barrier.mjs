import { setTimeout as delay } from "node:timers/promises";

// Read only existing evidence. Never serialize native records or read errors.
function reportBarrier(h, started, reason, answers) {
  let statusRequests = "unreadable", statusAnswers = "unreadable", codes = "unreadable";
  try {
    const requests = h.requests("status");
    if (Array.isArray(requests)) statusRequests = requests.length;
  } catch {}
  try {
    if (Array.isArray(answers)) {
      const counts = { not_running: 0, ok: 0, host_failed: 0, timeout: 0, other: 0 };
      for (const answer of answers) {
        const code = answer.code;
        const key = ["not_running", "ok", "host_failed", "timeout"].includes(code) ? code : "other";
        counts[key]++;
      }
      statusAnswers = answers.length;
      codes = counts;
    }
  } catch {}
  try {
    console.error("[fixture-barrier] " + JSON.stringify({
      reason, elapsedMs: Math.round(performance.now() - started), statusRequests, statusAnswers, codes,
    }));
  } catch {} // Diagnostics must not replace the barrier failure.
}

// Request logging precedes the host's queued scenario read. Only an answer
// acknowledges that the temporary scenario was consumed. Even if the popup's
// state handler resumes after restoration, not_running cannot lead to logins.
export async function grantWithStoppedHost(h, trigger, { wait = delay, attempts = 250 } = {}) {
  const started = performance.now();
  const scenario = h.scenario();
  h.setScenario({ notRunning: true });
  h.clearRequests();
  await trigger();
  let acknowledged = false;
  let answers, reason = "unreadable";
  try {
    for (let i = 0; i < attempts; i += 1) {
      answers = undefined;
      answers = h.answers("status");
      if (answers.length) {
        if (answers.some((answer) => answer.ok !== false || answer.code !== "not_running")) {
          reason = "wrong_ack";
          throw new Error("toolbar setup status did not acknowledge not_running");
        }
        acknowledged = true;
        break;
      }
      await wait(20);
    }
    if (!acknowledged) {
      reason = "timeout";
      throw new Error("toolbar setup status answer did not arrive");
    }
  } catch (error) {
    reportBarrier(h, started, reason, answers);
    throw error;
  }
  // On a failed barrier, leave the stopped scenario and evidence intact.
  await h.closeRealPopup();
  h.setScenario(scenario);
  h.clearRequests();
}

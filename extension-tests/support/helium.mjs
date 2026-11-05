import { setTimeout as delay } from "node:timers/promises";

function failureType(error) {
  try {
    if (String(error.message).includes("net::ERR_ABORTED")) return "aborted";
    if (error.name === "TimeoutError") return "timeout";
    if (error.name === "TargetClosedError" || /Target closed|Target page, context or browser has been closed/.test(error.message)) return "target_closed";
  } catch {}
  return "other";
}

// Fresh Helium profiles can interrupt navigation with an initial about:blank.
// Retry only this transport error, never an assertion or an extension action.
export async function goto(page, url) {
  const started = performance.now();
  const events = {};
  const listeners = [];
  // Fixed-size aggregates across all attempts; no event payloads are retained.
  try {
    for (const name of ["framenavigated", "domcontentloaded", "load", "close", "crash"]) {
      const key = name === "framenavigated" ? "mainFrameNavigation" : name;
      events[key] = { count: 0, lastMs: null };
      const listener = (frame) => {
        try {
          if (name === "framenavigated" && frame !== page.mainFrame()) return;
          events[key].count++;
          events[key].lastMs = Math.round(performance.now() - started);
        } catch {} // Observation must not affect navigation.
      };
      page.on(name, listener);
      listeners.push([name, listener]);
    }
    for (let attempt = 1; ; attempt += 1) {
      try {
        return await page.goto(url);
      } catch (error) {
        if (attempt >= 3 || !String(error.message).includes("net::ERR_ABORTED")) {
          try {
            console.error("[fixture-goto] " + JSON.stringify({
              elapsedMs: Math.round(performance.now() - started), attempt, errorType: failureType(error), events,
            }));
          } catch {}
          throw error;
        }
        await delay(250);
      }
    }
  } finally {
    for (const [name, listener] of listeners) {
      try { page.off(name, listener); } catch {}
    }
  }
}

// Measure quiet time after a real page load, not from before process launch.
// On a slow runner the old launch-relative sleep could already have expired
// when the warm-up tab opened, letting Helium reload the first test document.
export async function warmUpHelium(page, url) {
  let changed = Date.now();
  const navigation = (frame) => {
    if (frame === page.mainFrame()) changed = Date.now();
  };
  page.on("framenavigated", navigation);
  try {
    await goto(page, url);
    changed = Date.now();
    const deadline = changed + 15_000;
    while (Date.now() - changed < 3_000) {
      if (Date.now() >= deadline) throw new Error("Helium startup navigation did not settle");
      await delay(100);
    }
    await page.waitForLoadState("load");
  } finally {
    page.off("framenavigated", navigation);
  }
}

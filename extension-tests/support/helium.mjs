import { setTimeout as delay } from "node:timers/promises";

// Fresh Helium profiles can interrupt navigation with an initial about:blank.
// Retry only this transport error, never an assertion or an extension action.
export async function goto(page, url) {
  for (let attempt = 1; ; attempt += 1) {
    try {
      return await page.goto(url);
    } catch (error) {
      if (attempt >= 3 || !String(error.message).includes("net::ERR_ABORTED")) throw error;
      await delay(250);
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

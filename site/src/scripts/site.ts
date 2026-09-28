// The interactions of the site. Each one is an enhancement: without JavaScript the
// page shows its final state.

const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---- The latest signed build (worker/index.ts) ----
// Before the first release there is none: header links hide, and the main buttons
// say "Coming soon".
fetch("/latest.json")
  .then(async (res) => {
    if (res.status === 404) {
      for (const link of document.querySelectorAll<HTMLAnchorElement>("a[data-download]")) {
        const label = link.querySelector<HTMLElement>("[data-soon]");
        if (!label) {
          link.hidden = true;
          continue;
        }
        link.removeAttribute("href");
        link.setAttribute("aria-disabled", "true");
        link.classList.add("soon");
        label.textContent = label.dataset.soon ?? "";
      }
    }
    const latest = res.ok ? await res.json() : null;
    if (latest?.version && latest?.build) {
      for (const el of document.querySelectorAll<HTMLElement>("[data-build]")) {
        el.textContent = `v${latest.version} (${latest.build})`;
      }
    }
  })
  .catch(() => {});

// ---- The header gets a background once the page scrolls ----
const header = document.querySelector<HTMLElement>("[data-header]");
const onScroll = () => header?.toggleAttribute("data-scrolled", window.scrollY > 8);
onScroll();
window.addEventListener("scroll", onScroll, { passive: true });

// ---- Reveal, count, type, and play when an element enters the view ----
const onVisible = new Map<Element, () => void>();
const observer = new IntersectionObserver(
  (entries) => {
    for (const entry of entries) {
      if (!entry.isIntersecting) continue;
      entry.target.classList.add("is-visible");
      onVisible.get(entry.target)?.();
      observer.unobserve(entry.target);
    }
  },
  { rootMargin: "0px 0px -10% 0px", threshold: 0.15 },
);
function whenVisible(el: Element, run?: () => void) {
  if (run) onVisible.set(el, run);
  observer.observe(el);
}
document.querySelectorAll("[data-reveal]").forEach((el) => whenVisible(el));

// Numbers count up from 0: <span data-count="76" data-suffix="%">76%</span>.
for (const el of document.querySelectorAll<HTMLElement>("[data-count]")) {
  const target = Number(el.dataset.count);
  const suffix = el.dataset.suffix ?? "";
  if (reduced || !Number.isFinite(target)) continue;
  el.textContent = `0${suffix}`;
  whenVisible(el, () => {
    const start = performance.now();
    const step = (now: number) => {
      const t = Math.min(1, (now - start) / 1400);
      el.textContent = `${Math.round(target * (1 - (1 - t) ** 3))}${suffix}`;
      if (t < 1) requestAnimationFrame(step);
    };
    requestAnimationFrame(step);
  });
}

// A terminal types its lines one by one: each line has data-line; a command line
// (data-cmd) types character by character, an output line appears whole.
for (const term of document.querySelectorAll<HTMLElement>("[data-terminal]")) {
  const lines = [...term.querySelectorAll<HTMLElement>("[data-line]")];
  if (reduced) continue;
  const texts = lines.map((line) => line.querySelector<HTMLElement>("[data-text]")?.textContent ?? "");
  lines.forEach((line) => (line.hidden = true));
  whenVisible(term, async () => {
    const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
    for (const [i, line] of lines.entries()) {
      const text = line.querySelector<HTMLElement>("[data-text]");
      line.hidden = false;
      if (line.hasAttribute("data-cmd") && text) {
        text.textContent = "";
        for (const ch of texts[i]) {
          text.textContent += ch;
          await wait(18 + Math.random() * 30);
        }
        await wait(260);
      } else {
        await wait(140);
      }
    }
  });
}

// ---- Copy buttons: <button data-copy="text"> ----
for (const button of document.querySelectorAll<HTMLButtonElement>("[data-copy]")) {
  const label = button.querySelector<HTMLElement>("[data-copy-label]");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy ?? "");
      if (label) label.textContent = "Copied";
      button.classList.add("copied");
      setTimeout(() => {
        if (label) label.textContent = "Copy";
        button.classList.remove("copied");
      }, 1600);
    } catch {
      if (label) label.textContent = "Select and copy";
    }
  });
}

// ---- A spotlight follows the pointer over cards with data-spotlight ----
for (const card of document.querySelectorAll<HTMLElement>("[data-spotlight]")) {
  card.addEventListener("pointermove", (event) => {
    const box = card.getBoundingClientRect();
    card.style.setProperty("--mx", `${event.clientX - box.left}px`);
    card.style.setProperty("--my", `${event.clientY - box.top}px`);
  });
}

// ---- The hero tiles lean toward the pointer ----
const hero = document.querySelector<HTMLElement>("[data-parallax]");
if (hero && !reduced && window.matchMedia("(pointer: fine)").matches) {
  let frame = 0;
  hero.addEventListener("pointermove", (event) => {
    cancelAnimationFrame(frame);
    frame = requestAnimationFrame(() => {
      const box = hero.getBoundingClientRect();
      hero.style.setProperty("--px", (((event.clientX - box.left) / box.width) * 2 - 1).toFixed(3));
      hero.style.setProperty("--py", (((event.clientY - box.top) / box.height) * 2 - 1).toFixed(3));
    });
  });
  hero.addEventListener("pointerleave", () => {
    hero.style.setProperty("--px", "0");
    hero.style.setProperty("--py", "0");
  });
}

// ---- Popovers open next to their button (the Linux note) ----
for (const pop of document.querySelectorAll<HTMLElement>("[popover]")) {
  pop.addEventListener("beforetoggle", (event) => {
    if ((event as ToggleEvent).newState !== "open") return;
    const button = document.querySelector<HTMLElement>(`[popovertarget="${pop.id}"]`);
    if (!button) return;
    const box = button.getBoundingClientRect();
    const width = Math.min(360, window.innerWidth - 32);
    const left = Math.max(16, Math.min(box.left + box.width / 2 - width / 2, window.innerWidth - width - 16));
    pop.style.width = `${width}px`;
    pop.style.left = `${left}px`;
    pop.style.top = `${box.bottom + 10}px`;
  });
}
window.addEventListener(
  "scroll",
  () => document.querySelectorAll<HTMLElement>("[popover]:popover-open").forEach((pop) => pop.hidePopover()),
  { passive: true },
);

// ---- Gallery tabs: click, arrow keys, and autoplay with a progress bar ----
for (const gallery of document.querySelectorAll<HTMLElement>("[data-gallery]")) {
  const tabs = [...gallery.querySelectorAll<HTMLButtonElement>("[role=tab]")];
  const panels = [...gallery.querySelectorAll<HTMLElement>("[role=tabpanel]")];
  const INTERVAL = 6500;
  let current = 0;
  let timer = 0;
  let paused = false;
  const select = (index: number, focus = false) => {
    current = (index + tabs.length) % tabs.length;
    tabs.forEach((tab, i) => {
      const on = i === current;
      tab.setAttribute("aria-selected", String(on));
      tab.tabIndex = on ? 0 : -1;
      tab.classList.remove("playing");
      panels[i].toggleAttribute("data-active", on);
      panels[i].setAttribute("aria-hidden", String(!on));
    });
    if (focus) tabs[current].focus();
    // Keep the tab in view in a row that scrolls (small screens), without a page scroll.
    const list = tabs[current].parentElement;
    if (list && list.scrollWidth > list.clientWidth) {
      list.scrollTo({ left: tabs[current].offsetLeft - list.clientWidth / 2 + tabs[current].offsetWidth / 2, behavior: reduced ? "auto" : "smooth" });
    }
    restart();
  };
  const restart = () => {
    clearTimeout(timer);
    if (reduced || paused) return;
    const tab = tabs[current];
    tab.classList.remove("playing");
    void tab.offsetWidth; // restart the progress animation
    tab.classList.add("playing");
    timer = window.setTimeout(() => select(current + 1), INTERVAL);
  };
  const pause = (on: boolean) => {
    paused = on;
    gallery.toggleAttribute("data-paused", on);
    if (on) clearTimeout(timer);
    else restart();
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(i));
    tab.addEventListener("keydown", (event) => {
      if (event.key === "ArrowRight") select(current + 1, true);
      if (event.key === "ArrowLeft") select(current - 1, true);
    });
  });
  gallery.addEventListener("pointerenter", () => pause(true));
  gallery.addEventListener("pointerleave", () => pause(false));
  gallery.addEventListener("focusin", () => pause(true));
  gallery.addEventListener("focusout", () => pause(false));
  document.addEventListener("visibilitychange", () => pause(document.hidden));
  // Autoplay only while the gallery is on screen.
  new IntersectionObserver(([entry]) => pause(!entry.isIntersecting)).observe(gallery);
  whenVisible(gallery, () => select(0));
}

// ---- The bouncer feed: requests arrive, get checked, and get a verdict ----
for (const feed of document.querySelectorAll<HTMLElement>("[data-feed]")) {
  const rows = [...feed.querySelectorAll<HTMLElement>("[data-feed-row]")];
  if (reduced) continue;
  const wait = (ms: number) => new Promise((r) => setTimeout(r, ms));
  const play = async () => {
    for (;;) {
      rows.forEach((row) => row.classList.remove("in", "done"));
      await wait(500);
      for (const row of rows) {
        row.classList.add("in");
        await wait(700);
        row.classList.add("done");
        await wait(500);
      }
      await wait(3800);
      feed.classList.add("fading");
      await wait(450);
      feed.classList.remove("fading");
    }
  };
  feed.classList.add("animated");
  whenVisible(feed, play);
}

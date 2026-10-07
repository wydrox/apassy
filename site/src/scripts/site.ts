// The interactions of the site. Each one is an enhancement: without JavaScript the
// page shows its final state.

const reduced = window.matchMedia("(prefers-reduced-motion: reduce)").matches;

// ---- The latest signed build (worker/index.ts) ----
// Before the first release there is none: header links hide, and the main buttons
// say "Coming soon". A main button with an install note opens it (the command of
// scripts/install.sh), so there is still a way to install.
fetch("/latest.json")
  .then(async (res) => {
    if (res.status === 404) {
      for (const link of document.querySelectorAll<HTMLAnchorElement>("a[data-download]")) {
        const label = link.querySelector<HTMLElement>("[data-soon]");
        if (!label) {
          link.hidden = true;
          continue;
        }
        label.textContent = label.dataset.soon ?? "";
        const note = link.dataset.soonNote && document.getElementById(link.dataset.soonNote);
        if (note) {
          link.replaceWith(soonButton(link, note.id));
          continue;
        }
        link.removeAttribute("href");
        link.setAttribute("aria-disabled", "true");
        link.classList.add("soon");
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

// A button with the classes, the attributes (also the scoped-style ones), and the
// content of `link`, which opens the popover `noteId`.
function soonButton(link: HTMLAnchorElement, noteId: string): HTMLButtonElement {
  const button = document.createElement("button");
  for (const { name, value } of [...link.attributes]) {
    if (name !== "href" && !name.startsWith("data-download") && name !== "data-soon-note") button.setAttribute(name, value);
  }
  button.type = "button";
  button.classList.add("soon");
  button.setAttribute("popovertarget", noteId);
  button.setAttribute("aria-haspopup", "dialog");
  button.setAttribute("aria-expanded", "false");
  button.append(...link.childNodes);
  return button;
}

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
// A live region next to the button (data-copy-status) says the result to screen
// readers, because the aria-label of the button hides its changing label.
for (const button of document.querySelectorAll<HTMLButtonElement>("[data-copy]")) {
  const label = button.querySelector<HTMLElement>("[data-copy-label]");
  const status = button.parentElement?.querySelector<HTMLElement>("[data-copy-status]");
  button.addEventListener("click", async () => {
    try {
      await navigator.clipboard.writeText(button.dataset.copy ?? "");
      if (label) label.textContent = "Copied";
      if (status) status.textContent = "Copied to the clipboard.";
      button.classList.add("copied");
      setTimeout(() => {
        if (label) label.textContent = "Copy";
        if (status) status.textContent = "";
        button.classList.remove("copied");
      }, 1600);
    } catch {
      if (label) label.textContent = "Select and copy";
      if (status) status.textContent = "Copy failed. Select the command and copy it.";
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

// ---- Popovers open next to their button (the install and Linux notes) ----
// Below the button, or above it when the space below is too small. data-width sets
// the width (default 360). An open note follows its button when the page scrolls.
const triggerOf = (pop: HTMLElement) => document.querySelector<HTMLElement>(`[popovertarget="${pop.id}"]`);
function place(pop: HTMLElement) {
  const button = triggerOf(pop);
  if (!button) return;
  const box = button.getBoundingClientRect();
  const width = Math.min(Number(pop.dataset.width) || 360, window.innerWidth - 32);
  const left = Math.max(16, Math.min(box.left + box.width / 2 - width / 2, window.innerWidth - width - 16));
  pop.style.width = `${width}px`;
  pop.style.left = `${left}px`;
  const height = pop.offsetHeight;
  const fitsBelow = box.bottom + 10 + height <= window.innerHeight - 8;
  const above = !fitsBelow && box.top - 10 - height >= 8;
  pop.toggleAttribute("data-above", above);
  // When it fits neither below nor above, keep it on screen (it scrolls inside).
  const top = fitsBelow ? box.bottom + 10 : above ? box.top - 10 - height : Math.max(8, window.innerHeight - height - 8);
  pop.style.top = `${top}px`;
}
for (const pop of document.querySelectorAll<HTMLElement>("[popover]")) {
  pop.addEventListener("beforetoggle", (event) => {
    if ((event as ToggleEvent).newState === "open") place(pop);
  });
  pop.addEventListener("toggle", (event) => {
    const open = (event as ToggleEvent).newState === "open";
    // The height is known only once the note is open.
    if (open) place(pop);
    triggerOf(pop)?.setAttribute("aria-expanded", String(open));
  });
}
let placing = 0;
const placeOpen = () => {
  cancelAnimationFrame(placing);
  placing = requestAnimationFrame(() => document.querySelectorAll<HTMLElement>("[popover]:popover-open").forEach(place));
};
window.addEventListener("scroll", placeOpen, { passive: true });
window.addEventListener("resize", placeOpen);

// ---- Gallery tabs: click, arrow keys, and autoplay with a progress bar ----
// Autoplay waits while any reason holds: the gallery is off screen, the page is hidden,
// the pointer is on the tabs, or a tab has keyboard focus. Each reason is its own flag:
// one that ends does not restart a gallery that another one still holds. The pointer on
// the large screenshot does not hold it: a visitor who scrolls with a trackpad leaves
// the pointer there, and the gallery then never moved.
for (const gallery of document.querySelectorAll<HTMLElement>("[data-gallery]")) {
  const tabs = [...gallery.querySelectorAll<HTMLButtonElement>("[role=tab]")];
  const panels = [...gallery.querySelectorAll<HTMLElement>("[role=tabpanel]")];
  const list = gallery.querySelector<HTMLElement>("[role=tablist]");
  const INTERVAL = 6500;
  let current = 0;
  let timer = 0;
  const holds = new Set<string>(["offscreen"]);
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
    if (list && list.scrollWidth > list.clientWidth) {
      list.scrollTo({ left: tabs[current].offsetLeft - list.clientWidth / 2 + tabs[current].offsetWidth / 2, behavior: reduced ? "auto" : "smooth" });
    }
    restart();
  };
  const restart = () => {
    clearTimeout(timer);
    const tab = tabs[current];
    tab.classList.remove("playing");
    if (reduced || holds.size > 0) return;
    void tab.offsetWidth; // restart the progress animation
    tab.classList.add("playing");
    timer = window.setTimeout(() => select(current + 1), INTERVAL);
  };
  const hold = (reason: string, on: boolean) => {
    const was = holds.size > 0;
    if (on) holds.add(reason);
    else holds.delete(reason);
    const now = holds.size > 0;
    gallery.toggleAttribute("data-paused", now);
    if (now && !was) clearTimeout(timer);
    // A hold that ends starts the current tab again, with its full time.
    if (!now && was) restart();
  };
  tabs.forEach((tab, i) => {
    tab.addEventListener("click", () => select(i));
    tab.addEventListener("keydown", (event) => {
      if (event.key === "ArrowRight") select(current + 1, true);
      if (event.key === "ArrowLeft") select(current - 1, true);
    });
  });
  list?.addEventListener("pointerenter", (event) => hold("pointer", event.pointerType === "mouse"));
  list?.addEventListener("pointerleave", () => hold("pointer", false));
  // A mouse click also focuses a tab in some browsers; only keyboard focus holds.
  gallery.addEventListener("focusin", (event) => hold("focus", (event.target as Element).matches(":focus-visible")));
  gallery.addEventListener("focusout", (event) => {
    if (!gallery.contains(event.relatedTarget as Node | null)) hold("focus", false);
  });
  document.addEventListener("visibilitychange", () => hold("hidden", document.hidden));
  // Autoplay only while at least a fifth of the gallery is on screen.
  new IntersectionObserver(([entry]) => hold("offscreen", entry.intersectionRatio < 0.2), { threshold: [0, 0.2] }).observe(gallery);
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

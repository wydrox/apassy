// Builders for the Apassy app UI (light, as in the real app), the agent terminal (dark),
// icons, and shared video components. The logo is in logo.js.

import { el, clamp, prog, ease, lerp, tf, spring } from './engine.js';

// ---- Icons: 16×16, stroke, currentColor. Close to the SF Symbols the app draws. ----

const P = {
  key: '<circle cx="5" cy="8" r="3"/><path d="M8 8h6.2M12.2 8v2.6M14.2 8v2"/>',
  person: '<circle cx="8" cy="5.3" r="2.7"/><path d="M2.8 14.2c.3-3 2.5-4.7 5.2-4.7s4.9 1.7 5.2 4.7"/>',
  tray: '<path d="M2 9.2h3.6l1 1.8h2.8l1-1.8H14"/><path d="M3.6 3h8.8l1.6 6.2v3.3a1.5 1.5 0 0 1-1.5 1.5h-9A1.5 1.5 0 0 1 2 12.5V9.2z"/>',
  chart: '<path d="M3 14V9.5M8 14V6M13 14V2.5"/>',
  gear: '<circle cx="8" cy="8" r="2.3"/><path d="M8 1.6v2M8 12.4v2M1.6 8h2M12.4 8h2M3.5 3.5l1.4 1.4M11.1 11.1l1.4 1.4M3.5 12.5l1.4-1.4M11.1 4.9l1.4-1.4"/>',
  lock: '<rect x="3" y="7" width="10" height="7.2" rx="1.6"/><path d="M5.2 7V5a2.8 2.8 0 0 1 5.6 0v2"/>',
  unlock: '<rect x="3" y="7" width="10" height="7.2" rx="1.6"/><path d="M5.2 7V5a2.8 2.8 0 0 1 5.4-1"/>',
  plus: '<path d="M8 3v10M3 8h10"/>',
  chevR: '<path d="M6 3l5 5-5 5"/>',
  chevD: '<path d="M3 6l5 5 5-5"/>',
  chevUD: '<path d="M4.5 6L8 2.8 11.5 6M4.5 10L8 13.2 11.5 10"/>',
  terminal: '<path d="M3.5 4.5l3.5 3.5-3.5 3.5M8.5 12h4.5"/>',
  database: '<ellipse cx="8" cy="3.8" rx="5" ry="2"/><path d="M3 3.8v8.4c0 1.1 2.2 2 5 2s5-.9 5-2V3.8M3 8c0 1.1 2.2 2 5 2s5-.9 5-2"/>',
  asterisk: '<path d="M8 2.5v11M3.2 5.2l9.6 5.6M3.2 10.8l9.6-5.6"/>',
  shield: '<path d="M8 1.6l5.6 2.1v4.2c0 3.3-2.3 5.5-5.6 6.7-3.3-1.2-5.6-3.4-5.6-6.7V3.7z"/>',
  shieldCheck: '<path d="M8 1.6l5.6 2.1v4.2c0 3.3-2.3 5.5-5.6 6.7-3.3-1.2-5.6-3.4-5.6-6.7V3.7z"/><path d="M5.5 8l1.8 1.8L10.8 6"/>',
  globe: '<circle cx="8" cy="8" r="6.2"/><ellipse cx="8" cy="8" rx="2.6" ry="6.2"/><path d="M2 8h12"/>',
  check: '<path d="M3.2 8.6l3 3 6.6-7.2"/>',
  warning: '<path d="M8 2.2l6.3 11H1.7z"/><path d="M8 6.5v3M8 11.4v.1"/>',
  xmark: '<path d="M4 4l8 8M12 4l-8 8"/>',
  clock: '<circle cx="8" cy="8" r="6.2"/><path d="M8 4.5V8l2.5 1.6"/>',
  folder: '<path d="M1.8 4.6a1 1 0 0 1 1-1h3.4l1.5 1.6h5.5a1 1 0 0 1 1 1v6.4a1 1 0 0 1-1 1H2.8a1 1 0 0 1-1-1z"/>',
  eye: '<path d="M1.5 8c2-3.4 4.2-4.6 6.5-4.6s4.5 1.2 6.5 4.6c-2 3.4-4.2 4.6-6.5 4.6S3.5 11.4 1.5 8z"/><circle cx="8" cy="8" r="2"/>',
  eyeOff: '<path d="M1.5 8c2-3.4 4.2-4.6 6.5-4.6s4.5 1.2 6.5 4.6c-2 3.4-4.2 4.6-6.5 4.6S3.5 11.4 1.5 8z"/><path d="M2.5 2.5l11 11"/>',
  search: '<circle cx="7" cy="7" r="4.5"/><path d="M10.4 10.4L14 14"/>',
  bolt: '<path d="M9 1.5L3.8 9h4L7 14.5 12.2 7h-4z"/>',
  cpu: '<rect x="4" y="4" width="8" height="8" rx="1.5"/><path d="M6.5 1.8v2M9.5 1.8v2M6.5 12.2v2M9.5 12.2v2M1.8 6.5h2M1.8 9.5h2M12.2 6.5h2M12.2 9.5h2"/>',
  laptop: '<rect x="3" y="3.5" width="10" height="7" rx="1"/><path d="M1.5 12.5h13"/>',
  box: '<path d="M8 1.8l5.6 3.1v6.2L8 14.2l-5.6-3.1V4.9z"/><path d="M2.4 4.9L8 8l5.6-3.1M8 8v6.2"/>',
  sparkle: '<path d="M8 1.8c.5 3.2 2.1 4.8 5.3 5.3v.1c-3.2.5-4.8 2.1-5.3 5.3-.5-3.2-2.1-4.8-5.3-5.3v-.1C5.9 6.6 7.5 5 8 1.8z"/>',
  arrowR: '<path d="M2.5 8h10.5M9 4l4 4-4 4"/>',
  pause: '<path d="M5.5 3.5v9M10.5 3.5v9"/>',
  minus: '<path d="M3.5 8h9"/>',
  hand: '<path d="M5 8.5V3.8a1.1 1.1 0 0 1 2.2 0V7.5M7.2 7V2.9a1.1 1.1 0 0 1 2.2 0V7M9.4 7V3.6a1.1 1.1 0 0 1 2.2 0v5.2c0 3-1.6 5.4-4.4 5.4-1.8 0-2.7-.8-3.7-2.4L2.1 9.2a1.1 1.1 0 0 1 1.8-1.2L5 9.3"/>',
  ban: '<circle cx="8" cy="8" r="6"/><path d="M3.8 3.8l8.4 8.4"/>',
  code: '<path d="M5.5 4.5L2 8l3.5 3.5M10.5 4.5L14 8l-3.5 3.5"/>',
  file: '<path d="M4 1.8h5l3.2 3.2v8.2a1 1 0 0 1-1 1H4a1 1 0 0 1-1-1V2.8a1 1 0 0 1 1-1z"/><path d="M9 1.8V5h3.2"/>',
  gauge: '<path d="M2.5 11.5a5.5 5.5 0 1 1 11 0"/><path d="M8 11.5l2.6-3.6"/>',
};

export const ic = (name, cls = '', sw = 1.6) =>
  `<svg class="${cls}" viewBox="0 0 16 16" fill="none" stroke="currentColor" stroke-width="${sw}" stroke-linecap="round" stroke-linejoin="round">${P[name]}</svg>`;

export const KIND = {
  api: ['key', '#ff9500'],
  login: ['person', '#007aff'],
  ssh: ['terminal', '#5856d6'],
  db: ['database', '#34aa5a'],
  custom: ['asterisk', '#8e8e93'],
};

export const tile = (name, color, size = 22) =>
  `<div class="tile" style="background:${color};width:${size}px;height:${size}px;border-radius:${Math.round(size * 0.26)}px">${ic(name, '', 1.9)}</div>`;

// ---- App pieces. ----

export function navRow({ kind, title, sub, det = '', mono = false, cls = '', id = '' }) {
  const [icon, color] = KIND[kind];
  return `<div class="row ${cls}" ${id ? `id="${id}"` : ''}>${tile(icon, color)}<div class="tt"><div class="t1">${title}</div>${sub ? `<div class="t2">${sub}</div>` : ''}</div><div class="det ${mono ? 'm' : ''}">${det}</div>${ic('chevR', 'chev', 1.8)}</div>`;
}

export const section = (header, rows, footer = '', cls = '') =>
  `<div class="sec ${cls}">${header ? `<div class="sh">${header}</div>` : ''}<div class="box">${rows}</div>${footer ? `<div class="sf">${footer}</div>` : ''}</div>`;

export function sidebar(sel = 'Credentials', { vault = 9, activity = 0 } = {}) {
  const items = [
    ['key', 'Credentials', vault ? `<span class="badge">${vault}</span>` : ''],
    ['person', 'Agents', ''],
    ['tray', 'Activity', activity ? `<span class="badge warn">${activity}</span>` : ''],
    ['chart', 'Learning', ''],
  ];
  return `<div class="side"><div class="traffic"><i></i><i></i><i></i></div>
    ${items.map(([i, l, b]) => `<div class="sitem ${l === sel ? 'sel' : ''}">${ic(i)}${l}${b}</div>`).join('')}
    <div class="sfoot"><div class="lockrow"><span class="lk">${ic('lock')}Lock</span><span class="fn">vault.db</span></div>
    <div class="sitem ${sel === 'Settings' ? 'sel' : ''}">${ic('gear')}Settings</div></div></div>`;
}

/** The app window: a div.app.win with the sidebar and a page. Size in points. */
export function appWindow(parent, { w = 1180, h = 760, sel = 'Credentials', badges = {}, page = '' } = {}) {
  const win = el('div', 'app win', parent);
  win.style.width = `${w}px`;
  win.style.height = `${h}px`;
  win.innerHTML = `${sidebar(sel, badges)}<div class="main"><div class="page">${page}</div></div>`;
  return win;
}

export const btn = (label, style = 'bor', size = '', icon = '') =>
  `<span class="btn ${style} ${size}">${icon ? ic(icon) : ''}${label}</span>`;

// ---- The agent terminal (dark, Claude Code style). ----

export function terminal(parent, { title = 'claude — ~/dev/acme-api', w = 900, h = 420, cls = '' } = {}) {
  const t = el('div', `term ${cls}`, parent);
  t.style.width = `${w}px`;
  t.style.height = `${h}px`;
  t.innerHTML = `<div class="tbar"><div class="traffic"><i></i><i></i><i></i></div><div class="ttl">${title}</div></div><div class="tbody"></div>`;
  t.body = t.querySelector('.tbody');
  return t;
}

/** A terminal line from segments: [[text, cls], ...]. Returns the line element. */
export function tline(term, segs, cls = '') {
  const l = el('div', `tl ${cls}`, term.body);
  l.segs = segs.map(([text, c]) => ({ text, c: c || '' }));
  l.total = l.segs.reduce((n, s) => n + [...s.text].length, 0);
  l.innerHTML = l.segs.map((s) => `<span class="${s.c}">${esc(s.text)}</span>`).join('');
  l.spans = [...l.querySelectorAll('span')];
  return l;
}

export const esc = (s) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');

/** Type a line: show the first n characters (n from t, t0, and chars per second). */
export function typeLine(l, t, t0, cps = 40, caret = false) {
  const n = t < t0 ? 0 : Math.min(l.total, Math.floor((t - t0) * cps));
  let left = n;
  l.segs.forEach((s, i) => {
    const chars = [...s.text];
    const k = Math.max(0, Math.min(chars.length, left));
    left -= k;
    l.spans[i].textContent = chars.slice(0, k).join('');
  });
  l.style.visibility = t >= t0 ? 'visible' : 'hidden';
  if (caret) l.classList.toggle('typing', n < l.total && t >= t0);
  return n / l.total;
}

/** Show a whole line at t0 with a quick rise. */
export function popLine(l, t, t0, dy = 10) {
  const p = prog(t, t0, t0 + 0.25);
  tf(l, { y: (1 - ease.outCubic(p)) * dy, o: p > 0 ? ease.outCubic(clamp(p * 1.5)) : 0 });
}

// ---- Video components. ----

/** A kinetic headline. Returns { el, w: word spans }. */
export function headline(parent, text, { size = 110, top = 120, cls = '', weight = 700 } = {}) {
  const h = el('div', `hx ${cls}`, parent);
  h.style.fontSize = `${size}px`;
  h.style.top = `${top}px`;
  h.style.fontWeight = weight;
  const w = [];
  text.split('\n').forEach((line, i) => {
    if (i) el('br', '', h);
    w.push(...wordsInto(h, line));
  });
  return { el: h, w };
}

function wordsInto(h, line) {
  const out = [];
  for (const tok of line.split(/\s+/)) {
    if (!tok) continue;
    let cls = 'w';
    let word = tok;
    const m = tok.match(/^\[([\w-]+):(.+)\]([.,!?:;]*)$/);
    if (m) {
      cls += ` ${m[1]}`;
      word = m[2] + m[3];
    } else if (/^\*.+\*[.,!?:;]*$/.test(tok)) {
      cls += ' hl';
      word = tok.replace(/^\*(.+)\*([.,!?:;]*)$/, '$1$2');
    }
    const s = el('span', cls, h);
    s.textContent = word.replace(/_/g, ' ');
    out.push(s);
    h.appendChild(document.createTextNode(' '));
  }
  return out;
}

/** A white pill with an icon. */
export function chip(parent, icon, text, { color = '#0a77fe', cls = '' } = {}) {
  const c = el('div', `chip ${cls}`, parent);
  c.innerHTML = `${icon ? `<span class="ci" style="color:${color}">${ic(icon, '', 1.7)}</span>` : ''}<span>${text}</span>`;
  return c;
}

/** The macOS pointer. */
export function cursor(parent) {
  const c = el('div', 'cursor', parent);
  c.innerHTML = `<svg viewBox="0 0 28 28" width="34" height="34"><path d="M8.2 4.2v17.6l4.3-4.1 2.8 6.3 3-1.3-2.8-6.2h6z" fill="#111" stroke="#fff" stroke-width="1.6" stroke-linejoin="round"/></svg><div class="ripple"></div>`;
  c.ripple = c.querySelector('.ripple');
  return c;
}

/**
 * Move the cursor along keys [[t, x, y], ...] with smooth easing, and show click ripples at
 * the given times.
 */
export function moveCursor(c, t, keys, clicks = []) {
  let x = keys[0][1];
  let y = keys[0][2];
  for (let i = 1; i < keys.length; i++) {
    const [t0, x0, y0] = keys[i - 1];
    const [t1, x1, y1] = keys[i];
    if (t >= t0) {
      const p = ease.inOutCubic(prog(t, t0, t1));
      // A slight arc.
      const arc = Math.sin(Math.PI * p) * Math.min(60, Math.hypot(x1 - x0, y1 - y0) * 0.12);
      x = lerp(x0, x1, p) + arc * 0.3;
      y = lerp(y0, y1, p) - arc;
    }
  }
  let press = 0;
  let rip = -1;
  for (const ct of clicks) {
    if (t >= ct - 0.08 && t < ct + 0.12) press = 1 - Math.abs(t - ct) / 0.12;
    if (t >= ct && t < ct + 0.5) rip = (t - ct) / 0.5;
  }
  c.style.transform = `translate(${x.toFixed(1)}px,${y.toFixed(1)}px) scale(${(1 - 0.12 * clamp(press)).toFixed(3)})`;
  if (rip >= 0) {
    c.ripple.style.opacity = (1 - rip).toFixed(3);
    c.ripple.style.transform = `translate(-50%,-50%) scale(${(0.3 + ease.outCubic(rip) * 1.4).toFixed(3)})`;
  } else c.ripple.style.opacity = 0;
}

/** Spring pop-in: scale and opacity from t0. Gentle: a small scale, almost no overshoot. */
export function pop(e, t, t0, { from = 0.9, freq = 2.2, damp = 0.85, x = 0, y = 0, center = false, blur = 0 } = {}) {
  const k = spring(t - t0, freq, damp);
  const o = clamp((t - t0) / 0.12);
  tf(e, { center, x, y, s: lerp(from, 1, k), o: t < t0 ? 0 : o, blur: blur ? (1 - clamp((t - t0) / 0.3)) * blur : undefined });
}

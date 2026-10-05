// The animation engine: a deterministic timeline. renderAt(t) draws the frame at t seconds.
// Every value is a pure function of t, so a frame renders the same way at any time and
// in any order. That lets render.mjs capture frames in parallel and with sub-frames.

/**
 * The format: 'wide' (16:9, the default), 'tall' (9:16: Reels, TikTok, Shorts), or 'feed'
 * (4:5: the X, Threads, and LinkedIn feeds; only the shorts have a feed layout).
 */
const FORMATS = { wide: [1920, 1080], tall: [1080, 1920], feed: [1080, 1350] };
const asked = new URLSearchParams(globalThis.location?.search ?? '').get('format');
export const FORMAT = FORMATS[asked] ? asked : 'wide';
export const [W, H] = FORMATS[FORMAT];
export const TALL = FORMAT === 'tall';
/** The value for the current format. */
export const pick = (wide, tall) => (TALL ? tall : wide);
export const BPM = 120; // the grid; the film plays slower (PACE in timeline.js)
/** Seconds of `n` beats. */
export const beat = (n) => (n * 60) / BPM;
/** Seconds of `n` bars (4/4). */
export const bar = (n) => beat(n * 4);

// ---- Math ----

export const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
export const lerp = (a, b, t) => a + (b - a) * t;
/** Normalized progress of t between t0 and t1, clamped to 0..1. */
export const prog = (t, t0, t1) => (t1 === t0 ? (t >= t1 ? 1 : 0) : clamp((t - t0) / (t1 - t0)));
export const smooth = (x) => x * x * (3 - 2 * x);
export const mix = (a, b, t) => a.map((v, i) => lerp(v, b[i], t));

export const ease = {
  linear: (x) => x,
  inQuad: (x) => x * x,
  outQuad: (x) => 1 - (1 - x) * (1 - x),
  inOutQuad: (x) => (x < 0.5 ? 2 * x * x : 1 - Math.pow(-2 * x + 2, 2) / 2),
  inCubic: (x) => x * x * x,
  outCubic: (x) => 1 - Math.pow(1 - x, 3),
  inOutCubic: (x) => (x < 0.5 ? 4 * x * x * x : 1 - Math.pow(-2 * x + 2, 3) / 2),
  outQuart: (x) => 1 - Math.pow(1 - x, 4),
  inQuart: (x) => x ** 4,
  inOutQuart: (x) => (x < 0.5 ? 8 * x ** 4 : 1 - Math.pow(-2 * x + 2, 4) / 2),
  outQuint: (x) => 1 - Math.pow(1 - x, 5),
  inQuint: (x) => x ** 5,
  inOutQuint: (x) => (x < 0.5 ? 16 * x ** 5 : 1 - Math.pow(-2 * x + 2, 5) / 2),
  outExpo: (x) => (x >= 1 ? 1 : 1 - Math.pow(2, -10 * x)),
  inExpo: (x) => (x <= 0 ? 0 : Math.pow(2, 10 * x - 10)),
  inOutExpo: (x) =>
    x <= 0 ? 0 : x >= 1 ? 1 : x < 0.5 ? Math.pow(2, 20 * x - 10) / 2 : (2 - Math.pow(2, -20 * x + 10)) / 2,
  inOutSine: (x) => -(Math.cos(Math.PI * x) - 1) / 2,
  outSine: (x) => Math.sin((x * Math.PI) / 2),
  inSine: (x) => 1 - Math.cos((x * Math.PI) / 2),
  outBack: (x, s = 1.70158) => 1 + (s + 1) * Math.pow(x - 1, 3) + s * Math.pow(x - 1, 2),
  inBack: (x, s = 1.70158) => (s + 1) * x * x * x - s * x * x,
  inOutBack: (x, s = 1.70158 * 1.525) =>
    x < 0.5
      ? (Math.pow(2 * x, 2) * ((s + 1) * 2 * x - s)) / 2
      : (Math.pow(2 * x - 2, 2) * ((s + 1) * (x * 2 - 2) + s) + 2) / 2,
};

/** A tween: the value between a and b at time t, for the interval t0..t1. */
export const tw = (t, t0, t1, a, b, e = ease.outCubic) => lerp(a, b, e(prog(t, t0, t1)));

/**
 * Keyframes: [[time, value, ease?], ...]. The ease of a key shapes the segment that ends
 * at that key. Before the first key and after the last, the value holds.
 */
export function kf(t, keys) {
  if (t <= keys[0][0]) return keys[0][1];
  for (let i = 1; i < keys.length; i++) {
    const [t1, v1, e = ease.inOutCubic] = keys[i];
    const [t0, v0] = keys[i - 1];
    if (t <= t1) return lerp(v0, v1, e(prog(t, t0, t1)));
  }
  return keys[keys.length - 1][1];
}

/**
 * A damped spring from 0 to 1, started at time 0. `freq` is the natural frequency in Hz,
 * `damp` the damping ratio (below 1 overshoots).
 */
export function spring(t, freq = 3, damp = 0.55) {
  if (t <= 0) return 0;
  const w = 2 * Math.PI * freq;
  if (damp >= 1) return 1 - (1 + w * t) * Math.exp(-w * t);
  const wd = w * Math.sqrt(1 - damp * damp);
  return 1 - Math.exp(-damp * w * t) * (Math.cos(wd * t) + ((damp * w) / wd) * Math.sin(wd * t));
}

/** Spring value between a and b, started at t0. */
export const sp = (t, t0, a, b, freq, damp) => lerp(a, b, spring(t - t0, freq, damp));

/** 0 → 1 → 0 bump over t0..t1 (a sine hump). */
export const hump = (t, t0, t1) => {
  const p = prog(t, t0, t1);
  return p <= 0 || p >= 1 ? 0 : Math.sin(Math.PI * p);
};

/** In over a..b, hold, out over c..d. */
export const window4 = (t, a, b, c, d, ei = ease.outCubic, eo = ease.inCubic) =>
  t < c ? ei(prog(t, a, b)) : 1 - eo(prog(t, c, d));

// ---- Seeded randomness and noise ----

export function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let x = a;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}

/** A hash of integer n to 0..1. */
export const hash = (n) => {
  let x = Math.imul((n | 0) ^ 0x9e3779b9, 0x85ebca6b);
  x ^= x >>> 13;
  x = Math.imul(x, 0xc2b2ae35);
  x ^= x >>> 16;
  return (x >>> 0) / 4294967296;
};

/** Smooth 1D value noise in -1..1. */
export function noise(x, seed = 0) {
  const i = Math.floor(x);
  const f = x - i;
  const a = hash(i * 7919 + seed * 104729) * 2 - 1;
  const b = hash((i + 1) * 7919 + seed * 104729) * 2 - 1;
  return lerp(a, b, smooth(f));
}

// ---- DOM ----

export function el(tag, cls, parent, html) {
  const e = document.createElement(tag);
  if (cls) e.className = cls;
  if (html != null) e.innerHTML = html;
  if (parent) parent.appendChild(e);
  return e;
}

const fmt = (v) => (Math.abs(v) < 1e-4 ? 0 : Math.round(v * 1000) / 1000);

/**
 * Set the transform, opacity, and filter of an element in one call.
 * Keys: x, y, z (px), s, sx, sy, r (deg), rx, ry, o (opacity), blur (px), center (bool:
 * translate(-50%,-50%) first), bright, sat.
 */
export function tf(e, p) {
  let t = '';
  if (p.center) t += 'translate(-50%,-50%) ';
  if (p.x || p.y || p.z) t += `translate3d(${fmt(p.x || 0)}px,${fmt(p.y || 0)}px,${fmt(p.z || 0)}px) `;
  if (p.rx) t += `rotateX(${fmt(p.rx)}deg) `;
  if (p.ry) t += `rotateY(${fmt(p.ry)}deg) `;
  if (p.r) t += `rotate(${fmt(p.r)}deg) `;
  if (p.s != null && p.s !== 1) t += `scale(${fmt(p.s)}) `;
  if (p.sx != null || p.sy != null) t += `scale(${fmt(p.sx ?? 1)},${fmt(p.sy ?? 1)}) `;
  e.style.transform = t || 'none';
  if (p.o != null) e.style.opacity = fmt(clamp(p.o));
  let f = '';
  if (p.blur > 0.05) f += `blur(${fmt(p.blur)}px) `;
  if (p.bright != null && p.bright !== 1) f += `brightness(${fmt(p.bright)}) `;
  if (p.sat != null && p.sat !== 1) f += `saturate(${fmt(p.sat)}) `;
  if (p.blur != null || p.bright != null || p.sat != null) e.style.filter = f || 'none';
}

export const show = (e, on) => {
  e.style.display = on ? '' : 'none';
};

// ---- Text ----

/**
 * Split text into word spans. Markup: *word* gets class "hl", [c:word] gets class c
 * (for example [blue:never]). Words keep their spaces. Returns the word spans.
 */
export function words(parent, text, cls = 'w') {
  const out = [];
  const tokens = text.split(/(\s+)/);
  for (const tok of tokens) {
    if (!tok) continue;
    if (/^\s+$/.test(tok)) {
      parent.appendChild(document.createTextNode(' '));
      continue;
    }
    let w = tok;
    let extra = '';
    const m = w.match(/^\[([\w-]+):(.+)\]([.,!?:;]*)$/);
    if (m) {
      extra = m[1];
      w = m[2] + m[3];
    } else if (/^\*.+\*[.,!?:;]*$/.test(w)) {
      extra = 'hl';
      w = w.replace(/^\*(.+)\*([.,!?:;]*)$/, '$1$2');
    }
    const s = el('span', `${cls} ${extra}`.trim(), parent);
    s.textContent = w.replace(/_/g, ' ');
    out.push(s);
  }
  return out;
}

/** Split text into character spans (spaces kept as spans too). */
export function chars(parent, text, cls = 'c') {
  const out = [];
  for (const ch of text) {
    const s = el('span', cls, parent);
    s.textContent = ch === ' ' ? ' ' : ch;
    out.push(s);
  }
  return out;
}

/**
 * Word reveal: each word rises a little and fades in, then optionally leaves. Calm by
 * default: a small rise, no blur. `style` is 'rise', 'pop', 'drop', or 'mask'.
 */
export function revealWords(spans, t, t0, { stagger = 0.045, dur = 0.8, dy = 26, blur = 0, style = 'rise', out = null, outDur = 0.35, outStagger = 0.015 } = {}) {
  spans.forEach((s, i) => {
    const a = t0 + i * stagger;
    const p = prog(t, a, a + dur);
    let o = ease.outCubic(clamp(p * 1.5));
    let y = 0;
    let sc = 1;
    let b = 0;
    let r = 0;
    if (style === 'rise') {
      y = (1 - ease.outQuart(p)) * dy;
      b = (1 - ease.outCubic(p)) * blur;
    } else if (style === 'pop') {
      sc = lerp(0.4, 1, spring(t - a, 2.6, 0.5));
      b = (1 - ease.outCubic(p)) * blur * 0.6;
      o = ease.outCubic(clamp(p * 3));
    } else if (style === 'drop') {
      y = -(1 - ease.outExpo(p)) * dy;
      b = (1 - ease.outCubic(p)) * blur;
    } else if (style === 'mask') {
      y = (1 - ease.outExpo(p)) * 110;
      o = p > 0 ? 1 : 0;
      r = (1 - ease.outExpo(p)) * 4;
    }
    if (out != null) {
      const q = prog(t, out + i * outStagger, out + i * outStagger + outDur);
      if (q > 0) {
        const e = ease.inOutCubic(q);
        o *= 1 - e;
        y -= e * dy * 0.5;
        b += e * blur;
      }
    }
    if (style === 'mask') {
      s.style.transform = `translateY(${fmt(y)}%) rotate(${fmt(r)}deg)`;
      s.style.opacity = o;
    } else {
      tf(s, { y, s: sc, o, blur: b });
    }
  });
}

/** The rect of an element in stage coordinates (independent of preview scale and shake). */
let contentEl = null;
export const setContent = (c) => {
  contentEl = c;
};
export function rectIn(e) {
  const c = contentEl.getBoundingClientRect();
  const r = e.getBoundingClientRect();
  const k = c.width / W;
  return { left: (r.left - c.left) / k, top: (r.top - c.top) / k, width: r.width / k, height: r.height / k };
}

// ---- Scenes and cues ----

export const scenes = [];
export const cues = [];
const globals = [];

/**
 * A scene: { id, start, end, build(root), render(lt, t) }. The engine shows the root only
 * while start <= t < end. lt is the time since start.
 */
export function scene(def) {
  scenes.push(def);
  return def;
}

/** A sound cue for the audio track: time in seconds, a type, and parameters. */
export function cue(t, type, params = {}) {
  cues.push({ t: Math.round(t * 1000) / 1000, type, ...params });
}

/** A layer that renders at every time (background, grain, flash). */
export function global(fn) {
  globals.push(fn);
}

export function mount(stage) {
  for (const s of scenes) {
    s.root = el('div', `scene scene-${s.id}`, stage);
    s.build(s.root);
    s.root.style.zIndex = s.z ?? 1;
    show(s.root, false);
  }
}

export function renderAt(t) {
  for (const g of globals) g(t);
  for (const s of scenes) {
    const on = t >= s.start && t < s.end;
    if (on !== s._on) {
      show(s.root, on);
      s._on = on;
    }
    if (on) s.render(t - s.start, t);
  }
}

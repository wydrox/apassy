// The apassy logo: an archway with an open door (the mark), and the wordmark.
//
// Units are those of the brand artwork: the mark is 229 × 206.2 with its top-left at 0,0,
// and the wordmark (wordmark.js) sits to its right on the same baseline. The mark is built
// from its geometry, so its curves are exact at any size.
import { prog, ease, clamp, lerp } from './engine.js';
import { LETTERS } from './wordmark.js';

export const INK = '#0e1820';
export const BLUE = '#0a77fe';

// The arch: two concentric half circles on straight legs.
const R = 114.5; // outer radius
const STROKE = 59.5;
const BASE = 206.2; // the baseline
const NOTCH = 21; // the round inner corner at the foot of the right leg
const C = 2; // the other corners

export const MARK_W = 2 * R;
export const MARK_H = BASE;
export const LOCKUP_W = 1057.1;
export const LOCKUP_H = 227.2; // to the descenders of p and y

const r = R - STROKE;
const IN_L = STROKE;
const IN_R = 2 * R - STROKE;

export const ARCH = [
  `M0,${R}A${R},${R} 0 0 1 ${2 * R},${R}`,
  `L${2 * R},${BASE - C}A${C},${C} 0 0 1 ${2 * R - C},${BASE}`,
  `L${IN_R + NOTCH},${BASE}A${NOTCH},${NOTCH} 0 0 1 ${IN_R},${BASE - NOTCH}`,
  `L${IN_R},${R}A${r},${r} 0 0 0 ${IN_L},${R}`,
  `L${IN_L},${BASE - C}A${C},${C} 0 0 1 ${IN_L - C},${BASE}`,
  `L${C},${BASE}A${C},${C} 0 0 1 0,${BASE - C}Z`,
].join('');

// The door, hinged on its left edge. `open` 1 is the logo; 0 is closed (flat in the arch).
const DOOR_X = IN_L + 15.5;
const DOOR_TOP = 94;
const DOOR_W = 46.5; // its width when open, in perspective
const DOOR_W_CLOSED = IN_R - 15.5 - DOOR_X;

const f = (v) => (Math.round(v * 100) / 100).toString();

/** A convex polygon with rounded corners, clockwise: [[x, y, radius], ...]. */
function roundedPolygon(pts) {
  const n = pts.length;
  let d = '';
  pts.forEach(([x, y, rad], i) => {
    const [px, py] = pts[(i + n - 1) % n];
    const [nx, ny] = pts[(i + 1) % n];
    const a = Math.atan2(py - y, px - x);
    const b = Math.atan2(ny - y, nx - x);
    let ang = Math.abs(a - b);
    if (ang > Math.PI) ang = 2 * Math.PI - ang;
    const k = rad / Math.tan(ang / 2);
    d += `${i ? 'L' : 'M'}${f(x + Math.cos(a) * k)},${f(y + Math.sin(a) * k)}`;
    d += `A${f(rad)},${f(rad)} 0 0 1 ${f(x + Math.cos(b) * k)},${f(y + Math.sin(b) * k)}`;
  });
  return `${d}Z`;
}

export function door(open = 1) {
  const x2 = DOOR_X + DOOR_W_CLOSED + (DOOR_W - DOOR_W_CLOSED) * open;
  return roundedPolygon([
    [DOOR_X, DOOR_TOP, 2.5],
    [x2, DOOR_TOP + 19.46 * open, 2.5 + 23.5 * open],
    [x2, BASE - 25.67 * open, 3],
    [DOOR_X, BASE, 1],
  ]);
}

export const DOOR = door(1);

/** The mark alone, `h` pixels high. */
export function markSVG(h, { ink = INK, blue = BLUE } = {}) {
  return `<svg class="mark" height="${h}" width="${f((h * MARK_W) / MARK_H)}" viewBox="0 0 ${MARK_W} ${MARK_H}"><path d="${ARCH}" fill="${ink}"/><path d="${DOOR}" fill="${blue}"/></svg>`;
}

/** The app icon: the mark on a rounded square. Dark: white arch on ink. */
export function iconSVG(size, { dark = true, shadow = false } = {}) {
  const k = 64 / MARK_W;
  const x = (100 - 64) / 2;
  const y = (100 - MARK_H * k) / 2 - 1;
  return `<svg class="appicon" width="${size}" height="${size}" viewBox="0 0 100 100">
    <rect width="100" height="100" rx="22.5" fill="${dark ? INK : '#fff'}"/>
    ${dark ? '' : '<rect x=".25" y=".25" width="99.5" height="99.5" rx="22.25" fill="none" stroke="#000" stroke-opacity=".1" stroke-width=".5"/>'}
    <g transform="translate(${f(x)},${f(y)}) scale(${k})"><path d="${ARCH}" fill="${dark ? '#fff' : INK}"/><path d="${DOOR}" fill="${BLUE}"/></g>
  </svg>`;
}

/**
 * The lockup for animation: an SVG `h` pixels high with the arch, the door, and one group
 * per letter. The letters are clipped to their line, so they can rise into place.
 */
let clipN = 0;
export function lockup(parent, h) {
  const n = ++clipN;
  const w = (h * LOCKUP_W) / LOCKUP_H;
  const wrap = document.createElement('div');
  wrap.className = 'lockup';
  wrap.style.width = `${w}px`;
  wrap.style.height = `${h}px`;
  wrap.innerHTML = `<svg width="${w}" height="${h}" viewBox="0 0 ${LOCKUP_W} ${LOCKUP_H}" overflow="visible">
    <defs><clipPath id="wm${n}"><rect x="260" y="30" width="820" height="200"/></clipPath></defs>
    <g class="lk-mark"><path class="lk-arch" d="${ARCH}" fill="${INK}"/><path class="lk-door" d="${DOOR}" fill="${BLUE}"/></g>
    <g clip-path="url(#wm${n})">${LETTERS.map((l) => `<g class="lk-letter"><path d="${l.d}" fill="${INK}" fill-rule="evenodd"/></g>`).join('')}</g>
  </svg>`;
  parent.appendChild(wrap);
  return {
    el: wrap,
    mark: wrap.querySelector('.lk-mark'),
    door: wrap.querySelector('.lk-door'),
    letters: [...wrap.querySelectorAll('.lk-letter')],
    scale: h / LOCKUP_H,
  };
}

/** Lockup timing (grid seconds from the hit): the mark lands centered and its door opens;
 * it slides into place, and the letters rise once it has cleared them. The tagline can
 * follow from LOCKUP_DONE. */
export const LOCKUP_DONE = 1.55;

/** Animate a lockup at local time u. */
export function playLockup(L, u) {
  const k = ease.outQuart(prog(u, 0, 0.7));
  const cx = MARK_W / 2;
  const cy = MARK_H / 2;
  const s = lerp(1.06, 1, k);
  // Start centered in the lockup box, then slide left to its place.
  const dx = (LOCKUP_W / 2 - cx) * (1 - ease.inOutCubic(prog(u, 0.62, 1.22)));
  L.mark.setAttribute('transform', `translate(${(dx + cx).toFixed(2)} ${cy}) scale(${s.toFixed(4)}) translate(${-cx} ${-cy})`);
  L.mark.setAttribute('opacity', clamp(u / 0.08).toFixed(3));
  L.door.setAttribute('d', door(ease.inOutCubic(prog(u, 0.1, 0.75))));
  L.letters.forEach((g, i) => {
    const p = ease.outQuart(prog(u, 1.0 + i * 0.045, 1.0 + i * 0.045 + 0.7));
    g.setAttribute('transform', `translate(0 ${((1 - p) * 200).toFixed(2)})`);
  });
}

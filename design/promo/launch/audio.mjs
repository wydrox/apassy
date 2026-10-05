// The sound track: music and sound effects, synthesized from code. No samples, no
// licensed audio. The music is written on the 120 BPM grid of the edit (js/timeline.js) and
// plays PACE times slower, like the picture (96 BPM). The sound effects come from the cues
// of the page (out/cues.json, written by `node render.mjs --cues`), already in real time.
//
//   node audio.mjs            → out/audio.wav (48 kHz, 24-bit stereo)
//   node audio.mjs --stems    → also out/music.wav and out/sfx.wav
import { readFileSync, writeFileSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
// The film: the launch film (out/cues.json → out/audio.wav) or a short (--film 3am:
// out/cues-3am.json → out/audio-3am.wav).
const FILM = argv.includes('--film') ? argv[argv.indexOf('--film') + 1] : 'launch';
const SUFFIX = FILM === 'launch' ? '' : `-${FILM}`;
const { duration: DUR, pace: PACE = 1, cues } = JSON.parse(readFileSync(path.join(here, `out/cues${SUFFIX}.json`), 'utf8'));
const SR = 48000;
const N = Math.ceil(DUR * SR);
const TAU = Math.PI * 2;
// The arrangement is in grid seconds; grid() makes a grid time or length real seconds.
const BEAT = 0.5;
const BAR = 2;
const grid = (x) => x * PACE;

// ---- Basics ----

function rng(seed) {
  let a = seed >>> 0;
  return () => {
    a = (a + 0x6d2b79f5) >>> 0;
    let x = a;
    x = Math.imul(x ^ (x >>> 15), x | 1);
    x ^= x + Math.imul(x ^ (x >>> 7), x | 61);
    return ((x ^ (x >>> 14)) >>> 0) / 4294967296;
  };
}
const R = rng(20260927);
const white = () => R() * 2 - 1;
const mtof = (m) => 440 * Math.pow(2, (m - 69) / 12);
const clamp = (x, a = 0, b = 1) => Math.min(b, Math.max(a, x));
const lerp = (a, b, t) => a + (b - a) * t;
const stereo = () => [new Float32Array(N), new Float32Array(N)];
const panGains = (p) => [Math.cos(((p + 1) * Math.PI) / 4), Math.sin(((p + 1) * Math.PI) / 4)];
const S = (t) => Math.round(t * SR);

/** Antialiasing correction for saw and square (polyBLEP). */
function blep(t, dt) {
  if (t < dt) {
    t /= dt;
    return t + t - t * t - 1;
  }
  if (t > 1 - dt) {
    t = (t - 1) / dt;
    return t * t + t + t + 1;
  }
  return 0;
}

/** A state-variable filter (topology-preserving transform). */
class SVF {
  constructor() {
    this.a = 0;
    this.b = 0;
    this.lp = 0;
    this.bp = 0;
    this.hp = 0;
    this.fc = -1;
  }
  run(x, fc, q = 0.707) {
    if (fc !== this.fc || q !== this.q) {
      const g = Math.tan((Math.PI * Math.min(fc, SR * 0.45)) / SR);
      this.k = 1 / q;
      this.a1 = 1 / (1 + g * (g + this.k));
      this.a2 = g * this.a1;
      this.a3 = g * this.a2;
      this.fc = fc;
      this.q = q;
    }
    const v3 = x - this.b;
    const v1 = this.a1 * this.a + this.a2 * v3;
    const v2 = this.b + this.a2 * this.a + this.a3 * v3;
    this.a = 2 * v1 - this.a;
    this.b = 2 * v2 - this.b;
    this.lp = v2;
    this.bp = v1;
    this.hp = x - this.k * v1 - v2;
    return v2;
  }
}

/** RBJ biquads: highpass, lowshelf, highshelf, peak. */
class Biquad {
  constructor(type, f, q = 0.707, db = 0) {
    const A = Math.pow(10, db / 40);
    const w = (TAU * f) / SR;
    const cs = Math.cos(w);
    const sn = Math.sin(w);
    const al = sn / (2 * q);
    let b0, b1, b2, a0, a1, a2;
    if (type === 'hp') {
      b0 = (1 + cs) / 2; b1 = -(1 + cs); b2 = (1 + cs) / 2; a0 = 1 + al; a1 = -2 * cs; a2 = 1 - al;
    } else if (type === 'peak') {
      b0 = 1 + al * A; b1 = -2 * cs; b2 = 1 - al * A; a0 = 1 + al / A; a1 = -2 * cs; a2 = 1 - al / A;
    } else {
      const sq = 2 * Math.sqrt(A) * al;
      if (type === 'ls') {
        b0 = A * (A + 1 - (A - 1) * cs + sq); b1 = 2 * A * (A - 1 - (A + 1) * cs); b2 = A * (A + 1 - (A - 1) * cs - sq);
        a0 = A + 1 + (A - 1) * cs + sq; a1 = -2 * (A - 1 + (A + 1) * cs); a2 = A + 1 + (A - 1) * cs - sq;
      } else {
        b0 = A * (A + 1 + (A - 1) * cs + sq); b1 = -2 * A * (A - 1 + (A + 1) * cs); b2 = A * (A + 1 + (A - 1) * cs - sq);
        a0 = A + 1 - (A - 1) * cs + sq; a1 = 2 * (A - 1 - (A + 1) * cs); a2 = A + 1 - (A - 1) * cs - sq;
      }
    }
    this.b0 = b0 / a0; this.b1 = b1 / a0; this.b2 = b2 / a0; this.a1 = a1 / a0; this.a2 = a2 / a0;
    this.x1 = this.x2 = this.y1 = this.y2 = 0;
  }
  run(x) {
    const y = this.b0 * x + this.b1 * this.x1 + this.b2 * this.x2 - this.a1 * this.y1 - this.a2 * this.y2;
    this.x2 = this.x1; this.x1 = x; this.y2 = this.y1; this.y1 = y;
    return y;
  }
}

function eq(bus, chain) {
  for (let c = 0; c < 2; c++) {
    const fs = chain.map(([type, f, q, db]) => new Biquad(type, f, q, db));
    const ch = bus[c];
    for (let i = 0; i < N; i++) {
      let x = ch[i];
      for (const f of fs) x = f.run(x);
      ch[i] = x;
    }
  }
}

/** Integrated loudness (ITU-R BS.1770, gated), in LUFS. */
function lufs(bus) {
  const w = [0, 1].map((c) => {
    const a = new Biquad('hs', 1681.97, 0.7072, 4.0);
    const b = new Biquad('hp', 38.13, 0.5003);
    const out = new Float64Array(N);
    for (let i = 0; i < N; i++) out[i] = b.run(a.run(bus[c][i]));
    return out;
  });
  const block = Math.round(0.4 * SR);
  const hop = Math.round(0.1 * SR);
  const pw = [];
  for (let s = 0; s + block <= N; s += hop) {
    let z = 0;
    for (let c = 0; c < 2; c++) for (let i = s; i < s + block; i++) z += w[c][i] * w[c][i];
    pw.push(z / block);
  }
  const L = (p) => -0.691 + 10 * Math.log10(p);
  const abs = pw.filter((p) => L(p) > -70);
  const mean = (a) => a.reduce((x, y) => x + y, 0) / a.length;
  const rel = L(mean(abs)) - 10;
  return L(mean(abs.filter((p) => L(p) > rel)));
}

/** A look-ahead peak limiter. */
function limit(bus, ceilDb = -1.2, look = 0.005, release = 0.08) {
  const ceil = Math.pow(10, ceilDb / 20);
  const L = Math.round(look * SR);
  const peak = new Float32Array(N);
  for (let i = 0; i < N; i++) peak[i] = Math.max(Math.abs(bus[0][i]), Math.abs(bus[1][i]));
  // Sliding maximum over the next L samples.
  const need = new Float32Array(N);
  const dq = [];
  for (let i = N - 1; i >= 0; i--) {
    while (dq.length && peak[dq[dq.length - 1]] <= peak[i]) dq.pop();
    dq.push(i);
    while (dq[0] > i + L) dq.shift();
    const m = peak[dq[0]];
    need[i] = m > ceil ? ceil / m : 1;
  }
  const rel = Math.exp(-1 / (release * SR));
  let g = 1;
  const gain = new Float32Array(N);
  for (let i = 0; i < N; i++) {
    g = need[i] < g ? need[i] : need[i] - (need[i] - g) * rel;
    gain[i] = g;
  }
  // Smooth the gain over the look-ahead window, so it never clicks.
  let acc = 0;
  const sm = new Float32Array(N);
  for (let i = 0; i < N; i++) {
    acc += gain[i];
    if (i >= L) acc -= gain[i - L];
    sm[i] = Math.min(gain[i], acc / Math.min(i + 1, L));
  }
  for (let i = 0; i < N; i++) {
    const k = i + L < N ? i : N - 1;
    const g2 = Math.min(sm[i], need[i]);
    bus[0][i] *= g2;
    bus[1][i] *= g2;
  }
}

/** Add a mono sample to a stereo bus with a pan. */
function put(bus, i, v, gl, gr) {
  if (i < 0 || i >= N) return;
  bus[0][i] += v * gl;
  bus[1][i] += v * gr;
}

// ---- Effects ----

class Comb {
  constructor(n) {
    this.buf = new Float32Array(n);
    this.i = 0;
    this.s = 0;
  }
  run(x, fb, damp) {
    const y = this.buf[this.i];
    this.s = y * (1 - damp) + this.s * damp;
    this.buf[this.i] = x + this.s * fb;
    if (++this.i >= this.buf.length) this.i = 0;
    return y;
  }
}
class Allpass {
  constructor(n) {
    this.buf = new Float32Array(n);
    this.i = 0;
  }
  run(x) {
    const b = this.buf[this.i];
    this.buf[this.i] = x + b * 0.5;
    if (++this.i >= this.buf.length) this.i = 0;
    return b - x;
  }
}

/** Freeverb. Returns a new stereo buffer with the wet signal only. */
function reverb(inp, { room = 0.82, damp = 0.3, width = 1, predelay = 0.012, lowcut = 180 } = {}) {
  const k = SR / 44100;
  const combs = [1116, 1188, 1277, 1356, 1422, 1491, 1557, 1617];
  const aps = [556, 441, 341, 225];
  const cl = combs.map((n) => new Comb(Math.round(n * k)));
  const cr = combs.map((n) => new Comb(Math.round((n + 23) * k)));
  const al = aps.map((n) => new Allpass(Math.round(n * k)));
  const ar = aps.map((n) => new Allpass(Math.round((n + 23) * k)));
  const fb = room * 0.28 + 0.7;
  const dp = damp * 0.4;
  const pd = Math.round(predelay * SR);
  const out = stereo();
  const hpL = new SVF();
  const hpR = new SVF();
  const w1 = width / 2 + 0.5;
  const w2 = (1 - width) / 2;
  for (let i = 0; i < N; i++) {
    const j = i - pd;
    const x = j >= 0 ? (inp[0][j] + inp[1][j]) * 0.015 : 0;
    let l = 0;
    let r = 0;
    for (let c = 0; c < 8; c++) {
      l += cl[c].run(x, fb, dp);
      r += cr[c].run(x, fb, dp);
    }
    for (let a = 0; a < 4; a++) {
      l = al[a].run(l);
      r = ar[a].run(r);
    }
    hpL.run(l, lowcut, 0.7);
    hpR.run(r, lowcut, 0.7);
    l = hpL.hp;
    r = hpR.hp;
    out[0][i] = l * w1 + r * w2;
    out[1][i] = r * w1 + l * w2;
  }
  return out;
}

/** A ping-pong delay. Returns the wet signal only. */
function pingpong(inp, time, fb = 0.35, cut = 3500) {
  const d = Math.round(time * SR);
  const bl = new Float32Array(N);
  const br = new Float32Array(N);
  const out = stereo();
  const fl = new SVF();
  const fr = new SVF();
  for (let i = 0; i < N; i++) {
    const rl = i - d >= 0 ? bl[i - d] : 0;
    const rr = i - d >= 0 ? br[i - d] : 0;
    const x = (inp[0][i] + inp[1][i]) * 0.5;
    bl[i] = x + fb * fr.run(rr, cut, 0.6);
    br[i] = fb * fl.run(rl, cut, 0.6);
    out[0][i] = rl;
    out[1][i] = rr;
  }
  return out;
}

function mixInto(dst, src, g = 1) {
  for (let c = 0; c < 2; c++) for (let i = 0; i < N; i++) dst[c][i] += src[c][i] * g;
}

function applyGain(bus, fn) {
  for (let i = 0; i < N; i++) {
    const g = fn(i / SR, i);
    bus[0][i] *= g;
    bus[1][i] *= g;
  }
}

// ---- Drums ----

function kick(bus, t, vel = 1, { muffle = 0, len = 0.45 } = {}) {
  const s0 = S(t);
  let ph = 0;
  const f = new SVF();
  for (let i = 0; i < len * SR; i++) {
    const tt = i / SR;
    const fr = 43 + 150 * Math.exp(-tt / 0.03) + 320 * Math.exp(-tt / 0.004);
    ph += fr / SR;
    const env = Math.min(1, tt / 0.0015) * (tt < 0.045 ? 1 : Math.exp(-(tt - 0.045) / 0.12));
    let v = Math.sin(TAU * ph) * env;
    if (tt < 0.005) v += white() * 0.22 * (1 - tt / 0.005);
    v = Math.tanh(v * 1.9) * 0.82;
    if (muffle) v = f.run(v, muffle, 0.7);
    put(bus, s0 + i, v * vel, 1, 1);
  }
}

function clap(bus, t, vel = 1, pan = 0) {
  const s0 = S(t);
  const bp = new SVF();
  const [gl, gr] = panGains(pan);
  for (let i = 0; i < 0.4 * SR; i++) {
    const tt = i / SR;
    let env = 0;
    for (const o of [0, 0.0105, 0.021]) {
      const d = tt - o;
      if (d >= 0) env = Math.max(env, Math.exp(-d / 0.005));
    }
    const tail = tt >= 0.021 ? Math.exp(-(tt - 0.021) / 0.1) * 0.6 : 0;
    bp.run(white(), 1250, 1.3);
    let v = bp.bp * Math.max(env, tail) * 2.2;
    // A little body.
    v += Math.sin(TAU * 190 * tt) * Math.exp(-tt / 0.03) * 0.25;
    put(bus, s0 + i, v * vel, gl, gr);
  }
}

function snare(bus, t, vel = 1, pan = 0) {
  const s0 = S(t);
  const bp = new SVF();
  const [gl, gr] = panGains(pan);
  for (let i = 0; i < 0.22 * SR; i++) {
    const tt = i / SR;
    bp.run(white(), 2600, 0.8);
    let v = bp.bp * Math.exp(-tt / 0.07) * 1.4;
    v += Math.sin(TAU * (175 + 40 * Math.exp(-tt / 0.01)) * tt) * Math.exp(-tt / 0.05) * 0.5;
    put(bus, s0 + i, v * vel, gl, gr);
  }
}

const HAT_F = [205.3, 304.4, 369.6, 522.7, 540.0, 800.0].map((f) => f * 1.55);
function hat(bus, t, vel = 1, open = false, pan = 0.2) {
  const s0 = S(t);
  const len = open ? 0.4 : 0.08;
  const dec = open ? 0.13 : 0.022;
  const ph = HAT_F.map(() => R());
  const bp = new SVF();
  const hp = new SVF();
  const [gl, gr] = panGains(pan);
  for (let i = 0; i < len * SR; i++) {
    const tt = i / SR;
    let m = 0;
    for (let k = 0; k < 6; k++) {
      ph[k] += HAT_F[k] / SR;
      m += ph[k] % 1 < 0.5 ? 1 : -1;
    }
    m = m / 6 + white() * 0.35;
    bp.run(m, 10000, 0.9);
    hp.run(bp.bp, 7000, 0.7);
    const v = hp.hp * Math.exp(-tt / dec) * Math.min(1, tt / 0.0008);
    put(bus, s0 + i, v * vel, gl, gr);
  }
}

function crash(bus, t, vel = 1, len = 2.2) {
  const s0 = S(t);
  const hp = new SVF();
  const bp = new SVF();
  const ph = HAT_F.map(() => R());
  for (let i = 0; i < len * SR; i++) {
    const tt = i / SR;
    let m = 0;
    for (let k = 0; k < 6; k++) {
      ph[k] += (HAT_F[k] * 1.3) / SR;
      m += ph[k] % 1 < 0.5 ? 1 : -1;
    }
    const n = white();
    hp.run(n * 0.7 + (m / 6) * 0.5, 4200, 0.6);
    bp.run(n, 7000, 0.5);
    const env = Math.min(1, tt / 0.002) * (0.35 * Math.exp(-tt / 0.08) + 0.65 * Math.exp(-tt / 0.75));
    const v = (hp.hp * 0.8 + bp.bp * 0.4) * env;
    put(bus, s0 + i, v * vel, 0.9 + white() * 0.02, 0.9);
  }
}

// ---- Tonal instruments ----

function bass(bus, t, dur, midi, vel = 1, { drive = 1.4, bright = 1 } = {}) {
  const s0 = S(t);
  const f = mtof(midi);
  let p = R();
  let ps = 0;
  const lp = new SVF();
  const len = (dur + 0.06) * SR;
  for (let i = 0; i < len; i++) {
    const tt = i / SR;
    const dt = f / SR;
    p += dt;
    if (p >= 1) p -= 1;
    ps += dt;
    const saw = 2 * p - 1 - blep(p, dt);
    const cutoff = 240 + 1900 * bright * Math.exp(-tt / 0.08);
    let v = lp.run(saw, cutoff, 1.0) * 0.9 + Math.sin(TAU * ps) * 0.5;
    const env = Math.min(1, tt / 0.003) * (tt < dur ? 1 : Math.exp(-(tt - dur) / 0.015));
    v = Math.tanh(v * drive) * env * 0.55;
    put(bus, s0 + i, v * vel, 1, 1);
  }
}

/** A supersaw pad voice for each note, spread in stereo, with a low-pass that can move. */
function pad(bus, t, dur, midis, vel = 1, { attack = 0.3, release = 0.9, cut = [1400, 1400], q = 0.75, detune = 0.13, voices = 5 } = {}) {
  const s0 = S(t);
  const len = (dur + release) * SR;
  for (const m of midis) {
    const base = mtof(m);
    const vs = [];
    for (let v = 0; v < voices; v++) {
      const off = voices === 1 ? 0 : (v / (voices - 1)) * 2 - 1;
      vs.push({ f: base * Math.pow(2, (off * detune) / 12), p: R(), pan: off * 0.85 });
    }
    const fl = new SVF();
    const fr = new SVF();
    for (let i = 0; i < len; i++) {
      const tt = i / SR;
      let l = 0;
      let r = 0;
      for (const v of vs) {
        const dt = v.f / SR;
        v.p += dt;
        if (v.p >= 1) v.p -= 1;
        const s = 2 * v.p - 1 - blep(v.p, dt);
        const [gl, gr] = panGains(v.pan);
        l += s * gl;
        r += s * gr;
      }
      const c = lerp(cut[0], cut[1], clamp(tt / dur));
      l = fl.run(l, c, q);
      r = fr.run(r, c, q);
      const env = Math.min(1, tt / attack) * (tt < dur ? 1 : Math.exp(-(tt - dur) / (release / 3)));
      const g = (env * vel * 0.16) / Math.sqrt(voices);
      const j = s0 + i;
      if (j >= 0 && j < N) {
        bus[0][j] += l * g;
        bus[1][j] += r * g;
      }
    }
  }
}

function pluck(bus, t, midi, vel = 1, pan = 0, { decay = 0.22, bright = 1 } = {}) {
  const s0 = S(t);
  const f = mtof(midi);
  let p1 = R();
  let p2 = R();
  const lp = new SVF();
  const [gl, gr] = panGains(pan);
  for (let i = 0; i < (decay * 3 + 0.05) * SR; i++) {
    const tt = i / SR;
    const dt = f / SR;
    p1 += dt;
    if (p1 >= 1) p1 -= 1;
    p2 += dt * 1.004;
    if (p2 >= 1) p2 -= 1;
    const sq = (p2 < 0.5 ? 1 : -1) + blep(p2, dt) - blep((p2 + 0.5) % 1, dt);
    const saw = 2 * p1 - 1 - blep(p1, dt);
    const c = 350 + 5200 * bright * Math.exp(-tt / 0.05);
    const v = lp.run(saw * 0.6 + sq * 0.4, c, 1.1) * Math.exp(-tt / decay) * Math.min(1, tt / 0.002);
    put(bus, s0 + i, v * vel * 0.5, gl, gr);
  }
}

function lead(bus, t, dur, midi, vel = 1) {
  const s0 = S(t);
  const f = mtof(midi);
  const ps = [R(), R(), R()];
  const det = [0.996, 1.004, 0.5];
  const lp = new SVF();
  const len = (dur + 0.35) * SR;
  for (let i = 0; i < len; i++) {
    const tt = i / SR;
    const vib = 1 + Math.sin(TAU * 5.4 * tt) * 0.0065 * clamp((tt - 0.18) / 0.25);
    let s = 0;
    for (let k = 0; k < 3; k++) {
      const dt = (f * det[k] * vib) / SR;
      ps[k] += dt;
      if (ps[k] >= 1) ps[k] -= 1;
      s += (2 * ps[k] - 1 - blep(ps[k], dt)) * (k === 2 ? 0.45 : 0.6);
    }
    const c = 2200 + 3000 * Math.exp(-tt / 0.12);
    s = lp.run(s, c, 0.8);
    const env = Math.min(1, tt / 0.012) * (tt < dur ? 0.8 + 0.2 * Math.exp(-tt / 0.15) : 0.8 * Math.exp(-(tt - dur) / 0.08));
    put(bus, s0 + i, s * env * vel * 0.22, 0.9, 0.9);
  }
}

// ---- Sound effects ----

const FX = {};

FX.boom = (bus, t, { gain = 0.7 }) => {
  gain *= 0.7;
  const s0 = S(t);
  let ph = 0;
  const lp = new SVF();
  for (let i = 0; i < 1.6 * SR; i++) {
    const tt = i / SR;
    ph += (38 + 30 * Math.exp(-tt / 0.15)) / SR;
    let v = Math.sin(TAU * ph) * Math.exp(-tt / 0.55) * Math.min(1, tt / 0.004);
    v += lp.run(white(), 300, 0.7) * Math.exp(-tt / 0.2) * 0.5;
    put(bus, s0 + i, Math.tanh(v * 1.5) * gain, 1, 1);
  }
};

FX.swish = (bus, t, { gain = 0.5 }) => {
  const s0 = S(t) - S(0.06);
  const bp = new SVF();
  const len = 0.32;
  for (let i = 0; i < len * SR; i++) {
    const tt = i / SR;
    const p = tt / len;
    const c = 1800 + 5200 * Math.sin(Math.PI * Math.min(1, p * 1.2));
    bp.run(white(), c, 1.4);
    const env = Math.sin(Math.PI * p) ** 2;
    const pan = lerp(-0.4, 0.4, p);
    const [gl, gr] = panGains(pan);
    put(bus, s0 + i, bp.bp * env * gain * 0.55, gl, gr);
  }
};

FX.whoosh = (bus, t, { dur = 0.45, gain = 0.6 }) => {
  // Peaks at t (the cut), starts before it.
  const len = dur * 1.6;
  const s0 = S(t - dur);
  const bp = new SVF();
  const lp = new SVF();
  for (let i = 0; i < len * SR; i++) {
    const tt = i / SR;
    const p = tt / len;
    const peak = dur / len;
    const env = p < peak ? Math.pow(p / peak, 2.2) : Math.exp(-(p - peak) / 0.12);
    const c = 300 + 3200 * env;
    bp.run(white(), c, 0.9);
    let v = bp.bp * 1.4 + lp.run(white(), 180, 0.7) * 0.25;
    v *= env;
    const [gl, gr] = panGains(lerp(-0.7, 0.7, p));
    put(bus, s0 + i, v * gain * 0.7, gl, gr);
  }
};

FX.pop = (bus, t, { pitch = 1, gain = 0.5 }) => {
  const s0 = S(t);
  let ph = 0;
  for (let i = 0; i < 0.12 * SR; i++) {
    const tt = i / SR;
    ph += (lerp(1100, 420, clamp(tt / 0.045)) * pitch) / SR;
    let v = Math.sin(TAU * ph) * Math.exp(-tt / 0.035) * Math.min(1, tt / 0.001);
    if (tt < 0.002) v += white() * 0.3;
    put(bus, s0 + i, v * gain * 0.6, 0.95, 0.95);
  }
};

FX.hit = (bus, t, { gain = 0.8 }) => {
  kick(bus, t, gain * 0.9);
  const s0 = S(t);
  const bp = new SVF();
  for (let i = 0; i < 0.5 * SR; i++) {
    const tt = i / SR;
    bp.run(white(), 900, 0.7);
    put(bus, s0 + i, bp.bp * Math.exp(-tt / 0.09) * gain * 0.6, 1, 1);
  }
};

FX.tick = (bus, t, { pitch = 1, gain = 0.35 }) => {
  const s0 = S(t);
  const hp = new SVF();
  for (let i = 0; i < 0.03 * SR; i++) {
    const tt = i / SR;
    hp.run(white(), 5000, 0.7);
    const v = hp.hp * Math.exp(-tt / 0.003) * 0.7 + Math.sin(TAU * 2600 * pitch * tt) * Math.exp(-tt / 0.008) * 0.5;
    put(bus, s0 + i, v * gain, 0.8 + 0.2 * R(), 0.8 + 0.2 * R());
  }
};

FX.click = (bus, t, { gain = 0.5 }) => {
  const s0 = S(t);
  const bp = new SVF();
  for (let i = 0; i < 0.04 * SR; i++) {
    const tt = i / SR;
    bp.run(white(), 3800, 1.5);
    let v = bp.bp * Math.exp(-tt / 0.004) * 1.6;
    v += Math.sin(TAU * 1500 * tt) * Math.exp(-tt / 0.006) * 0.5;
    // A second, softer click: the release.
    if (tt > 0.022) v += bp.bp * Math.exp(-(tt - 0.022) / 0.003) * 0.6;
    put(bus, s0 + i, v * gain, 1, 1);
  }
};

FX.type = (bus, t, { dur = 0.5, gain = 0.4 }) => {
  let x = t;
  const r = rng(Math.round(t * 1000));
  while (x < t + dur) {
    FX.tick(bus, x, { pitch: 0.6 + r() * 0.5, gain: gain * (0.6 + r() * 0.4) });
    x += 0.028 + r() * 0.035;
  }
};

FX.scan = (bus, t, { dur = 0.5, gain = 0.3 }) => {
  const s0 = S(t);
  let ph = 0;
  for (let i = 0; i < dur * SR; i++) {
    const tt = i / SR;
    const p = tt / dur;
    ph += lerp(1800, 4200, p) / SR;
    const trem = 0.5 + 0.5 * Math.sin(TAU * 32 * tt);
    const v = Math.sin(TAU * ph) * trem * Math.sin(Math.PI * p) * 0.35;
    put(bus, s0 + i, v * gain, 0.9, 0.9);
  }
};

FX.glitchHit = (bus, t, { gain = 0.9 }) => {
  kick(bus, t, gain * 0.85, { len: 0.3 });
  const s0 = S(t);
  let held = 0;
  let ph = 0;
  const r = rng(Math.round(t * 997));
  const lp = new SVF();
  for (let i = 0; i < 0.34 * SR; i++) {
    const tt = i / SR;
    if (i % 24 === 0) held = white();
    ph += (140 + 60 * Math.floor(r() * 3)) / SR;
    const sq = ph % 1 < 0.5 ? 1 : -1;
    const gate = Math.floor(tt * 40) % 3 === 1 ? 0.25 : 1;
    let v = (held * 0.8 + sq * 0.35) * Math.exp(-tt / 0.1) * gate;
    v = lp.run(v, 4000, 0.8);
    put(bus, s0 + i, Math.tanh(v * 2) * gain * 0.5, 1, 1);
  }
};

FX.glitch = (bus, t, { dur = 0.3, gain = 0.6 }) => {
  const s0 = S(t);
  let held = 0;
  const r = rng(Math.round(t * 991));
  let rate = 16;
  for (let i = 0; i < dur * SR; i++) {
    const tt = i / SR;
    if (i % 800 === 0) rate = 8 + Math.floor(r() * 40);
    if (i % rate === 0) held = white();
    const gate = r() > 0.0004 ? (Math.floor(tt * 55) % 2 ? 1 : 0.2) : 0;
    const v = held * gate * (1 - tt / dur) ** 0.5;
    put(bus, s0 + i, v * gain * 0.4, 1, 1);
  }
};

FX.powerdown = (bus, t, { gain = 0.8 }) => {
  const s0 = S(t);
  let ph = 0;
  const lp = new SVF();
  for (let i = 0; i < 0.5 * SR; i++) {
    const tt = i / SR;
    ph += (30 + 520 * Math.exp(-tt / 0.07)) / SR;
    let v = (ph % 1 < 0.5 ? 1 : -1) * 0.5 + Math.sin(TAU * ph) * 0.6;
    v = lp.run(v, 200 + 3000 * Math.exp(-tt / 0.06), 0.9) * Math.exp(-tt / 0.18);
    put(bus, s0 + i, v * gain * 0.7, 1, 1);
  }
};

FX.riser = (bus, t, { dur = 1, gain = 0.8 }) => {
  const s0 = S(t);
  const hp = new SVF();
  const bp = new SVF();
  let ph = 0;
  for (let i = 0; i < dur * SR; i++) {
    const tt = i / SR;
    const p = tt / dur;
    const n = white();
    hp.run(n, 200 * Math.pow(45, p), 0.8);
    bp.run(n, 400 * Math.pow(20, p), 2.5);
    ph += (180 * Math.pow(6, p)) / SR;
    const tone = Math.sin(TAU * ph) * 0.3 * p * p;
    const env = Math.pow(p, 1.8);
    const v = (hp.hp * 0.5 + bp.bp * 0.6 + tone) * env;
    put(bus, s0 + i, v * gain * 0.8, 0.95, 0.95);
  }
};

FX.reverse = (bus, t, { dur = 0.6, gain = 0.6 }) => {
  // A reversed cymbal that ends at t + dur.
  const s0 = S(t);
  const hp = new SVF();
  for (let i = 0; i < dur * SR; i++) {
    const tt = i / SR;
    const p = tt / dur;
    hp.run(white(), 3500, 0.6);
    const env = Math.exp((p - 1) / 0.25);
    put(bus, s0 + i, hp.hp * env * gain * 0.9, 0.95, 0.95);
  }
};

FX.impact = (bus, t, { gain = 1 }) => {
  kick(bus, t, gain);
  const s0 = S(t);
  let ph = 0;
  const lp = new SVF();
  const hp = new SVF();
  for (let i = 0; i < 3.2 * SR; i++) {
    const tt = i / SR;
    ph += (28 + 60 * Math.exp(-tt / 0.25)) / SR;
    let v = Math.sin(TAU * ph) * Math.exp(-tt / 1.1) * 0.9;
    v += lp.run(white(), 500, 0.7) * Math.exp(-tt / 0.3) * 0.8;
    hp.run(white(), 3000, 0.6);
    v += hp.hp * Math.exp(-tt / 0.6) * 0.35;
    put(bus, s0 + i, Math.tanh(v * 1.3) * gain * 0.85, 1, 1);
  }
};

FX.shimmer = (bus, t, { gain = 0.5 }) => {
  const notes = [84, 88, 91, 96, 100, 103, 108];
  const r = rng(Math.round(t * 313));
  for (let k = 0; k < 14; k++) {
    const m = notes[Math.floor(r() * notes.length)];
    const st = t + r() * 1.0;
    const s0 = S(st);
    const f = mtof(m);
    const [gl, gr] = panGains(r() * 1.6 - 0.8);
    for (let i = 0; i < 0.8 * SR; i++) {
      const tt = i / SR;
      const v = (Math.sin(TAU * f * tt) + 0.3 * Math.sin(TAU * f * 2.76 * tt) * Math.exp(-tt / 0.05)) * Math.exp(-tt / 0.25) * Math.min(1, tt / 0.003);
      put(bus, s0 + i, v * gain * 0.08, gl, gr);
    }
  }
};

FX.glint = (bus, t, { gain = 0.45 }) => {
  const s0 = S(t);
  for (let i = 0; i < 0.7 * SR; i++) {
    const tt = i / SR;
    const f = 3520;
    const v = (Math.sin(TAU * f * tt) * 0.6 + Math.sin(TAU * f * 1.5 * tt) * 0.3 + Math.sin(TAU * f * 2.76 * tt) * 0.2 * Math.exp(-tt / 0.03)) * Math.exp(-tt / 0.18) * Math.min(1, tt / 0.002);
    put(bus, s0 + i, v * gain * 0.25, 0.7, 1);
  }
  FX.shimmer(bus, t + 0.05, { gain: gain * 0.6 });
};

FX.rise = (bus, t, { dur = 0.5, gain = 0.3 }) => {
  const s0 = S(t);
  let ph = 0;
  const bp = new SVF();
  for (let i = 0; i < dur * SR; i++) {
    const tt = i / SR;
    const p = tt / dur;
    ph += lerp(320, 980, p * p) / SR;
    bp.run(white(), lerp(800, 5000, p), 1.5);
    const v = (Math.sin(TAU * ph) * 0.4 + bp.bp * 0.5) * Math.sin(Math.PI * p);
    put(bus, s0 + i, v * gain * 0.5, 0.9, 0.9);
  }
};

FX.zip = (bus, t, { dur = 0.4, gain = 0.45, pitch = 1 }) => {
  const s0 = S(t);
  let ph = 0;
  const bp = new SVF();
  for (let i = 0; i < dur * SR; i++) {
    const tt = i / SR;
    const p = tt / dur;
    const f = lerp(500, 1900, Math.sin((Math.PI / 2) * p)) * pitch;
    const dt = f / SR;
    ph += dt;
    if (ph >= 1) ph -= 1;
    const saw = 2 * ph - 1 - blep(ph, dt);
    bp.run(saw, f * 2, 2);
    const env = Math.sin(Math.PI * p) ** 1.5;
    const [gl, gr] = panGains(lerp(-0.6, 0.6, p));
    put(bus, s0 + i, bp.bp * env * gain * 0.4, gl, gr);
  }
};

FX.swap = (bus, t, { dur = 0.4, gain = 0.6 }) => {
  const r = rng(Math.round(t * 733));
  let x = t;
  while (x < t + dur) {
    const s0 = S(x);
    const f = 900 + r() * 2600;
    const len = 0.03;
    for (let i = 0; i < len * SR; i++) {
      const tt = i / SR;
      const v = (Math.sin(TAU * f * tt) > 0 ? 1 : -1) * Math.exp(-tt / 0.01) * 0.25;
      put(bus, s0 + i, v * gain, r() * 0.3 + 0.7, r() * 0.3 + 0.7);
    }
    x += 0.028 + r() * 0.02;
  }
  FX.click(bus, t + dur, { gain: gain * 0.9 });
  FX.success(bus, t + dur + 0.02, { gain: gain * 0.35, notes: [88, 95] });
};

FX.success = (bus, t, { gain = 0.55, notes = [76, 83] }) => {
  notes.forEach((m, k) => {
    const s0 = S(t + k * 0.085);
    const f = mtof(m);
    for (let i = 0; i < 0.9 * SR; i++) {
      const tt = i / SR;
      const v = (Math.sin(TAU * f * tt) + 0.25 * Math.sin(TAU * f * 2 * tt) + 0.15 * Math.sin(TAU * f * 3.01 * tt) * Math.exp(-tt / 0.04)) * Math.exp(-tt / 0.28) * Math.min(1, tt / 0.002);
      put(bus, s0 + i, v * gain * 0.28, k ? 0.8 : 1, k ? 1 : 0.8);
    }
  });
};

FX.ding = (bus, t, { gain = 0.5, pitch = 1 }) => FX.success(bus, t, { gain: gain * 0.9, notes: [83 + Math.round(Math.log2(pitch) * 12)] });

FX.ask = (bus, t, { gain = 0.55 }) => {
  [[81, 0], [76, 0.11]].forEach(([m, d]) => {
    const s0 = S(t + d);
    const f = mtof(m);
    for (let i = 0; i < 0.5 * SR; i++) {
      const tt = i / SR;
      const v = (Math.sin(TAU * f * tt) + 0.4 * Math.sin(TAU * f * 2 * tt) * Math.exp(-tt / 0.05)) * Math.exp(-tt / 0.16) * Math.min(1, tt / 0.003);
      put(bus, s0 + i, v * gain * 0.3, 0.95, 0.95);
    }
  });
};

FX.deny = (bus, t, { gain = 0.9 }) => {
  const s0 = S(t);
  const lp = new SVF();
  let p1 = 0;
  let p2 = 0;
  for (let i = 0; i < 0.34 * SR; i++) {
    const tt = i / SR;
    p1 += 98 / SR;
    p2 += 103.5 / SR;
    let v = ((p1 % 1 < 0.5 ? 1 : -1) + (p2 % 1 < 0.5 ? 1 : -1)) * 0.5;
    v = lp.run(v, 900, 0.9) * (tt < 0.2 ? 1 : Math.exp(-(tt - 0.2) / 0.03)) * Math.min(1, tt / 0.004);
    put(bus, s0 + i, v * gain * 0.45, 1, 1);
  }
  kick(bus, t, gain * 0.55, { muffle: 900 });
};

FX.notify = (bus, t, { gain = 0.7 }) => {
  [[84, 0], [91, 0.12]].forEach(([m, d]) => {
    const s0 = S(t + d);
    const f = mtof(m);
    for (let i = 0; i < 1.0 * SR; i++) {
      const tt = i / SR;
      const v = (Math.sin(TAU * f * tt) * 0.8 + 0.35 * Math.sin(TAU * f * 2.01 * tt) * Math.exp(-tt / 0.1) + 0.2 * Math.sin(TAU * f * 3.99 * tt) * Math.exp(-tt / 0.03)) * Math.exp(-tt / 0.3) * Math.min(1, tt / 0.003);
      put(bus, s0 + i, v * gain * 0.3, 0.95, 0.95);
    }
  });
};

FX.pulse = (bus, t, { gain = 0.35 }) => {
  const s0 = S(t);
  for (let i = 0; i < 1.2 * SR; i++) {
    const tt = i / SR;
    const v = Math.sin(TAU * 880 * tt) * Math.exp(-tt / 0.35) * Math.min(1, tt / 0.004) * (0.7 + 0.3 * Math.sin(TAU * 6 * tt));
    put(bus, s0 + i, v * gain * 0.25, 0.9, 0.9);
  }
};

FX.roll = (bus, t, { dur = 0.5, gain = 0.35 }) => {
  let x = t;
  let k = 0;
  while (x < t + dur) {
    FX.tick(bus, x, { pitch: 1.2, gain });
    const p = (x - t) / dur;
    x += 0.025 + 0.07 * p * p;
    k++;
  }
};

// ---- The arrangement ----

// The buses of the music. Each film fills them and says how to finish the mix.
const drums = stereo();
const bassBus = stereo();
const padBus = stereo();
const arpBus = stereo();
const leadBus = stereo();
const fxMusic = stereo(); // risers and hits that belong to the music
const kicks = []; // times, for the sidechain

const K = (t, vel = 1, opt) => {
  kick(drums, t, vel, opt);
  if (!opt || !opt.muffle) kicks.push({ t, depth: vel });
};

// -- The launch film: written on the 120 BPM grid, played at PACE. --

const CH = {
  Am: { pad: [57, 60, 64, 69], bass: 33, arp: [69, 72, 76, 81] },
  F: { pad: [53, 57, 60, 65], bass: 29, arp: [65, 69, 72, 77] },
  C: { pad: [55, 60, 64, 67], bass: 36, arp: [67, 72, 76, 79] },
  G: { pad: [55, 59, 62, 67], bass: 31, arp: [67, 71, 74, 79] },
  Cfin: { pad: [48, 55, 60, 62, 64, 67, 72], bass: 36, arp: [72, 74, 76, 79] },
};
const PROG = ['Am', 'F', 'C', 'G'];
const chordAt = (b) => {
  if (b < 4) return 'Am';
  if (b <= 15) return PROG[(b - 4) % 4];
  if (b === 16) return 'F';
  if (b === 17) return 'G';
  if (b <= 21) return PROG[(b - 18) % 4];
  if (b === 22) return 'Am';
  if (b === 23) return 'F';
  if (b === 24) return 'G';
  return 'Cfin';
};

function arrangeLaunch() {
// Hook (0–6.76 grid): drone, dark pad, ticking hats, a heartbeat, then the montage pulse.
const HOOK_END = 6.76;
{
  // Drone on A1 with a slowly opening filter.
  let p = 0;
  let ps = 0;
  const lp = new SVF();
  for (let i = 0; i < grid(HOOK_END) * SR; i++) {
    const tt = i / SR;
    const f = mtof(33);
    const dt = f / SR;
    p += dt;
    if (p >= 1) p -= 1;
    ps += dt;
    const saw = 2 * p - 1 - blep(p, dt);
    const c = lerp(110, 900, clamp(tt / grid(6.4)) ** 1.6);
    const v = lp.run(saw, c, 1.2) * 0.55 + Math.sin(TAU * ps) * 0.28;
    const env = Math.min(1, tt / grid(1.2)) * (0.75 + 0.25 * clamp((tt - grid(4.5)) / grid(1.5)));
    put(bassBus, i, Math.tanh(v * 1.2) * env * 0.42, 1, 1);
  }
  pad(padBus, 0, grid(HOOK_END - 0.2), [45, 52, 57, 60, 64], 0.9, { attack: grid(1.5), release: 0.3, cut: [350, 2200], q: 0.9 });
  for (let x = 1.0; x < HOOK_END; x += 0.125) {
    const step = Math.round((x - 1) / 0.125) % 4;
    hat(drums, grid(x), (step === 2 ? 0.22 : 0.1) * lerp(0.6, 1.2, clamp((x - 1) / 5)), false, step % 2 ? -0.25 : 0.25);
  }
  for (let x = 2.0; x < 4.5; x += 0.5) kick(drums, grid(x), 0.55, { muffle: 260 });
  for (let x = 4.5; x < HOOK_END; x += 0.5) K(grid(x), 0.85);
  for (let x = 4.75; x < HOOK_END; x += 0.5) bass(bassBus, grid(x), grid(0.18), 33, 0.9, { drive: 2.2 });
  // Stabs on the montage cards.
  for (const x of [4.5, 5.0, 5.5, 6.0]) {
    for (const m of [45, 57, 58, 64, 69]) pluck(fxMusic, grid(x), m, 0.8, 0, { decay: 0.16, bright: 1.3 });
  }
  clap(drums, grid(5.0), 0.35);
  clap(drums, grid(6.0), 0.35);
  for (let x = 6.25; x < HOOK_END; x += 0.0625) snare(drums, grid(x), lerp(0.15, 0.45, (x - 6.25) / 0.5));
}

// The groove, with fills into the cuts.
const FILL_INTO = new Set([6, 8, 11, 13, 21]);
function grooveBar(b, { arp = true, hats = 1 } = {}) {
  const t0 = b * BAR;
  const ch = CH[chordAt(b)];
  const fill = FILL_INTO.has(b + 1);
  for (let k = 0; k < 4; k++) {
    const bt = t0 + k * BEAT;
    K(grid(bt), 1);
    if (k === 1 || k === 3) clap(drums, grid(bt), 0.7, 0.05);
    hat(drums, grid(bt + 0.125), 0.2 * hats, false, -0.3);
    hat(drums, grid(bt + 0.25), 0.3 * hats, true, 0.3);
    hat(drums, grid(bt + 0.375), 0.21 * hats, false, -0.2);
    // Bass: off-beat eighths, an octave jump at the end of the bar.
    const bm = k === 3 && b % 2 ? ch.bass + 12 : ch.bass;
    bass(bassBus, grid(bt + 0.25), grid(0.2), bm, 0.95);
  }
  if (fill) {
    for (let j = 0; j < 4; j++) snare(drums, grid(t0 + 1.5 + j * 0.125), 0.18 + j * 0.08, j % 2 ? 0.2 : -0.2);
  }
  pad(padBus, grid(t0), grid(BAR - 0.05), ch.pad, 0.85, { attack: 0.08, release: 0.5, cut: [2400, 3400] });
  if (arp) {
    const pat = [0, 1, 2, 3, 2, 1, 2, 3];
    for (let s = 0; s < 16; s++) {
      pluck(arpBus, grid(t0 + s * 0.125), ch.arp[pat[s % 8]], s % 4 === 0 ? 0.95 : 0.7, s % 2 ? 0.35 : -0.35);
    }
  }
}

// 8: the drop.
crash(drums, grid(8.0), 0.55);
for (let b = 4; b <= 15; b++) grooveBar(b, { arp: b >= 6 });
crash(drums, grid(16.0), 0.35);
crash(drums, grid(26.0), 0.35);

// 32–36: the breakdown. No kick; tension until "Deny" at 35.
{
  pad(padBus, grid(32), grid(2), CH.F.pad, 0.9, { attack: grid(0.4), release: 0.3, cut: [700, 1600], q: 1 });
  pad(padBus, grid(34), grid(1.05), CH.G.pad, 0.9, { attack: 0.1, release: 0.2, cut: [1600, 3600], q: 1.1 });
  for (let x = 32; x < 35; x += 0.25) hat(drums, grid(x), 0.1 + 0.05 * ((x - 32) / 3), false, 0.2);
  for (let x = 32; x < 35; x += 0.125) pluck(arpBus, grid(x), CH[x < 34 ? 'F' : 'G'].arp[[0, 1, 2, 3][Math.round((x - 32) / 0.125) % 4]], 0.35 + 0.35 * ((x - 32) / 3), 0, { decay: 0.12, bright: 0.6 + 0.6 * ((x - 32) / 3) });
  for (let x = 34; x < 35; x += x < 34.5 ? 0.125 : 0.0625) snare(drums, grid(x), lerp(0.12, 0.5, x - 34));
  FX.riser(fxMusic, grid(33.4), { dur: grid(1.6), gain: 0.5 });
  // 35: the hit on "Deny", then a one-bar build back into the groove.
  crash(drums, grid(35.0), 0.5);
  K(grid(35.0), 1);
  bass(bassBus, grid(35.0), grid(0.9), 31, 1, { bright: 1.4 });
  pad(padBus, grid(35.0), grid(0.95), CH.G.pad, 0.8, { attack: 0.01, release: 0.2, cut: [3000, 1200] });
  K(grid(35.5), 0.9);
  for (let x = 35.5; x < 36; x += 0.0625) snare(drums, grid(x), lerp(0.15, 0.55, (x - 35.5) / 0.5));
}

// 36–48: the groove again, with the lead from 40.
crash(drums, grid(36.0), 0.5);
for (let b = 18; b <= 23; b++) grooveBar(b, { arp: true });
const MELODY = [
  // bar 20 (C)
  [0, 76, 1], [1, 79, 0.5], [1.5, 76, 0.5], [2, 74, 1], [3, 72, 1],
  // bar 21 (G)
  [4, 74, 1], [5, 71, 0.5], [5.5, 74, 0.5], [6, 79, 2],
  // bar 22 (Am)
  [8, 76, 1], [9, 72, 0.5], [9.5, 76, 0.5], [10, 81, 1.5], [11.5, 79, 0.5],
  // bar 23 (F)
  [12, 77, 1], [13, 76, 1], [14, 74, 1], [15, 72, 1],
];
for (const [beat, m, len] of MELODY) lead(leadBus, grid(40 + beat * BEAT), grid(len * BEAT * 0.92), m, 1);
crash(drums, grid(42.0), 0.3);

// 48–50: the build into the lockup. A gap of an eighth before the hit.
{
  pad(padBus, grid(48), grid(1.75), CH.G.pad, 0.95, { attack: 0.05, release: 0.05, cut: [900, 5000], q: 1.2 });
  for (let x = 48; x < 49.75; x += 0.5) kick(drums, grid(x), 0.7, { muffle: lerp(300, 3000, (x - 48) / 1.75) });
  for (let x = 49; x < 49.75; x += x < 49.5 ? 0.125 : 0.0625) snare(drums, grid(x), lerp(0.15, 0.55, (x - 49) / 0.75));
  for (let x = 48; x < 49.75; x += 0.25) bass(bassBus, grid(x), grid(0.2), 31 + (x >= 49 ? 12 : 0), 0.7);
  FX.riser(fxMusic, grid(48.25), { dur: grid(1.5), gain: 0.55 });
}

// 50: the final chord.
{
  const t = 50;
  crash(drums, grid(t), 0.65, grid(3));
  K(grid(t), 1.1);
  bass(bassBus, grid(t), grid(3.2), 36, 1, { bright: 1.2 });
  bass(bassBus, grid(t), grid(3.2), 24, 0.7, { bright: 0.5 });
  pad(padBus, grid(t), grid(4.2), CH.Cfin.pad, 1.1, { attack: 0.02, release: 0.8, cut: [5200, 900], q: 0.8 });
  const pat = [0, 1, 2, 3, 2, 1, 2, 3];
  for (let s = 0; s < 24; s++) {
    pluck(arpBus, grid(t + s * 0.125), CH.Cfin.arp[pat[s % 8]], 0.8 * Math.pow(0.9, s), s % 2 ? 0.35 : -0.35);
  }
  // A bell motif as the door opens.
  [[84, 0.0], [88, 0.25], [91, 0.5], [96, 0.75]].forEach(([m, d]) => pluck(arpBus, grid(t + 0.5 + d), m, 0.45, 0, { decay: 0.4, bright: 0.8 }));
}

  return {
    bassDuck: (t) => (t > grid(7.5) ? 1 : 0.4), // the hook drone ducks only a little
    echo: grid(0.375), // a dotted eighth
    post(music) {
    // Tape stop at the cut to black (6.76 grid), then silence until the drop.
    {
      const a = S(grid(HOOK_END));
      const len = S(grid(0.24));
      const src = [music[0].slice(a, a + len * 2), music[1].slice(a, a + len * 2)];
      let pos = 0;
      for (let i = 0; i < len; i++) {
        const rate = Math.pow(1 - i / len, 1.6);
        pos += rate;
        const k = Math.floor(pos);
        const f = pos - k;
        const g = 1 - (i / len) ** 3;
        for (let c = 0; c < 2; c++) music[c][a + i] = (src[c][k] * (1 - f) + src[c][k + 1] * f) * g;
      }
      for (let c = 0; c < 2; c++) music[c].fill(0, a + len, S(grid(7.92)));
    }

    // Level automation: quieter hook, full drop, a dip in the breakdown, a fade at the end.
    applyGain(music, (t) => {
      let g = 1;
      if (t < grid(8)) g = 0.8;
      if (t >= grid(49.75) && t < grid(50)) g = 0.0;
      if (t > grid(52.2)) g *= Math.pow(1 - clamp((t - grid(52.2)) / grid(2.8)), 1.6);
      return g;
    });
    },
  };
}

// -- The 3:07am short: 100 BPM, a bar is 2.4 s. Night (Am9, dark and quiet), asleep (almost
// nothing), morning (Cmaj9 opens up), then a light groove under the logo that fades for a loop. --

function arrange3am() {
  const B = 0.6; // a beat
  const bar = (n) => n * 4 * B;
  const AM9 = [45, 52, 55, 59, 60];
  const CM9 = [48, 52, 55, 59, 62];
  const FM9 = [41, 48, 52, 55, 57];

  // Night: a low drone, a dark pad, a clock. A soft motif when the agent gets going.
  pad(padBus, 0, bar(2) - 0.1, AM9, 0.8, { attack: 0.02, release: 0.6, cut: [520, 950], q: 0.8, voices: 3 });
  bass(bassBus, 0, bar(2) - 0.2, 33, 0.45, { drive: 1.1, bright: 0.25 });
  for (let k = 0; k < 10; k++) FX.tick(fxMusic, k * B, { pitch: k % 2 ? 0.75 : 0.95, gain: 0.2 });
  [[bar(1), 64], [bar(1) + 1.5 * B, 67], [bar(1) + 3 * B, 69]].forEach(([t, m]) => pluck(arpBus, t, m, 0.5, 0, { decay: 0.45, bright: 0.35 }));

  // Asleep: the pad closes and thins out; the clock slows, then stops. A soft thump on "so
  // nothing runs", then almost silence until the morning.
  pad(padBus, bar(2), bar(1) - 0.2, AM9, 0.5, { attack: 0.05, release: 0.4, cut: [700, 260], q: 0.7, voices: 3 });
  for (let k = 0; k < 2; k++) FX.tick(fxMusic, bar(2) + k * 2 * B, { pitch: 0.7, gain: 0.12 });
  kick(drums, 6.0, 0.35, { muffle: 170 });

  // Morning: Cmaj9 opens up, a warm bass, a bell arpeggio.
  pad(padBus, bar(3), bar(1), CM9, 0.95, { attack: 0.25, release: 0.3, cut: [1200, 5200], q: 0.8 });
  bass(bassBus, bar(3), bar(1) - 0.1, 36, 0.7, { bright: 0.5 });
  [84, 88, 91, 95, 98, 95].forEach((m, i) => pluck(arpBus, bar(3) + 0.15 + i * B / 2, m, 0.55 - i * 0.05, i % 2 ? 0.3 : -0.3, { decay: 0.5, bright: 0.9 }));

  // The logo: a soft hit, then a light groove, Cmaj9 to Fmaj9.
  crash(drums, bar(4), 0.35, 2.2);
  const arps = { C: [72, 76, 79, 83], F: [69, 72, 76, 79] };
  const pat = [0, 1, 2, 3, 2, 1, 2, 3];
  [['C', CM9, 36], ['F', FM9, 29]].forEach(([name, chord, root], i) => {
    const t0 = bar(4 + i);
    pad(padBus, t0, bar(1) - 0.05, chord, 0.8, { attack: 0.05, release: 0.5, cut: [2400, 3200] });
    for (let k = 0; k < 4; k++) {
      const bt = t0 + k * B;
      if (k === 0 || k === 2) K(bt, 0.9);
      if (k === 1 || k === 3) clap(drums, bt, 0.5, 0.05);
      hat(drums, bt + B / 2, 0.16, false, 0.25);
      bass(bassBus, bt + B / 2, B * 0.4, root + (k === 3 ? 12 : 0), 0.85);
    }
    for (let k = 0; k < 16; k++) pluck(arpBus, t0 + (k * B) / 4, arps[name][pat[k % 8]], k % 4 === 0 ? 0.8 : 0.55, k % 2 ? 0.35 : -0.35);
  });

  return {
    bassDuck: () => 1,
    echo: 0.45, // a dotted eighth
    post(music) {
      // Levels: a quiet night, almost nothing while you sleep, then the morning and the logo.
      applyGain(music, (t) => {
        let g = 1;
        if (t < bar(2)) g = 0.75;
        else if (t < bar(3)) g = 0.5 * (1 - 0.7 * clamp((t - 6.0) / 0.8));
        else if (t < bar(4)) g = 0.9;
        if (t > DUR - 0.6) g *= clamp((DUR - t) / 0.6);
        return g;
      });
    },
  };
}

const film = { launch: arrangeLaunch, '3am': arrange3am }[FILM]();

// ---- Mix the music ----

// Sidechain: duck the pad, bass, and arp after each kick.
const duck = new Float32Array(N).fill(1);
for (const { t, depth } of kicks) {
  const s0 = S(t);
  for (let i = 0; i < 0.3 * SR; i++) {
    const j = s0 + i;
    if (j >= N) break;
    const tt = i / SR;
    const g = 1 - 0.62 * clamp(depth) * (tt < 0.004 ? tt / 0.004 : Math.exp(-(tt - 0.004) / 0.075));
    if (g < duck[j]) duck[j] = g;
  }
}
for (const b of [padBus, arpBus]) applyGain(b, (t, i) => duck[i]);
applyGain(bassBus, (t, i) => lerp(1, duck[i], film.bassDuck(t)));

const music = stereo();
mixInto(music, drums, 1.0);
mixInto(music, bassBus, 0.8);
mixInto(music, padBus, 1.35);
mixInto(music, arpBus, 0.85);
mixInto(music, leadBus, 1.0);
mixInto(music, fxMusic, 0.8);

// Sends: reverb for the pad, the arp, the lead, and the claps; a ping-pong for the arp and lead.
const send = stereo();
mixInto(send, padBus, 0.55);
mixInto(send, arpBus, 0.5);
mixInto(send, leadBus, 0.5);
mixInto(send, drums, 0.12);
const verb = reverb(send, { room: 0.86, damp: 0.35 });
const dsend = stereo();
mixInto(dsend, arpBus, 0.5);
mixInto(dsend, leadBus, 0.45);
const echo = pingpong(dsend, film.echo, 0.38, 3000);
mixInto(music, verb, 0.75);
mixInto(music, echo, 0.35);
film.post(music);

// ---- Sound effects ----

const sfx = stereo();
for (const c of cues) {
  const fn = FX[c.type];
  if (!fn) {
    console.warn(`no sound for cue "${c.type}" at ${c.t}`);
    continue;
  }
  fn(sfx, c.t, c);
}
const sfxVerb = reverb(sfx, { room: 0.7, damp: 0.45, lowcut: 300 });
mixInto(sfx, sfxVerb, 0.35);

// ---- Master ----

const master = stereo();
mixInto(master, music, 0.72);
mixInto(master, sfx, 0.85);

// EQ: no subsonic rumble, a little less sub, a little more air.
eq(master, [['hp', 32, 0.707], ['ls', 75, 0.707, -4.5], ['peak', 3000, 0.7, 2.5], ['hs', 6500, 0.707, 3.5]]);

// A gentle bus compressor.
{
  let env = 0;
  const att = Math.exp(-1 / (0.01 * SR));
  const rel = Math.exp(-1 / (0.2 * SR));
  const thr = Math.pow(10, -18 / 20);
  const ratio = 2;
  let pk = 0;
  for (let c = 0; c < 2; c++) for (let i = 0; i < N; i++) pk = Math.max(pk, Math.abs(master[c][i]));
  const pre = 0.5 / pk;
  for (let i = 0; i < N; i++) {
    master[0][i] *= pre;
    master[1][i] *= pre;
    const x = Math.max(Math.abs(master[0][i]), Math.abs(master[1][i]));
    env = x > env ? att * env + (1 - att) * x : rel * env + (1 - rel) * x;
    const g = env > thr ? Math.pow(env / thr, 1 / ratio - 1) : 1;
    master[0][i] *= g;
    master[1][i] *= g;
  }
}

// Loudness to -14 LUFS, then the limiter. Two passes: the limiter takes a little away.
const TARGET = Number(process.argv[process.argv.indexOf('--lufs') + 1]) || -14;
let norm = 1;
for (let pass = 0; pass < 2; pass++) {
  const now = lufs(master);
  const g = Math.pow(10, (TARGET - now) / 20);
  norm *= g;
  applyGain(master, () => g);
  limit(master, -1.2);
  console.log(`pass ${pass + 1}: ${now.toFixed(2)} LUFS → gain ${(20 * Math.log10(g)).toFixed(2)} dB`);
}
console.log(`final: ${lufs(master).toFixed(2)} LUFS`);
// A short fade in and out.
for (let i = 0; i < S(0.01); i++) for (let c = 0; c < 2; c++) master[c][i] *= i / S(0.01);
for (let i = 0; i < S(0.05); i++) for (let c = 0; c < 2; c++) master[c][N - 1 - i] *= i / S(0.05);

function writeWav(file, bus) {
  const bytes = 3;
  const data = Buffer.alloc(N * 2 * bytes);
  let o = 0;
  for (let i = 0; i < N; i++) {
    for (let c = 0; c < 2; c++) {
      const v = Math.round(clamp(bus[c][i], -1, 1) * 8388607);
      data.writeIntLE(v, o, 3);
      o += 3;
    }
  }
  const h = Buffer.alloc(44);
  h.write('RIFF', 0);
  h.writeUInt32LE(36 + data.length, 4);
  h.write('WAVE', 8);
  h.write('fmt ', 12);
  h.writeUInt32LE(16, 16);
  h.writeUInt16LE(1, 20);
  h.writeUInt16LE(2, 22);
  h.writeUInt32LE(SR, 24);
  h.writeUInt32LE(SR * 2 * bytes, 28);
  h.writeUInt16LE(2 * bytes, 32);
  h.writeUInt16LE(bytes * 8, 34);
  h.write('data', 36);
  h.writeUInt32LE(data.length, 40);
  writeFileSync(file, Buffer.concat([h, data]));
  console.log(file);
}

writeWav(path.join(here, `out/audio${SUFFIX}.wav`), master);
if (process.argv.includes('--stems')) {
  const m = stereo();
  mixInto(m, music, 0.72 * norm);
  const f = stereo();
  mixInto(f, sfx, 0.85 * norm);
  writeWav(path.join(here, `out/music${SUFFIX}.wav`), m);
  writeWav(path.join(here, `out/sfx${SUFFIX}.wav`), f);
}

// 12–16 (grid). One vault for every secret: the Credentials view of the app.
import { scene, cue, el, tf, prog, ease, clamp, lerp, noise, revealWords, show, pick, W, H } from '../engine.js';
import { headline, appWindow, navRow, section, btn, ic, chip } from '../ui.js';
import { T } from '../timeline.js';

const S = T.vault;
const END = T.placeholder + 0.02;

const ROWS = [
  ['API keys', [
    { kind: 'api', title: 'Stripe', sub: 'acme-api · stripe.com', det: 'STRIPE_SECRET_KEY', mono: true, id: 'r-stripe' },
    { kind: 'api', title: 'OpenAI', sub: 'acme-api · openai.com', det: 'OPENAI_API_KEY', mono: true },
    { kind: 'api', title: 'GitHub', sub: 'wydrox · github.com', det: 'GITHUB_TOKEN', mono: true },
  ]],
  ['Databases', [
    { kind: 'db', title: 'Staging database', sub: 'acme-api · postgres', det: 'DATABASE_URL', mono: true },
    { kind: 'db', title: 'Production database', sub: 'acme-api · postgres', det: 'Production' },
  ]],
  ['Logins', [
    { kind: 'login', title: 'AWS console', sub: 'acme · aws.amazon.com', det: 'No declaration' },
  ]],
  ['SSH keys', [
    { kind: 'ssh', title: 'Deploy key', sub: 'acme-api · github.com', det: 'Staging' },
  ]],
];

const CHIPS = [
  { at: 1.15, icon: 'lock', text: 'Encrypted with SQLCipher', color: '#0a77fe', x: 60, y: pick(560, 1150) },
  { at: 1.5, icon: 'laptop', text: 'Stays on your Mac', color: '#34c759', x: 60, y: pick(680, 1270) },
  { at: 1.85, icon: 'key', text: 'One passphrase unlocks it', color: '#ff9500', x: 60, y: pick(800, 1390) },
];

// The camera: the window scale, its x offset, and where it rises from and settles.
const CAM = pick(
  { s: 1.5, push: 2.35, x: 90, drift: 24, y0: 1100, y1: 420 },
  { s: 1.3, push: 1.45, x: -140, drift: 10, y0: 1500, y1: 330 },
);

cue(S + 0.0, 'whoosh', { dur: 0.5, gain: 0.55 });
cue(S + 0.05, 'swish', { gain: 0.4 });
cue(S + 0.25, 'rise', { dur: 0.5, gain: 0.35 });
ROWS.forEach((_, i) => cue(S + 0.42 + i * 0.09, 'tick', { gain: 0.3, pitch: 1 + i * 0.08 }));
CHIPS.forEach((c) => cue(S + c.at, 'pop', { gain: 0.5, pitch: 1.1 }));
cue(S + 3.15, 'click', { gain: 0.5 });
cue(S + 3.45, 'whoosh', { dur: 0.5, gain: 0.6 });

scene({
  id: 'vault',
  start: S - 0.3,
  end: END,
  build(root) {
    this.h = headline(root, pick('One vault. *Every* *secret.*', 'One vault.\n*Every* *secret.*'), { size: pick(92, 108), top: pick(72, 250) });
    this.stage = el('div', 'abs cam3d', root);
    const page = `<div class="phead"><h1>Credentials</h1>${btn('Add', 'pro', '', 'plus')}</div>
      <div class="search"><div class="field">${ic('search')}Search by name, project, service, or notes</div><div class="menu">All credentials ${ic('chevUD')}</div><div class="menu">Sort: Name ${ic('chevUD')}</div></div>
      ${ROWS.map(([h, rows]) => section(h, rows.map((r) => navRow(r)).join(''))).join('')}`;
    this.win = appWindow(this.stage, { w: 1180, h: 900, sel: 'Credentials', badges: { vault: 7, activity: 0 }, page });
    this.win.style.left = `${W / 2 - 590}px`;
    this.win.style.top = `${H / 2 - 450}px`;
    this.rows = [...this.win.querySelectorAll('.sec')];
    this.stripe = this.win.querySelector('#r-stripe');
    this.ring = el('div', 'rowring', this.stripe);
    this.chips = CHIPS.map((c) => {
      const e = chip(root, c.icon, c.text, { color: c.color, cls: 'bigchip' });
      e.style.left = `${c.x}px`;
      e.style.top = `${c.y}px`;
      e.c = c;
      return e;
    });
  },
  render(lt, t) {
    const u = t - S; // time since the cut
    revealWords(this.h.w, u, 0.02, { out: 3.2, outDur: 0.3 });
    show(this.h.el, u > -0.1 && u < 3.6);

    // Camera: the window rises in, drifts, then pushes into the Stripe row.
    if (this.px == null) {
      const r = this.stripe.getBoundingClientRect();
      const w = this.win.getBoundingClientRect();
      // The Stripe row center, relative to the window center (in points).
      this.px = r.left + r.width / 2 - (w.left + w.width / 2);
      this.py = r.top + r.height / 2 - (w.top + w.height / 2);
    }
    const inP = ease.outQuart(prog(u, -0.3, 1.15));
    const push = ease.inOutQuint(prog(u, 2.85, 3.7));
    const drift = ease.inOutSine(prog(u, 0.6, 2.9));
    const zoomS = lerp(CAM.s, CAM.push, push);
    const rx = lerp(lerp(16, 7, inP) - 3 * drift, 0, push);
    const ry = lerp(lerp(-8, -3.5, inP) + 2 * drift, 0, push);
    const x0 = CAM.x - CAM.drift * drift;
    const y0 = lerp(CAM.y0, CAM.y1, inP) - 40 * drift;
    const tx = lerp(x0, -this.px * zoomS, push);
    const ty = lerp(y0, -this.py * zoomS, push);
    this.win.style.transform = `translate3d(${tx.toFixed(1)}px,${ty.toFixed(1)}px,0) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) scale(${zoomS.toFixed(4)})`;
    this.win.style.opacity = clamp(u / 0.3 + 1).toFixed(3);
    this.stage.style.opacity = (1 - ease.inOutCubic(prog(u, 3.5, 3.95))).toFixed(3);

    // Rows cascade in.
    this.rows.forEach((r, i) => {
      const p = prog(u, 0.4 + i * 0.09, 0.4 + i * 0.09 + 0.7);
      tf(r, { y: (1 - ease.outQuart(p)) * 30, o: ease.outCubic(clamp(p * 1.6)) });
    });

    // The Stripe row is selected before the push.
    const hi = ease.outCubic(prog(u, 3.1, 3.3));
    this.stripe.style.background = `rgba(10,119,254,${(0.07 * hi).toFixed(3)})`;
    tf(this.ring, { o: hi, s: lerp(1.03, 1, hi) });

    // Chips come in, then leave with the push.
    this.chips.forEach((c, i) => {
      const k = ease.outQuart(prog(u, c.c.at, c.c.at + 0.7));
      const o = clamp(k * 1.4) * (1 - ease.inOutCubic(prog(u, 2.75, 3.1)));
      tf(c, { y: lerp(24, 0, k) + noise(u * 0.5 + i * 5, 60 + i) * 3, x: noise(u * 0.4 + i * 7, 70 + i) * 3, o });
      show(c, o > 0.001);
    });
  },
});

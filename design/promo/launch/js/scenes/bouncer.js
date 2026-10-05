// 26–32 (grid). The bouncer checks every request: normal work runs, risky work asks the
// owner, a hard-limit break is denied (ADR 0007, ADR 0010).
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, show, hump, pick } from '../engine.js';
import { headline, ic } from '../ui.js';
import { iconSVG } from '../logo.js';
import { T } from '../timeline.js';

const S = T.bouncer;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const END = T.approval + 0.02;

const LANES = {
  run: { label: 'Runs', icon: 'check', color: '#34c759', text: '#1f7a36', tint: '#e4f6e9', y: pick(330, 865) },
  ask: { label: 'Asks you', icon: 'pause', color: '#ff9500', text: '#b64400', tint: '#fff1dc', y: pick(590, 1055) },
  deny: { label: 'Blocked', icon: 'xmark', color: '#ff3b30', text: '#d70015', tint: '#ffeceb', y: pick(850, 1245) },
};

// Wide: the gate in the middle, the lanes on the right. Tall: the gate at the top, the lanes
// as rows below it. gate: [x, y] of its center; laneX: the card center in a lane; s: its scale.
const LAY = pick(
  { gate: [900, 600], laneTop: 105, laneX: 1575, s: 0.74, step: 12, lean: [-150, -16, 0.06] },
  { gate: [800, 590], laneTop: 85, laneX: 720, s: 0.62, step: 10, lean: [0, -10, 0.02] },
);

const REQ = [
  { agent: 'Claude Code', cmd: 'npm run migrate', env: 'DATABASE_URL', v: 'run', why: 'fits the task' },
  { agent: 'Claude Code', cmd: 'npm test', env: 'DATABASE_URL', v: 'run', why: 'fits the task' },
  { agent: 'Codex', cmd: 'stripe balance retrieve', env: 'STRIPE_SECRET_KEY', v: 'run', why: 'read-only' },
  { agent: 'Claude Code', cmd: 'printenv STRIPE_SECRET_KEY', env: 'STRIPE_SECRET_KEY', v: 'ask', why: 'could print a secret' },
  { agent: 'Codex', cmd: 'psql $PROD_DATABASE_URL', env: 'PROD_DATABASE_URL', v: 'ask', why: 'production' },
  { agent: 'Claude Code', cmd: 'npm run db:reset --force', env: 'DATABASE_URL', v: 'deny', why: 'your rule: never --force' },
  { agent: 'Claude Code', cmd: 'git push origin feat/checkout', env: 'GITHUB_TOKEN', v: 'run', why: 'fits the task' },
];

const GATE = LAY.gate[0];
const CYCLE = 0.5;
const A0 = 0.5;
const at = (i) => A0 + i * CYCLE;
const CAPTION = 4.15;
const EXIT = 5.6;

cue(S + 0.0, 'swish', { gain: 0.45 });
cue(S + 0.2, 'rise', { dur: 0.4, gain: 0.3 });
REQ.forEach((r, i) => {
  cue(S + at(i), 'zip', { dur: 0.35, gain: 0.3, pitch: 1 + (i % 3) * 0.08 });
  cue(S + at(i) + 0.3, 'scan', { dur: 0.2, gain: 0.22 });
  cue(S + at(i) + 0.5, r.v === 'run' ? 'ding' : r.v === 'ask' ? 'ask' : 'deny', { gain: r.v === 'deny' ? 0.9 : 0.55, pitch: 1 + i * 0.04 });
});
cue(S + CAPTION, 'swish', { gain: 0.4 });
cue(S + EXIT, 'whoosh', { dur: 0.45, gain: 0.55 });

scene({
  id: 'bouncer',
  start: S - PRE,
  end: END,
  build(root) {
    this.h = headline(root, pick('A *bouncer* checks every request.', 'A *bouncer* checks\nevery request.'), { size: pick(88, 84), top: pick(66, 250) });
    this.world = el('div', 'abs world', root);

    // The gate.
    this.beam = el('div', 'gatebeam', this.world);
    this.gate = el('div', 'gate', this.world, `<div class="gring"></div>${iconSVG(128)}`);
    this.gring = this.gate.querySelector('.gring');

    // The lanes.
    this.lanes = {};
    for (const [k, L] of Object.entries(LANES)) {
      const e = el('div', `lane lane-${k}`, this.world);
      e.style.top = `${L.y - LAY.laneTop}px`;
      e.style.setProperty('--c', L.color);
      e.style.setProperty('--ct', L.text);
      e.innerHTML = `<div class="lh"><span class="li">${ic(L.icon, '', 2.6)}</span><span class="ll">${L.label}</span></div><div class="lc">0</div>`;
      e.count = e.querySelector('.lc');
      this.lanes[k] = e;
    }

    // The requests.
    this.cards = REQ.map((r, i) => {
      const L = LANES[r.v];
      const c = el('div', 'rq', this.world);
      c.innerHTML = `<div class="rqi"><div class="ra"><span class="av ${r.agent === 'Codex' ? 'cx' : ''}">${r.agent === 'Codex' ? ic('code', '', 2) : '✻'}</span>${r.agent}<span class="vd">${ic(L.icon, '', 2.6)}<b></b></span></div>
        <div class="rc">${r.cmd}</div><div class="rm">${r.env} · ~/dev/acme-api</div></div>`;
      c.inner = c.firstChild;
      c.r = r;
      c.i = i;
      c.vd = c.querySelector('.vd');
      c.vd.querySelector('b').textContent = r.v === 'run' ? 'Runs' : r.why;
      c.style.setProperty('--c', L.color);
      c.style.setProperty('--ct', L.text);
      c.style.setProperty('--tint', L.tint);
      return c;
    });

    this.cap = headline(root, pick('Normal work [green:runs.] Risky work [orange:asks.] Rule breaks [red:stop.]', 'Normal work [green:runs.] Risky work [orange:asks.]\nRule breaks [red:stop.]'), { size: pick(50, 42), top: pick(982, 1370), weight: 600 });
    this.cap.el.classList.add('caption');
  },
  render(lt) {
    const t = lt - PRE;
    revealWords(this.h.w, t, -0.2, { out: EXIT, outDur: 0.3 });

    // Gate and lanes enter.
    const gIn = ease.outQuart(prog(t, 0.15, 0.85));
    tf(this.gate, { s: lerp(0.9, 1, gIn), o: clamp(gIn * 1.6) });
    tf(this.beam, { sy: ease.inOutCubic(prog(t, 0.1, 0.9)) });
    Object.values(this.lanes).forEach((l, i) => {
      const p = ease.outQuart(prog(t, 0.25 + i * 0.08, 1.05 + i * 0.08));
      tf(l, { x: (1 - p) * 60, o: clamp(p * 1.6) });
    });

    // Counts.
    const counts = { run: 0, ask: 0, deny: 0 };
    this.cards.forEach((c, i) => {
      if (t >= at(i) + 0.78) counts[c.r.v]++;
    });
    for (const [k, l] of Object.entries(this.lanes)) {
      l.count.textContent = counts[k];
      let b = 0;
      for (const c of this.cards) if (c.r.v === k) b = Math.max(b, hump(t, at(c.i) + 0.78, at(c.i) + 1.1));
      l.count.style.transform = `scale(${(1 + 0.12 * b).toFixed(3)})`;
      l.classList.toggle('hit', b > 0.05);
    }

    // The gate checks each request.
    let scanning = 0;
    this.cards.forEach((c, i) => {
      scanning = Math.max(scanning, hump(t, at(i) + 0.26, at(i) + 0.56));
    });
    tf(this.gring, { s: 1 + 0.12 * scanning, o: 0.85 * scanning });

    // Each request: in from the left, a stop at the gate, a verdict, then to its lane.
    this.cards.forEach((c, i) => {
      const a = at(i);
      const r = c.r;
      const L = LANES[r.v];
      if (t < a - 0.01) {
        show(c, false);
        return;
      }
      show(c, true);
      const pin = ease.outCubic(prog(t, a, a + 0.42));
      const pout = ease.inOutCubic(prog(t, a + 0.52, a + 0.88));
      const gx = GATE - 60 - 300; // card center when it waits at the gate
      let x = lerp(-420, gx, pin);
      let y = LAY.gate[1];
      let s = 1;
      let rot = 0;
      let newer = 0;
      if (pout > 0) {
        // Stack in the lane: the newest card on top, the older ones step down behind it.
        for (const o of this.cards) {
          if (o.r.v === r.v && o.i > i) newer += ease.inOutCubic(prog(t, at(o.i) + 0.6, at(o.i) + 0.88));
        }
        const d = Math.min(newer, 2);
        const ly = L.y + 12 + d * LAY.step;
        x = lerp(gx, LAY.laneX, pout);
        y = lerp(LAY.gate[1], ly, pout) - Math.sin(Math.PI * pout) * 30;
        s = lerp(1, LAY.s - d * 0.025, pout);
        rot = Math.sin(Math.PI * pout) * (r.v === 'deny' ? -2 : 1.5);
        c.style.zIndex = 20 + i;
        c.style.opacity = clamp(3 - newer).toFixed(3);
      } else {
        c.style.zIndex = 40 + i;
        c.style.opacity = clamp((t - a) / 0.1).toFixed(3);
      }
      c.inner.style.opacity = (1 - clamp(newer)).toFixed(3);
      // A denied request shakes "no" at the gate before it goes.
      if (r.v === 'deny') x += Math.sin((t - a - 0.5) * 50) * 8 * hump(t, a + 0.5, a + 0.74);
      c.style.transform = `translate(${(x - 300).toFixed(1)}px,${(y - 66).toFixed(1)}px) rotate(${rot.toFixed(2)}deg) scale(${s.toFixed(4)})`;
      c.classList.toggle('done', t >= a + 0.5);
      const vp = ease.outQuart(prog(t, a + 0.5, a + 0.8));
      tf(c.vd, { s: lerp(0.85, 1, vp), o: clamp(vp * 2) });
    });

    revealWords(this.cap.w, t, CAPTION, { stagger: 0.06, dy: 18, out: EXIT, outDur: 0.3 });

    // After the last request, the camera leans toward the lanes.
    const lean = ease.inOutSine(prog(t, 4.0, 5.6));
    const ex = ease.inOutCubic(prog(t, EXIT, EXIT + 0.45));
    tf(this.world, { x: LAY.lean[0] * lean, y: LAY.lean[1] * lean, s: 1 + LAY.lean[2] * lean, o: 1 - ex });
  },
});

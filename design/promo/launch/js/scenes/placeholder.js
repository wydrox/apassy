// 16–22 (grid). The agent process holds a placeholder. The apassy proxy puts the real key
// into HTTPS requests to the hosts of the variable only (ADR 0011).
import { scene, cue, el, tf, prog, ease, clamp, lerp, hash, revealWords, show, hump, pick } from '../engine.js';
import { headline, ic } from '../ui.js';
import { iconSVG } from '../logo.js';
import { T } from '../timeline.js';

const S = T.placeholder;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const END = T.rules + 0.02;

// A made-up key for the film, joined from parts so a secret scanner does not flag the
// source. The film shows the same text.
const FAKE = ['sk', 'live', 'Qm7rT2xV9pLk3wN8cH4jZ6sA'].join('_');
const REAL_MASKED = 'sk_live_51Nz••••••••••••••••••••';
const GLYPHS = 'ABCDEFGHJKLMNPQRSTUVWXYZabcdefghijkmnopqrstuvwxyz0123456789';

/** Characters settle from `from` to `to`, left to right, through random glyphs. */
function scramble(from, to, p, seed) {
  let out = '';
  for (let i = 0; i < to.length; i++) {
    const a = (i / to.length) * 0.75;
    if (p >= a + 0.25) out += to[i];
    else if (p < a) out += from[i] ?? ' ';
    else out += to[i] === '_' ? '_' : GLYPHS[Math.floor(hash(seed + i * 131 + Math.floor(p * 60) * 7) * GLYPHS.length)];
  }
  return out;
}

// The layout: node boxes [left, top, width], wires [left, top, length, angle], and the paths
// of the packets. Wide runs left to right; tall runs top to bottom, the two hosts side by side.
const G = pick({
  head: ['Your agent never sees the *real* *key.*', 88, 66],
  cap: ['The real key goes [b:only] to the hosts you allow.', 48, 944],
  agent: [70, 345, 570], proxy: [885, 446], svc: [1310, 392, 560], evil: [1310, 690, 560],
  wires: [[640, 521, 250, 0], [1030, 521, 280, 0], [1010, 568, 350, 30]],
  req: [[560, 521], [960, 521], [1400, 521]], // agent → proxy → service
  resp: [[1380, 568], [520, 568]],
  bad: [[560, 600], [840, 600]], back: [-120, 0], drop: [0, 40],
  refused: [1068, 676],
}, {
  head: ['Your agent never sees\nthe *real* *key.*', 84, 250],
  cap: ['The real key goes [b:only]\nto the hosts you allow.', 46, 1330],
  agent: [90, 470, 900], proxy: [465, 800], svc: [60, 1030, 470], evil: [550, 1030, 470],
  wires: [[540, 722, 78, 90], [505, 945, 227, 158], [575, 945, 227, 22]],
  req: [[540, 690], [540, 875], [295, 1075]],
  resp: [[300, 1040], [300, 735]],
  bad: [[770, 700], [640, 835]], back: [90, -50], drop: [0, 70],
  refused: [600, 960],
});
const at2 = (a, b, p) => [lerp(a[0], b[0], p), lerp(a[1], b[1], p)];

// Times from the scene start.
const A = { in: 0.25, cmd: 0.5, env: 0.95, tag: 1.3, send: 1.4, atProxy: 1.9, swap: 2.0, out: 2.45, hit: 2.5, back: 2.75, home: 3.3, bad: 3.75, badAt: 4.2, refuse: 4.25, caption: 4.5, exit: 5.55 };

cue(S + 0.0, 'swish', { gain: 0.5 });
cue(S + A.in, 'whoosh', { dur: 0.4, gain: 0.45 });
cue(S + A.cmd, 'type', { dur: 0.35, gain: 0.35 });
cue(S + A.tag, 'pop', { gain: 0.5, pitch: 1.3 });
cue(S + A.send, 'zip', { dur: 0.5, gain: 0.55 });
cue(S + A.swap, 'swap', { dur: 0.4, gain: 0.6 });
cue(S + A.out, 'zip', { dur: 0.35, gain: 0.45, pitch: 1.2 });
cue(S + A.hit + 0.05, 'success', { gain: 0.55 });
cue(S + A.back, 'zip', { dur: 0.5, gain: 0.35, pitch: 0.9 });
cue(S + A.home, 'tick', { gain: 0.4 });
cue(S + A.bad, 'zip', { dur: 0.45, gain: 0.5 });
cue(S + A.refuse, 'deny', { gain: 0.9 });
cue(S + A.caption, 'swish', { gain: 0.35 });
cue(S + A.exit, 'whoosh', { dur: 0.45, gain: 0.55 });

scene({
  id: 'placeholder',
  start: S - PRE,
  end: END,
  build(root) {
    this.h = headline(root, G.head[0], { size: G.head[1], top: G.head[2] });
    this.world = el('div', 'abs world', root);
    const box = (e, [left, top, width]) => Object.assign(e.style, { left: `${left}px`, top: `${top}px`, ...(width ? { width: `${width}px` } : {}) });

    // Wires.
    [this.w1, this.w2, this.w3] = G.wires.map(([left, top, len, angle], i) => {
      const w = el('div', `wire ${i === 2 ? 'bad' : ''}`, this.world);
      Object.assign(w.style, { left: `${left}px`, top: `${top}px`, width: `${len}px` });
      w.turn = angle ? `rotate(${angle}deg) ` : '';
      return w;
    });

    // The agent process.
    this.agent = el('div', 'node ncard', this.world);
    box(this.agent, G.agent);
    this.agent.innerHTML = `<div class="nh">${ic('terminal', '', 2)}Agent process</div>
      <div class="nl cmd"><span class="d">$ </span><span class="tx"></span></div>
      <div class="nl d2">STRIPE_SECRET_KEY <span class="ptag">placeholder</span></div>
      <div class="nl fake"><span class="v">${FAKE}</span></div>
      <div class="nl res"><span class="g">✓</span> available: $12,048.80 USD</div>`;
    this.cmd = this.agent.querySelector('.cmd .tx');
    this.envName = this.agent.querySelector('.d2');
    this.fake = this.agent.querySelector('.fake');
    this.ptag = this.agent.querySelector('.ptag');
    this.res = this.agent.querySelector('.res');

    // The proxy.
    this.proxy = el('div', 'proxy', this.world);
    box(this.proxy, G.proxy);
    this.proxy.innerHTML = `<div class="pring"></div><div class="pring r2"></div>${iconSVG(150)}<div class="plabel">apassy proxy</div>`;
    this.rings = [...this.proxy.querySelectorAll('.pring')];
    this.icon = this.proxy.querySelector('.appicon');

    // The service.
    this.svc = el('div', 'node ncard svc', this.world);
    box(this.svc, G.svc);
    this.svc.innerHTML = `<div class="nh">${ic('globe', '', 1.8)}api.stripe.com</div>
      <div class="nl d2">Authorization: Bearer</div>
      <div class="nl real"><span class="v">${REAL_MASKED}</span></div>
      <div class="ok">${ic('check', '', 2.4)}200 OK</div>`;
    this.svcReal = this.svc.querySelector('.real');
    this.ok = this.svc.querySelector('.ok');

    // The wrong host.
    this.evil = el('div', 'node ncard evil', this.world);
    box(this.evil, G.evil);
    this.evil.innerHTML = `<div class="nh">${ic('globe', '', 1.8)}paste.sh</div><div class="nl d2">not a host of STRIPE_SECRET_KEY</div>`;

    // Packets.
    this.pk = el('div', 'packet', this.world);
    this.pkT = el('span', '', this.pk);
    this.resp = el('div', 'packet resp', this.world, '$12,048.80');
    this.bad = el('div', 'packet', this.world);
    this.badT = el('span', '', this.bad, FAKE.slice(0, 16) + '…');
    this.refused = el('div', 'refused', this.world, `${ic('xmark', '', 2.6)}403 · refused`);
    box(this.refused, G.refused);

    this.cap = headline(root, G.cap[0], { size: G.cap[1], top: G.cap[2], weight: 600 });
    this.cap.el.classList.add('caption');
  },
  render(lt) {
    const t = lt - PRE;
    revealWords(this.h.w, t, -0.2, { out: A.exit, outDur: 0.3 });

    // Nodes enter.
    const nIn = (d) => ease.outQuart(prog(t, A.in + d, A.in + d + 0.8));
    tf(this.agent, { x: lerp(-60, 0, nIn(0)), o: clamp(nIn(0) * 1.6) });
    const pIn = ease.outQuart(prog(t, A.in + 0.1, A.in + 0.8));
    tf(this.proxy, { s: lerp(0.9, 1, pIn), o: clamp(pIn * 1.6) });
    tf(this.svc, { x: lerp(60, 0, nIn(0.15)), o: clamp(nIn(0.15) * 1.6) });
    for (const [w, d] of [[this.w1, 0.15], [this.w2, 0.3]]) {
      w.style.transform = `${w.turn}scaleX(${ease.inOutCubic(prog(t, A.in + d, A.in + d + 0.6)).toFixed(3)})`;
    }

    // The agent runs a command. Its environment has only a placeholder.
    const cmd = 'stripe balance retrieve';
    this.cmd.textContent = cmd.slice(0, Math.max(0, Math.floor((t - A.cmd) * 60)));
    tf(this.envName, { o: ease.outCubic(prog(t, A.env, A.env + 0.3)) });
    tf(this.fake, { o: ease.outCubic(prog(t, A.env + 0.08, A.env + 0.4)), x: (1 - ease.outQuart(prog(t, A.env + 0.08, A.env + 0.6))) * 14 });
    const tagP = ease.outQuart(prog(t, A.tag, A.tag + 0.4));
    tf(this.ptag, { s: lerp(0.85, 1, tagP), o: clamp(tagP * 2) });
    tf(this.res, { o: ease.outCubic(prog(t, A.home, A.home + 0.35)), y: (1 - ease.outQuart(prog(t, A.home, A.home + 0.5))) * 10 });

    // The request: agent → proxy (behind the icon) → swap → service.
    const [a0, ap, a1] = G.req;
    let pos = a0;
    let txt = FAKE.slice(0, 16) + '…';
    let cls = '';
    let o = 0;
    if (t >= A.send && t < A.hit + 0.1) {
      if (t < A.swap) {
        pos = at2(a0, ap, ease.inOutCubic(prog(t, A.send, A.atProxy)));
        o = clamp((t - A.send) / 0.1) * (1 - prog(t, A.atProxy - 0.08, A.atProxy));
      } else {
        const p = prog(t, A.swap, A.out + 0.05);
        pos = at2(ap, a1, ease.inOutCubic(prog(t, A.swap, A.hit)));
        txt = scramble(FAKE.slice(0, 16) + '…', REAL_MASKED.slice(0, 16) + '…', p, 17);
        cls = p > 0.6 ? 'real' : 'mid';
        o = clamp((t - A.swap) / 0.08) * (1 - prog(t, A.hit, A.hit + 0.1));
      }
    }
    this.pkT.textContent = txt;
    this.pk.className = `packet ${cls}`;
    tf(this.pk, { x: pos[0], y: pos[1], o, center: true });
    show(this.pk, o > 0);

    // The proxy answers with a ring: blue when it swaps, red when it refuses.
    const swapPulse = prog(t, A.swap - 0.05, A.swap + 0.7);
    const badPulse = prog(t, A.refuse, A.refuse + 0.8);
    this.rings.forEach((r, i) => {
      const p = i === 0 ? swapPulse : badPulse;
      tf(r, { s: 1 + ease.outCubic(p) * 0.6, o: p > 0 && p < 1 ? 1 - ease.inCubic(p) : 0 });
    });
    tf(this.icon, { s: 1 + 0.04 * hump(t, A.swap - 0.05, A.swap + 0.35) + 0.05 * hump(t, A.refuse, A.refuse + 0.35) });

    // The service gets the real key and answers.
    const got = prog(t, A.hit, A.hit + 0.3);
    tf(this.svcReal, { o: ease.outCubic(got) });
    this.svc.classList.toggle('lit', t >= A.hit && t < A.hit + 0.9);
    const okP = ease.outQuart(prog(t, A.hit + 0.05, A.hit + 0.45));
    tf(this.ok, { s: lerp(0.85, 1, okP), o: clamp(okP * 2) });

    // The answer comes back without a key.
    const ro = t >= A.back && t < A.home + 0.05;
    const rp = ease.inOutCubic(prog(t, A.back, A.home));
    const rpos = at2(G.resp[0], G.resp[1], rp);
    tf(this.resp, { center: true, x: rpos[0], y: rpos[1], o: ro ? clamp((t - A.back) / 0.08) * (1 - prog(t, A.home - 0.08, A.home)) : 0 });
    show(this.resp, ro);

    // The wrong host.
    const eIn = ease.outQuart(prog(t, A.bad - 0.25, A.bad + 0.5));
    tf(this.evil, { x: lerp(60, 0, eIn), o: clamp(eIn * 1.6) });
    this.w3.style.transform = `${this.w3.turn}scaleX(${ease.inOutCubic(prog(t, A.bad - 0.15, A.bad + 0.35)).toFixed(3)})`;
    const bo = t >= A.bad && t < A.refuse + 0.7;
    const bp = prog(t, A.refuse, A.refuse + 0.7);
    let bpos;
    if (t < A.refuse) bpos = at2(G.bad[0], G.bad[1], ease.inCubic(prog(t, A.bad, A.refuse)));
    else {
      const e = ease.outCubic(prog(t, A.refuse, A.refuse + 0.6));
      bpos = [G.bad[1][0] + G.back[0] * e, G.bad[1][1] + G.back[1] * e];
    }
    const dq = ease.inQuad(bp);
    tf(this.bad, { center: true, x: bpos[0] + G.drop[0] * dq, y: bpos[1] + G.drop[1] * dq, r: -6 * ease.outCubic(bp), o: bo ? clamp((t - A.bad) / 0.08) * (1 - ease.inCubic(bp)) : 0 });
    this.bad.className = t >= A.refuse ? 'packet badp' : 'packet';
    show(this.bad, bo);
    const rfP = ease.outQuart(prog(t, A.refuse, A.refuse + 0.4));
    tf(this.refused, { s: lerp(0.9, 1, rfP), o: clamp(rfP * 2) });

    revealWords(this.cap.w, t, A.caption, { stagger: 0.04, dy: 18, out: A.exit, outDur: 0.3 });

    // Exit: everything lifts a little and fades.
    const ex = ease.inOutCubic(prog(t, A.exit, A.exit + 0.45));
    tf(this.world, { y: -40 * ex, o: 1 - ex });
  },
});

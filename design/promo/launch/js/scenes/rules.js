// 22–26 (grid). Rules in plain English: the process access sheet with the owner instruction
// and the hard limits (ADR 0007).
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, rectIn, pick } from '../engine.js';
import { headline, cursor, moveCursor } from '../ui.js';
import { T } from '../timeline.js';

const S = T.rules;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const END = T.bouncer + 0.02;

const RULE = 'Only run migrations and tests on staging. Never print or send keys.';
const LIMITS = [
  ['Allowed command prefixes', 'npm run migrate, npm test', true],
  ['Forbidden words', 'prod, --force', true],
  ['Expires after', '120 hours', false],
  ['Runs per hour', '20', false],
];
const A = { in: 0.1, click: 0.75, push: 1.0, type: 1.05, typeEnd: 2.25, pan: 2.3, lim: 2.6, save: 3.45, exit: 3.62 };

// The camera puts a point of the sheet at (X, Y): the top as it rises, the instruction, then
// the hard limits. s: the scales at those three moments. cur: where the pointer rests.
const CAM = pick(
  { X: 960, Y: [1400, 640, 560, 600], s: [1.75, 2.55, 1.95], cur: [[1500, 1150], [1700, 1000]] },
  { X: 540, Y: [2300, 900, 900, 960], s: [1.45, 1.72, 1.6], cur: [[900, 1700], [930, 1420]] },
);

cue(S + 0.0, 'whoosh', { dur: 0.4, gain: 0.5 });
cue(S + 0.02, 'swish', { gain: 0.45 });
cue(S + A.click, 'click', { gain: 0.6 });
cue(S + A.type, 'type', { dur: A.typeEnd - A.type, gain: 0.45 });
cue(S + A.push, 'swish', { gain: 0.3 });
cue(S + A.pan, 'swish', { gain: 0.3 });
LIMITS.forEach((_, i) => cue(S + A.lim + i * 0.16, 'pop', { gain: 0.45, pitch: 0.9 + i * 0.1 }));
cue(S + A.save, 'click', { gain: 0.6 });
cue(S + A.save + 0.05, 'success', { gain: 0.35 });
cue(S + A.exit + 0.05, 'whoosh', { dur: 0.4, gain: 0.55 });

scene({
  id: 'rules',
  start: S - PRE,
  end: END,
  build(root) {
    this.h = headline(root, 'Rules in *plain* *English.*', { size: pick(92, 84), top: pick(66, 270) });
    this.cam = el('div', 'cam3d', root);
    this.sheet = el('div', 'app sheet rulesheet', this.cam);
    this.sheet.innerHTML = `
      <div class="st"><h2>Staging database for Claude Code</h2><p>The agent can run a command with <span class="mono">DATABASE_URL</span> in its environment.</p></div>
      <div class="sb">
        <div class="frow"><span class="fl">Who decides</span><div class="seg"><div class="knob"></div><span class="o1">Ask me each time</span><span class="o2">Bouncer decides</span></div></div>
        <div class="sec"><div class="sh">Your instruction</div><div class="box"><div class="row"><div class="ta"><span class="typed"></span><span class="caret"></span></div></div></div><div class="sf">In plain words. The bouncer checks each request against it.</div></div>
        <div class="sec"><div class="sh">Hard limits</div><div class="box">
          ${LIMITS.map(([k, v, m]) => `<div class="row lim"><span class="k">${k}</span><span class="v ${m ? 'mono' : ''}">${v}</span></div>`).join('')}
        </div><div class="sf">Apassy checks hard limits before the bouncer. A request that fails a hard limit is denied.</div></div>
      </div>
      <div class="sbtn"><span></span><div class="r"><span class="btn bor">Cancel</span><span class="btn pro save">Save</span></div></div>`;
    this.knob = this.sheet.querySelector('.knob');
    this.o1 = this.sheet.querySelector('.o1');
    this.o2 = this.sheet.querySelector('.o2');
    this.typed = this.sheet.querySelector('.typed');
    this.caret = this.sheet.querySelector('.caret');
    this.lims = [...this.sheet.querySelectorAll('.lim .v')];
    this.save = this.sheet.querySelector('.save');
    this.cur = cursor(root);
  },
  render(lt) {
    const t = lt - PRE;
    if (!this.m) {
      // Measure the segmented control and the Save button (sheet coordinates, points).
      const seg = this.sheet.querySelector('.seg');
      this.m = { o1: [this.o1.offsetLeft, this.o1.offsetWidth], o2: [this.o2.offsetLeft, this.o2.offsetWidth] };
      this.segEl = seg;
    }
    revealWords(this.h.w, t, -0.2, { out: A.push - 0.1, outDur: 0.35 });

    // Camera: the sheet rises, pushes in on the instruction, then pans down to the limits.
    if (!this.focus) {
      const keep = this.sheet.style.transform;
      this.sheet.style.transform = 'none';
      const sr = rectIn(this.sheet);
      const ta = rectIn(this.sheet.querySelector('.ta'));
      const lb = rectIn(this.sheet.querySelectorAll('.sec .box')[1]);
      this.focus = {
        top: [310, 150],
        ta: [ta.left - sr.left + ta.width / 2, ta.top - sr.top + ta.height / 2],
        lim: [310, lb.top - sr.top + lb.height / 2 + 20],
      };
      this.sheet.style.transform = keep;
    }
    const F = this.focus;
    const inP = ease.outQuart(prog(t, A.in, A.in + 1.0));
    const pushP = ease.inOutCubic(prog(t, A.push, A.push + 0.55));
    const pan = ease.inOutCubic(prog(t, A.pan, A.pan + 0.65));
    const ex = ease.inOutCubic(prog(t, A.exit, A.exit + 0.4));
    const fx = lerp(lerp(F.top[0], F.ta[0], pushP), F.lim[0], pan);
    const fy = lerp(lerp(F.top[1], F.ta[1], pushP), F.lim[1], pan);
    const sc = lerp(lerp(CAM.s[0], CAM.s[1], pushP), CAM.s[2], pan) * (1 + 0.03 * prog(t, 0.5, 3.6));
    const X = CAM.X;
    const Y = lerp(lerp(lerp(CAM.Y[0], CAM.Y[1], inP), CAM.Y[2], pushP), CAM.Y[3], pan);
    const x = X - fx * sc;
    const y = Y - fy * sc - 50 * ex;
    const rx = lerp(lerp(lerp(14, 4, inP), 1.5, pushP), 2.5, pan);
    const ry = lerp(lerp(-6, -2, inP), -0.5, pushP) + 1.5 * pan;
    this.sheet.style.transformOrigin = `${fx.toFixed(1)}px ${fy.toFixed(1)}px`;
    this.sheet.style.transform = `translate3d(${x.toFixed(1)}px,${y.toFixed(1)}px,0) translate(${(fx * sc - fx).toFixed(1)}px,${(fy * sc - fy).toFixed(1)}px) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) scale(${sc.toFixed(4)})`;
    this.sheet.style.opacity = (clamp(inP * 2.5) * (1 - ex)).toFixed(3);

    // "Bouncer decides" gets selected.
    const k = ease.inOutCubic(prog(t, A.click + 0.02, A.click + 0.25));
    const [l1, w1] = this.m.o1;
    const [l2, w2] = this.m.o2;
    this.knob.style.left = `${lerp(l1, l2, k)}px`;
    this.knob.style.width = `${lerp(w1, w2, k)}px`;
    this.o1.style.fontWeight = k < 0.5 ? 560 : 400;
    this.o2.style.fontWeight = k >= 0.5 ? 560 : 400;

    // The instruction types itself.
    const n = Math.floor(clamp(prog(t, A.type, A.typeEnd)) * RULE.length);
    this.typed.textContent = RULE.slice(0, n);
    this.caret.style.opacity = t < A.type ? (Math.floor(t * 2.5) % 2 ? 0 : 1) : n < RULE.length ? 1 : Math.floor(t * 2.5) % 2 ? 0 : 1;

    // Hard limits fill in one by one.
    this.lims.forEach((v, i) => {
      const p = prog(t, A.lim + i * 0.16, A.lim + i * 0.16 + 0.45);
      tf(v, { x: (1 - ease.outQuart(p)) * 12, o: ease.outCubic(clamp(p * 1.5)) });
    });

    // The pointer: to "Bouncer decides", then away, then to Save.
    const segR = rectIn(this.segEl);
    const saveR = rectIn(this.save);
    const o2c = [segR.left + segR.width * 0.75, segR.top + segR.height * 0.5];
    const svc = [saveR.left + saveR.width * 0.5, saveR.top + saveR.height * 0.55];
    moveCursor(this.cur, t, [
      [0.2, ...CAM.cur[0]],
      [A.click - 0.05, o2c[0], o2c[1]],
      [A.click + 0.45, ...CAM.cur[1]],
      [A.save - 0.4, ...CAM.cur[1]],
      [A.save - 0.02, svc[0], svc[1]],
    ], [A.click, A.save]);
    this.cur.style.opacity = (clamp((t - 0.35) / 0.2) * (1 - ex)).toFixed(3);
    this.save.style.filter = t >= A.save - 0.05 && t < A.save + 0.12 ? 'brightness(0.85)' : 'none';
  },
});

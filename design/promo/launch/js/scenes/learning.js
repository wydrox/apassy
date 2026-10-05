// 38–42 (grid). It learns what is normal: the Learning view with the ask rate over 14 days.
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, pick, W, H } from '../engine.js';
import { headline, appWindow, chip } from '../ui.js';
import { T } from '../timeline.js';

const S = T.learning;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const END = T.proof + 0.02;

const RATES = [46, 41, 36, 31, 27, 23, 20, 17, 15, 13, 12, 10, 9, 8];
const MAX = 50;
const PLOT_H = 170;
const A = { in: 0.05, cols: 0.55, goal: 1.55, chip: 2.15, exit: 3.55 };

// The camera: the window scale, its x offset and drift, where it rises from and settles, and
// the center of the pattern chip.
const CAM = pick(
  { s: 1.42, x: -60, dx: 26, y: [1000, 330], dy: 36, chip: [1180, 975] },
  { s: 1.2, x: -130, dx: 10, y: [1300, 52], dy: 30, chip: [540, 1330] },
);

cue(S + 0.0, 'whoosh', { dur: 0.4, gain: 0.5 });
cue(S + 0.02, 'swish', { gain: 0.45 });
RATES.forEach((_, i) => cue(S + A.cols + i * 0.065, 'tick', { gain: 0.25, pitch: 1.4 - i * 0.04 }));
cue(S + A.goal, 'rise', { dur: 0.35, gain: 0.3 });
cue(S + A.chip, 'pop', { gain: 0.5, pitch: 1.2 });
cue(S + A.exit, 'whoosh', { dur: 0.45, gain: 0.55 });

scene({
  id: 'learning',
  start: S - PRE,
  end: END,
  build(root) {
    this.h = headline(root, pick('It learns what’s *normal.*', 'It learns\nwhat’s *normal.*'), { size: pick(92, 96), top: pick(66, 250) });
    this.stage = el('div', 'abs cam3d', root);
    const days = RATES.map((_, i) => `09-${String(14 + i).padStart(2, '0')}`);
    const page = `<div class="phead"><h1>Learning</h1></div>
      <div class="psub">Apassy learns from your decisions. A remembered pattern and a calibrated level act only at the model step. They never change the hard rules, the production rule, or a rule flag.</div>
      <div class="tiles">
        <div class="stile"><div class="l">Asked you, last 7 days</div><div class="v n1">9%</div><div class="c">31 of 342 runs · goal 10% or less</div></div>
        <div class="stile"><div class="l">Ran without you</div><div class="v n2">311</div><div class="c">model 262 · pattern 49</div></div>
        <div class="stile"><div class="l">Remembered patterns</div><div class="v n3">14</div><div class="c">active · 3 still learning</div></div>
      </div>
      <div class="sec"><div class="sh">Ask rate over time</div><div class="box chartbox"><div class="chart">
        <div class="legend"><i></i>Goal: 10% or less</div>
        <div class="plot">${RATES.map((v, i) => `<div class="col" style="left:${i * 50 + 10}px"><div class="bar"></div><div class="val">${v}%</div><div class="day">${days[i]}</div></div>`).join('')}
        <div class="goal" style="bottom:${(10 / MAX) * PLOT_H}px"></div></div>
      </div></div></div>`;
    this.win = appWindow(this.stage, { w: 1180, h: 820, sel: 'Learning', badges: { vault: 7, activity: 0 }, page });
    this.win.style.left = `${W / 2 - 590}px`;
    this.win.style.top = `${H / 2 - 410}px`;
    this.cols = [...this.win.querySelectorAll('.col')];
    this.goal = this.win.querySelector('.goal');
    this.legend = this.win.querySelector('.legend');
    this.nums = [this.win.querySelector('.n1'), this.win.querySelector('.n2'), this.win.querySelector('.n3')];
    this.chip = chip(root, 'sparkle', 'Approve and remember: no prompt after 3 approvals', { color: '#34c759', cls: 'bigchip' });
    this.chip.style.left = '0px';
    this.chip.style.top = '0px';
  },
  render(lt) {
    const t = lt - PRE;
    revealWords(this.h.w, t, -0.2, { out: A.exit, outDur: 0.3 });

    const inP = ease.outQuart(prog(t, A.in - 0.25, A.in + 1.0));
    const drift = ease.inOutSine(prog(t, 0.6, A.exit));
    const ex = ease.inOutCubic(prog(t, A.exit, A.exit + 0.45));
    const sc = CAM.s + 0.04 * drift + 0.04 * ex;
    const rx = lerp(16, 7, inP) - 3 * drift;
    const ry = lerp(7, 3.5, inP) - 2 * drift;
    const y = lerp(CAM.y[0], CAM.y[1], inP) - CAM.dy * drift;
    this.win.style.transform = `translate3d(${(CAM.x + CAM.dx * drift).toFixed(1)}px,${y.toFixed(1)}px,0) rotateX(${rx.toFixed(2)}deg) rotateY(${ry.toFixed(2)}deg) scale(${sc.toFixed(4)})`;
    this.stage.style.opacity = (clamp(inP * 2.5) * (1 - ex)).toFixed(3);

    // Columns grow one by one.
    this.cols.forEach((c, i) => {
      const p = ease.outCubic(prog(t, A.cols + i * 0.065, A.cols + i * 0.065 + 0.45));
      c.firstChild.style.height = `${((RATES[i] / MAX) * PLOT_H * p).toFixed(1)}px`;
      c.children[1].style.opacity = clamp((p - 0.6) / 0.4).toFixed(3);
      c.children[1].style.bottom = `${((RATES[i] / MAX) * PLOT_H * p + 4).toFixed(1)}px`;
      c.classList.toggle('under', RATES[i] <= 10);
    });
    const g = ease.inOutCubic(prog(t, A.goal, A.goal + 0.45));
    this.goal.style.transform = `scaleX(${g.toFixed(3)})`;
    this.legend.style.opacity = g.toFixed(3);

    // The figures count up.
    const cnt = ease.outCubic(prog(t, 0.5, 1.5));
    this.nums[0].textContent = `${Math.round(lerp(46, 9, cnt))}%`;
    this.nums[1].textContent = `${Math.round(lerp(0, 311, cnt))}`;
    this.nums[2].textContent = `${Math.round(lerp(0, 14, cnt))}`;

    // The pattern chip.
    const k = ease.outQuart(prog(t, A.chip, A.chip + 0.7));
    tf(this.chip, { x: CAM.chip[0], y: CAM.chip[1] + lerp(24, 0, k), s: lerp(0.94, 1, k), o: clamp(k * 1.6) * (1 - ex), center: true });
  },
});

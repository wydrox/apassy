// 42–48 (grid). The measured results of the blind held-out set v4 (README), then the agents
// it works with and how it is built.
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, show, pick, TALL, W } from '../engine.js';
import { headline, ic } from '../ui.js';
import { iconSVG } from '../logo.js';
import { T } from '../timeline.js';

const S = T.proof;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const END = T.outro + 0.02;

const A = { n1: 0.0, n2: 0.5, out: 2.25, works: 2.6, badges: 3.4, exit: 5.6 };
const BADGES = [
  ['box', 'Built in Rust', '#ff6b35'],
  ['cpu', 'Local bouncer model', '#0a77fe'],
  ['shield', 'Agents in a sandbox', '#34c759'],
  ['lock', 'SQLCipher vault', '#8e5cf7'],
];

cue(S + A.n1, 'hit', { gain: 0.7 });
cue(S + A.n1, 'roll', { dur: 0.45, gain: 0.35 });
cue(S + A.n2, 'hit', { gain: 0.7 });
cue(S + A.n2 + 0.05, 'roll', { dur: 0.8, gain: 0.35 });
cue(S + A.out, 'whoosh', { dur: 0.4, gain: 0.55 });
cue(S + A.works + 0.25, 'pop', { gain: 0.5, pitch: 0.9 });
cue(S + A.works + 0.4, 'pop', { gain: 0.5, pitch: 1.1 });
cue(S + A.works + 0.55, 'pop', { gain: 0.5, pitch: 1.3 });
BADGES.forEach((_, i) => cue(S + A.badges + i * 0.12, 'tick', { gain: 0.35, pitch: 1 + i * 0.1 }));
cue(S + A.exit, 'whoosh', { dur: 0.45, gain: 0.5 });

scene({
  id: 'proof',
  start: S - PRE,
  end: END,
  build(root) {
    this.stats = el('div', 'abs world', root);
    this.eyebrow = el('div', 'eyebrow', this.stats, 'Blind held-out test · 226 cases');
    this.s1 = el('div', 'stat', this.stats, `<div class="big"><span class="roll">0</span></div><div class="lab">violations ran without you</div><div class="sub">No critical case either</div>`);
    this.s2 = el('div', 'stat', this.stats, `<div class="big"><span class="cnt">0</span>%</div><div class="lab">of normal work ran with no prompt</div><div class="sub">On day one, before any learning</div>`);
    const [p1, p2] = pick([[160, 250], [1000, 250]], [[160, 380], [160, 890]]);
    Object.assign(this.s1.style, { left: `${p1[0]}px`, top: `${p1[1]}px` });
    Object.assign(this.s2.style, { left: `${p2[0]}px`, top: `${p2[1]}px` });
    this.div = el('div', 'vdiv', this.stats);
    this.roll = this.s1.querySelector('.roll');
    this.cnt = this.s2.querySelector('.cnt');

    this.works = el('div', 'abs world', root);
    this.wh = headline(this.works, pick('Works with the agents *you* *use.*', 'Works with the\nagents *you* *use.*'), { size: 84, top: pick(158, 280) });
    this.hub = el('div', 'hub', this.works, iconSVG(150));
    this.link1 = el('div', 'link', this.works);
    this.link2 = el('div', 'link r', this.works);
    this.lab1 = el('div', 'linklab', this.works, 'MCP · hooks');
    this.lab2 = el('div', 'linklab r', this.works, 'MCP · hooks');
    this.a1 = el('div', 'agentchip', this.works, `<span class="av">✻</span>Claude Code`);
    this.a2 = el('div', 'agentchip', this.works, `<span class="av cx">${ic('code', '', 2)}</span>Codex`);
    if (!TALL) {
      this.a1.style.right = `${1920 - 575}px`;
      this.a2.style.left = '1345px';
    }
    const row = el('div', 'pbadges', this.works);
    this.badges = BADGES.map(([i, text, c]) => el('div', 'pbadge', row, `<span style="color:${c}">${ic(i, '', 1.8)}</span>${text}`));
  },
  render(lt) {
    const t = lt - PRE;
    // 1. The numbers.
    const outP = ease.inOutCubic(prog(t, A.out, A.out + 0.35));
    show(this.stats, t < A.out + 0.4);
    const p1 = ease.outQuart(prog(t, A.n1, A.n1 + 0.8));
    const p2 = ease.outQuart(prog(t, A.n2, A.n2 + 0.8));
    tf(this.s1, { y: lerp(40, 0, p1) - 40 * outP, s: lerp(0.96, 1, p1), o: clamp(p1 * 2) * (1 - outP) });
    tf(this.s2, { y: lerp(40, 0, p2) - 40 * outP, s: lerp(0.96, 1, p2), o: clamp(p2 * 2) * (1 - outP) });
    tf(this.eyebrow, { o: ease.outCubic(prog(t, -0.1, 0.4)) * (1 - outP), y: -20 * outP });
    tf(this.div, { [pick('sy', 'sx')]: ease.inOutCubic(prog(t, 0.3, 1.1)), o: 1 - outP });
    // "0": a slot roll from 9 down to 0.
    const rp = prog(t, A.n1, A.n1 + 0.45);
    this.roll.textContent = rp >= 1 ? '0' : String(9 - Math.floor(ease.outCubic(rp) * 9));
    this.cnt.textContent = String(Math.round(76 * ease.outCubic(prog(t, A.n2 + 0.05, A.n2 + 0.85))));

    // 2. Works with.
    const w = t >= A.works;
    show(this.works, w);
    if (!w) return;
    const ex = ease.inOutCubic(prog(t, A.exit, A.exit + 0.45));
    revealWords(this.wh.w, t, A.works, { stagger: 0.05 });
    const hk = ease.outQuart(prog(t, A.works + 0.1, A.works + 0.8));
    tf(this.hub, { s: lerp(0.9, 1, hk), o: clamp(hk * 1.6) });
    const l = ease.inOutCubic(prog(t, A.works + 0.2, A.works + 0.9));
    this.link1.style.transform = `${pick('scaleX', 'scaleY')}(${l.toFixed(3)})`;
    this.link2.style.transform = `${pick('scaleX', 'scaleY')}(${l.toFixed(3)})`;
    if (TALL && this.a1.style.left === '') {
      // Center the agent chips above and below the icon.
      for (const c of [this.a1, this.a2]) c.style.left = `${(W - c.offsetWidth) / 2}px`;
    }
    tf(this.lab1, { o: clamp((l - 0.5) * 2) });
    tf(this.lab2, { o: clamp((l - 0.5) * 2) });
    for (const [c, d, dir] of [[this.a1, 0.3, -1], [this.a2, 0.45, 1]]) {
      const k = ease.outQuart(prog(t, A.works + d, A.works + d + 0.75));
      tf(c, { x: dir * lerp(-40, 0, k), o: clamp(k * 1.6) });
    }
    this.badges.forEach((b, i) => {
      const k = ease.outQuart(prog(t, A.badges + i * 0.12, A.badges + i * 0.12 + 0.7));
      tf(b, { y: lerp(24, 0, k), o: clamp(k * 1.6) });
    });
    tf(this.works, { s: pick(1.12, 1) + 0.025 * ease.inOutSine(prog(t, A.works, A.exit)), y: -30 * ex, o: 1 - ex });
  },
});

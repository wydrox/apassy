// 48–55 (grid). The promise, then the logo and the call to action.
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, show, pick, TALL, W } from '../engine.js';
import { headline, ic } from '../ui.js';
import { lockup, playLockup, LOCKUP_DONE, MARK_H, LOCKUP_W, LOCKUP_H } from '../logo.js';
import { T } from '../timeline.js';

const S = T.outro;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const L = T.lockup - S; // the lockup lands on the last big hit
const CTA = 'github.com/wydrox/apassy';
const SUB = 'For macOS · Works with Claude Code and Codex';
const LH = pick(176, 172); // lockup height, px
const CY = pick(420, 800); // the center of the mark on screen
// The tops of the promise, the tagline, and the centers of the button and the line under it.
const Y = pick({ l1: 350, l2: 510, tag: 578, cta: 722, sub: 808 }, { l1: 560, l2: 880, tag: 950, cta: 1182, sub: 1272 });

cue(S + 0.0, 'swish', { gain: 0.5 });
cue(S + 1.0, 'swish', { gain: 0.55 });
cue(T.lockup - 0.5, 'reverse', { dur: 0.5, gain: 0.6 });
cue(T.lockup, 'impact', { gain: 1 });
cue(T.lockup + 0.03, 'shimmer', { gain: 0.5 });
cue(T.lockup + 0.75, 'swish', { gain: 0.45 });
cue(T.lockup + LOCKUP_DONE + 0.4, 'pop', { gain: 0.45, pitch: 1.2 });

scene({
  id: 'outro',
  start: S - PRE,
  end: T.end + 0.5,
  build(root) {
    this.l1 = headline(root, pick('Agents get access.', 'Agents get\naccess.'), { size: 132, top: Y.l1 });
    this.l2 = headline(root, pick('Never your *secrets.*', 'Never your\n*secrets.*'), { size: 132, top: Y.l2 });

    this.group = el('div', 'abs world', root);
    this.group.style.transformOrigin = `${W / 2}px ${CY}px`;
    this.L = lockup(this.group, LH);
    const w = (LH * LOCKUP_W) / LOCKUP_H;
    this.L.el.style.left = `${(W - w) / 2}px`;
    this.L.el.style.top = `${CY - (MARK_H / 2) * this.L.scale}px`;
    this.tag = el('div', 'tagline', this.group);
    this.tag.style.top = `${Y.tag}px`;
    if (!TALL) this.tag.style.fontSize = '42px';
    this.tagW = [];
    'A credential manager for you and [hl:your_agents.]'.split(' ').forEach((tok) => {
      const m = tok.match(/^\[(\w+):(.+)\]$/);
      const s = el('span', `w ${m ? m[1] : ''}`, this.tag);
      s.textContent = (m ? m[2] : tok).replace(/_/g, ' ');
      this.tag.appendChild(document.createTextNode(' '));
      if (TALL && tok === 'manager') el('br', '', this.tag);
      this.tagW.push(s);
    });
    this.cta = el('div', 'cta', this.group, `${ic('arrowR', '', 2.2)}<span>${CTA}</span>`);
    this.sub = el('div', 'ctasub', this.group, SUB);
  },
  render(lt) {
    const t = lt - PRE;
    // 1. The promise. The first line steps back to gray when the second arrives.
    revealWords(this.l1.w, t, -0.15, { stagger: 0.07 });
    revealWords(this.l2.w, t, 1.0, { stagger: 0.08 });
    const dim = ease.inOutCubic(prog(t, 1.0, 1.5));
    this.l1.el.style.color = `rgb(${lerp(14, 134, dim) | 0},${lerp(24, 134, dim) | 0},${lerp(32, 139, dim) | 0})`;
    const out = ease.inOutCubic(prog(t, L - 0.3, L - 0.02));
    for (const h of [this.l1, this.l2]) {
      tf(h.el, { s: (1 + 0.02 * prog(t, 0, L)) * (1 - 0.03 * out), o: 1 - out });
      show(h.el, t < L);
    }

    // 2. The lockup, the tagline, and the call to action.
    const u = t - L;
    const on = u >= 0;
    show(this.group, on);
    if (!on) return;
    playLockup(this.L, u);
    revealWords(this.tagW, u, LOCKUP_DONE, { stagger: 0.04 });
    const c0 = LOCKUP_DONE + 0.4;
    const ck = ease.outQuart(prog(u, c0, c0 + 0.8));
    tf(this.cta, { center: true, x: W / 2, y: Y.cta + lerp(20, 0, ck), o: clamp(ck * 1.6) });
    const sk = ease.outQuart(prog(u, c0 + 0.25, c0 + 1.05));
    tf(this.sub, { center: true, x: W / 2, y: Y.sub + lerp(16, 0, sk), o: clamp(sk * 1.6) });
    const push = 1 + 0.02 * ease.inOutSine(prog(u, 0.8, 5));
    tf(this.group, { s: push });
  },
});

// 8–12 (grid). The drop: the logo on a light screen. The door of the mark swings open,
// the name rises into place, then the tagline.
import { scene, cue, el, tf, prog, ease, revealWords, pick, TALL, W } from '../engine.js';
import * as FX from '../fx.js';
import { lockup, playLockup, LOCKUP_DONE, MARK_H, LOCKUP_W, LOCKUP_H } from '../logo.js';
import { T } from '../timeline.js';

const S = T.reveal;
const END = T.vault + 0.05;
const LH = pick(190, 172); // lockup height, px
const CY = pick(468, 850); // the center of the mark on screen

FX.bg(S, FX.LIGHT);
cue(S, 'impact', { gain: 1 });
cue(S + 0.02, 'shimmer', { gain: 0.5 });
cue(S + 0.75, 'swish', { gain: 0.55 });
cue(S + LOCKUP_DONE, 'swish', { gain: 0.35 });
cue(S + 3.55, 'whoosh', { dur: 0.45, gain: 0.7 });

scene({
  id: 'reveal',
  start: S,
  end: END,
  z: 2,
  build(root) {
    this.group = el('div', 'abs world', root);
    this.group.style.transformOrigin = `960px ${CY}px`;
    this.L = lockup(this.group, LH);
    const w = (LH * LOCKUP_W) / LOCKUP_H;
    this.L.el.style.left = `${(W - w) / 2}px`;
    this.L.el.style.top = `${CY - (MARK_H / 2) * this.L.scale}px`;

    this.tag = el('div', 'tagline', this.group);
    this.tag.style.top = `${pick(640, 990)}px`;
    this.tagW = [];
    'A credential manager for you and [hl:your_agents.]'.split(' ').forEach((tok) => {
      const m = tok.match(/^\[(\w+):(.+)\]$/);
      const s = el('span', `w ${m ? m[1] : ''}`, this.tag);
      s.textContent = (m ? m[2] : tok).replace(/_/g, ' ');
      this.tag.appendChild(document.createTextNode(' '));
      if (TALL && tok === 'manager') el('br', '', this.tag);
      this.tagW.push(s);
    });
  },
  render(lt) {
    const t = lt;
    playLockup(this.L, t);
    revealWords(this.tagW, t, LOCKUP_DONE, { stagger: 0.04 });

    // A slow push while it holds, then it steps back and fades.
    const push = 1 + 0.02 * ease.inOutSine(prog(t, 0.8, 3.5));
    const ex = ease.inOutCubic(prog(t, 3.45, 3.95));
    tf(this.group, { s: push * (1 - 0.03 * ex), o: 1 - ex });
  },
});

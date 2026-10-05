// "3:07am": a 14-second short for Reels, TikTok, Shorts (9:16) and the X, Threads, and
// LinkedIn feeds (4:5). Your agent wants to reset the production database at night.
// Production runs wait for the owner (ADR 0010), and you are asleep, so nothing runs.
// A notification shows only the agent and the event, never the command (ADR 0010).
//
// Real seconds, 100 BPM (a bar is 2.4 s): night 0–7.2, morning 7.2–9.6, the logo 9.6–14.4.
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, show, FORMAT, W } from '../engine.js';
import * as FX from '../fx.js';
import { headline, terminal, tline, typeLine, popLine, ic } from '../ui.js';
import { lockup, playLockup, iconSVG, LOCKUP_DONE, MARK_H, LOCKUP_W, LOCKUP_H } from '../logo.js';

if (FORMAT === 'wide') throw new Error('The 3:07am short has a 9:16 (tall) and a 4:5 (feed) layout.');

export const NAME = '3am';
export const PACE = 1;
export const DURATION = 14.4;
export const out = (format) => `apassy-3am-${format === 'feed' ? '4x5' : '9x16'}.mp4`;

const NIGHT = [10, 11, 15];
const MORNING = 7.2;
const LOGO = 9.6;
FX.bg(0, NIGHT);
FX.bg(MORNING - 0.1, FX.LIGHT, 0.3);

// The layout of each format. Tall keeps its content between y 250 and 1500 (the Reels and
// TikTok overlays); feed has no overlays.
const L = {
  tall: {
    cap: { top: 420, size: 96 }, sub: { top: 540, size: 50 },
    note: { y: 690, s: 2.3 }, term: { top: [760, 880], w: 990, h: 380 },
    morning: [800, 880, 124], logo: { cy: 820, h: 172 }, tag: 985, cta: 1140, ctasub: 1226,
  },
  feed: {
    cap: { top: 230, size: 92 }, sub: { top: 342, size: 46 },
    note: { y: 440, s: 2.1 }, term: { top: [510, 620], w: 940, h: 350 },
    morning: [560, 632, 116], logo: { cy: 560, h: 160 }, tag: 710, cta: 852, ctasub: 932,
  },
}[FORMAT];

// Sound.
cue(0.25, 'type', { dur: 0.95, gain: 0.3 });
cue(1.4, 'type', { dur: 0.5, gain: 0.32 });
cue(2.0, 'tick', { gain: 0.35, pitch: 0.9 });
cue(2.4, 'notify', { gain: 0.75 });
cue(2.75, 'pulse', { gain: 0.3 });
cue(2.9, 'swish', { gain: 0.25 });
cue(4.8, 'swish', { gain: 0.2 });
cue(MORNING - 0.15, 'rise', { dur: 0.3, gain: 0.25 });
cue(LOGO, 'impact', { gain: 0.55 });
cue(LOGO + 0.02, 'shimmer', { gain: 0.35 });
cue(LOGO + 0.75, 'swish', { gain: 0.3 });
cue(LOGO + LOCKUP_DONE + 0.4, 'pop', { gain: 0.4, pitch: 1.2 });

/** A caption: rises in at t0, leaves at t1 (both optional). */
function caption(h, t, t0, t1) {
  revealWords(h.w, t, t0, { stagger: 0.03, dur: 0.4, dy: 20, out: t1, outDur: 0.18, outStagger: 0.01 });
  show(h.el, t >= t0 - 0.05 && (t1 == null || t < t1 + 0.25));
}

// 0–7.2: night. The agent, the request, the wait.
scene({
  id: 'night',
  start: 0,
  end: MORNING,
  build(root) {
    this.pov = headline(root, "[dim:POV:] it's 3:07am", { size: L.cap.size, top: L.cap.top });
    this.pov2 = headline(root, 'your agent is ‘just fixing one migration’', { size: L.sub.size, top: L.sub.top, weight: 500 });
    this.pov2.el.classList.add('sub');
    this.wait = headline(root, 'prod runs wait for you.', { size: L.cap.size, top: L.cap.top });
    this.asleep = headline(root, 'you’re asleep.', { size: L.cap.size, top: L.cap.top });
    this.nothing = headline(root, 'so nothing runs.', { size: L.cap.size, top: L.cap.top });

    this.term = terminal(root, { title: 'claude — ~/dev/acme-api', w: L.term.w, h: L.term.h, cls: 's3term' });
    this.term.style.left = `${(W - L.term.w) / 2}px`;
    this.lines = [
      tline(this.term, [['⏺ ', 'cc'], ['The migration keeps failing.', 'u']]),
      tline(this.term, [['  ', ''], ['I’ll reset the database and start fresh.', 'u']]),
      tline(this.term, [['⏺ ', 'cc'], ['Bash', 'bo'], ['(npm run db:reset)', 'u']]),
      tline(this.term, [['  ⎿  ', 'd'], ['DATABASE_URL', 'k'], [' · ', 'd'], ['production', 'o']]),
      tline(this.term, [['  ⎿  ', 'd'], ['Waiting for the owner', 'y'], ['', 'y']]),
    ];
    this.dots = this.lines[4].spans[2];

    // A macOS notification: the agent and the event, not the command.
    this.note = el('div', 'app notif s3notif', root);
    this.note.innerHTML = `<div class="ic">${iconSVG(38)}</div><div class="tx"><span class="when">now</span><b>apassy</b><div>Claude Code wants to run a command</div></div>`;
    this.note.style.transformOrigin = '0 0';
  },
  render(t) {
    // Captions. The first one is already there on the first frame.
    caption(this.pov, t, -1, 2.72);
    caption(this.pov2, t, -1, 2.72);
    caption(this.wait, t, 2.9, 4.68);
    caption(this.asleep, t, 4.86, 5.86);
    caption(this.nothing, t, 6.02);

    // The terminal: the agent's first line is there on the first frame; it moves down for the
    // notification.
    const down = ease.inOutCubic(prog(t, 2.25, 2.6));
    tf(this.term, { y: lerp(L.term.top[0], L.term.top[1], down) });
    typeLine(this.lines[0], t, -0.8, 40);
    typeLine(this.lines[1], t, 0.25, 45);
    typeLine(this.lines[2], t, 1.4, 50);
    popLine(this.lines[4], t, 2.75);
    this.dots.textContent = t < 2.75 ? '' : '.'.repeat(1 + (Math.floor((t - 2.75) / 0.35) % 3));

    // The notification drops in.
    const n = ease.outQuart(prog(t, 2.4, 2.8));
    tf(this.note, { x: W / 2 - 190 * L.note.s, y: L.note.y - 36 * (1 - n), s: L.note.s, o: clamp(n * 2) });

    // Asleep: everything dims except the line that waits.
    const dim = ease.inOutCubic(prog(t, 4.8, 5.3));
    for (const l of this.lines.slice(0, 3)) l.style.opacity = (1 - 0.72 * dim).toFixed(3);
    const p3 = prog(t, 2.0, 2.25);
    tf(this.lines[3], { y: (1 - ease.outCubic(p3)) * 10, o: (p3 > 0 ? ease.outCubic(clamp(p3 * 1.5)) : 0) * (1 - 0.72 * dim) });
    this.term.querySelector('.tbar').style.opacity = (1 - 0.6 * dim).toFixed(3);
    this.note.style.opacity = (clamp(n * 2) * (1 - 0.7 * dim)).toFixed(3);

    // The night goes out just before the lights come up.
    this.root.style.opacity = (1 - ease.inOutCubic(prog(t, 6.95, 7.15))).toFixed(3);
  },
});

// 7.2–9.6: morning.
scene({
  id: 'morning',
  start: MORNING - 0.1,
  end: LOGO,
  build(root) {
    const [timeTop, lineTop, size] = L.morning;
    this.time = headline(root, '[dim:8:02am.]', { size: Math.round(size * 0.52), top: timeTop, weight: 500 });
    this.fine = headline(root, 'prod is fine.', { size, top: lineTop });
  },
  render(lt, t) {
    caption(this.time, t, MORNING + 0.08, LOGO - 0.3);
    caption(this.fine, t, MORNING + 0.24, LOGO - 0.3);
  },
});

// 9.6–14.4: the logo, what it is, where to get it. It loops back to the night.
scene({
  id: 'brand',
  start: LOGO,
  end: DURATION + 0.5,
  build(root) {
    this.group = el('div', 'abs world', root);
    this.group.style.transformOrigin = `${W / 2}px ${L.logo.cy}px`;
    this.L = lockup(this.group, L.logo.h);
    const w = (L.logo.h * LOCKUP_W) / LOCKUP_H;
    this.L.el.style.left = `${(W - w) / 2}px`;
    this.L.el.style.top = `${L.logo.cy - (MARK_H / 2) * this.L.scale}px`;
    this.tag = el('div', 'tagline', this.group);
    this.tag.style.top = `${L.tag}px`;
    this.tagW = [];
    'the bouncer for [hl:your_AI_agents.]'.split(' ').forEach((tok) => {
      const m = tok.match(/^\[(\w+):(.+)\]$/);
      const s = el('span', `w ${m ? m[1] : ''}`, this.tag);
      s.textContent = (m ? m[2] : tok).replace(/_/g, ' ');
      this.tag.appendChild(document.createTextNode(' '));
      this.tagW.push(s);
    });
    this.cta = el('div', 'cta', this.group, `${ic('arrowR', '', 2.2)}<span>github.com/wydrox/apassy</span>`);
    this.sub = el('div', 'ctasub', this.group, 'For macOS · Works with Claude Code and Codex');
  },
  render(lt) {
    const u = lt;
    playLockup(this.L, u);
    revealWords(this.tagW, u, LOCKUP_DONE, { stagger: 0.035, dur: 0.5, dy: 18 });
    const c0 = LOCKUP_DONE + 0.4;
    const ck = ease.outQuart(prog(u, c0, c0 + 0.6));
    tf(this.cta, { center: true, x: W / 2, y: L.cta + lerp(18, 0, ck), o: clamp(ck * 1.6) });
    const sk = ease.outQuart(prog(u, c0 + 0.2, c0 + 0.8));
    tf(this.sub, { center: true, x: W / 2, y: L.ctasub + lerp(14, 0, sk), o: clamp(sk * 1.6) });
    tf(this.group, { s: 1 + 0.02 * ease.inOutSine(prog(u, 0.8, 4.8)) });
  },
});

// 32–38 (grid). When in doubt, it asks you: the notification, the approval card of the app,
// and "Deny" on the beat (35 s). Nothing runs.
import { scene, cue, el, tf, prog, ease, clamp, lerp, revealWords, show, hump, rectIn, pick, W } from '../engine.js';
import { headline, ic, btn, cursor, moveCursor, terminal, tline, typeLine } from '../ui.js';
import { iconSVG } from '../logo.js';
import { T } from '../timeline.js';

const S = T.approval;
const PRE = 0.25; // the scene starts before its cut, so it is already moving at the cut
const END = T.learning + 0.02;

const A = { notif: 0.25, morph: 1.05, risk: 1.75, cur: 2.2, click: 3.0, toast: 3.2, term: 3.55, exit: 5.55 };

// ns, cs: the scales of the notification and the card; y: their tops; leave: how the card
// makes room for the terminal ([x, y]); toast: its center y; term: [left, top]; cur: the start.
const LAY = pick(
  { ns: 1.75, ny: 330, cs: 1.74, cy: [340, 262], leave: [-120, -40], toast: 830, term: [1010, 790], cur: [1650, 1150] },
  { ns: 2.1, ny: 600, cs: 1.45, cy: [640, 560], leave: [0, -40], toast: 1060, term: [130, 1040], cur: [900, 1650] },
);

cue(S + 0.0, 'swish', { gain: 0.45 });
cue(S + A.notif, 'notify', { gain: 0.8 });
cue(S + A.morph, 'whoosh', { dur: 0.35, gain: 0.35 });
cue(S + A.risk, 'pulse', { gain: 0.35 });
cue(S + A.click, 'click', { gain: 0.8 });
cue(S + A.click + 0.01, 'deny', { gain: 1 });
cue(S + A.toast, 'pop', { gain: 0.4, pitch: 0.9 });
cue(S + A.term, 'type', { dur: 0.45, gain: 0.35 });
cue(S + A.exit, 'whoosh', { dur: 0.45, gain: 0.55 });

scene({
  id: 'approval',
  start: S - PRE,
  end: END,
  build(root) {
    this.h = headline(root, pick('When in doubt, it asks *you.*', 'When in doubt,\nit asks *you.*'), { size: pick(88, 96), top: pick(66, 250) });
    this.cam = el('div', 'cam3d', root);

    // The macOS notification: the agent and the event, never the command (ADR 0010).
    this.notif = el('div', 'app notif big', this.cam);
    this.notif.innerHTML = `<div class="ic">${iconSVG(38)}</div><div class="tx"><span class="when">now</span><b>apassy</b><div>Claude Code asks to run a command with secrets</div></div>`;

    // The approval card (as in src/desktop/ui/activity.rs).
    this.card = el('div', 'app acard big', this.cam);
    this.card.innerHTML = `
      <div class="hd"><span class="dot warn"></span><span class="ttl">Claude Code asks to run a command with secrets</span><span class="tag warn st1">Waiting</span><span class="tag bad st2">Denied</span></div>
      <div class="ur">User request (hook): "run the migrations on staging"</div>
      <div class="code">npm run db:reset</div>
      <div class="grid2"><span class="k">Purpose</span><span>Reset the database before the migration</span><span class="k">Folder</span><span>~/dev/acme-api</span><span class="k">Secrets</span><span>DATABASE_URL</span></div>
      <div class="note warn risk">Below the needed certainty: destructive, purpose_mismatch. destructive 94%, purpose_mismatch 91%.</div>
      <div class="note">The process can read these secrets. Approve only a command that you trust. An approval needs Touch ID or the passphrase now. A notification is not an approval.</div>
      <div class="btns"><span class="btn des deny">Deny</span><div class="r">${btn('Approve once', 'pro')}</div></div>`;
    this.deny = this.card.querySelector('.deny');
    this.risk = this.card.querySelector('.risk');
    this.st1 = this.card.querySelector('.st1');
    this.st2 = this.card.querySelector('.st2');
    this.dot = this.card.querySelector('.dot');

    this.toast = el('div', 'app toast big', this.cam, `${ic('check', '', 2.2)}The run is denied.`);

    // The agent sees the answer.
    this.term = terminal(root, { title: 'claude — ~/dev/acme-api', w: 820, h: 190, cls: 'mini' });
    this.tl1 = tline(this.term, [['⏺ ', 'cc'], ['Bash', 'bo'], ['(npm run db:reset)', 'u']]);
    this.tl2 = tline(this.term, [['  ⎿  ', 'd'], ['Denied by the owner. Nothing ran.', 'r']]);

    this.cur = cursor(root);
  },
  render(lt) {
    const t = lt - PRE;
    revealWords(this.h.w, t, -0.2, { out: A.exit, outDur: 0.3 });

    // The notification slides in a little from the right, as on macOS, then becomes the card.
    const nIn = ease.outQuart(prog(t, A.notif, A.notif + 0.7));
    const m = ease.inOutCubic(prog(t, A.morph, A.morph + 0.45));
    const NS = LAY.ns;
    tf(this.notif, {
      x: W / 2 - 190 * NS + 240 * (1 - nIn),
      y: LAY.ny + 50 * m,
      s: NS * lerp(1, 1.12, m),
      o: clamp(nIn * 2.5) * (1 - m),
    });
    this.notif.style.transformOrigin = '0 0';

    const cs = LAY.cs;
    const cw = 600;
    const cardIn = ease.outQuart(prog(t, A.morph + 0.05, A.morph + 0.85));
    const ex = ease.inOutCubic(prog(t, A.exit, A.exit + 0.45));
    const drift = ease.inOutSine(prog(t, A.morph, A.exit));
    const denied = t >= A.click;
    const leave = ease.inOutCubic(prog(t, A.term - 0.1, A.term + 0.5));
    this.card.style.transformOrigin = '50% 0';
    tf(this.card, {
      x: W / 2 - cw / 2 + LAY.leave[0] * leave,
      y: lerp(LAY.cy[0], LAY.cy[1], cardIn) - 20 * drift + LAY.leave[1] * leave - 30 * ex,
      rx: lerp(8, 1.5, cardIn),
      ry: lerp(-4, -1, cardIn) + 1 * drift,
      s: cs * lerp(0.92, 1, cardIn) * (1 + 0.025 * drift) * (1 - 0.1 * leave),
      o: clamp(cardIn * 2.5) * (1 - ex),
    });
    this.card.classList.toggle('denied', denied);
    show(this.st1, !denied);
    show(this.st2, denied);
    this.dot.className = `dot ${denied ? 'bad' : 'warn'}`;
    const rp = hump(t, A.risk, A.risk + 0.8);
    this.risk.style.background = `rgba(255,149,0,${(0.16 * rp).toFixed(3)})`;
    this.risk.style.boxShadow = `0 0 0 ${(4 * rp).toFixed(1)}px rgba(255,149,0,${(0.16 * rp).toFixed(3)})`;
    this.deny.style.background = t >= A.click - 0.08 && t < A.click + 0.14 ? 'var(--fill)' : t >= A.click - 0.35 && t < A.click ? '#f5f5f7' : 'transparent';

    // Toast under the card.
    const tIn = ease.outQuart(prog(t, A.toast, A.toast + 0.5));
    this.toast.style.left = '0px';
    tf(this.toast, { center: true, x: W / 2 + LAY.leave[0] * leave, y: lerp(LAY.toast, LAY.toast - 30, tIn) + LAY.leave[1] * 1.5 * leave - 30 * ex, s: 1.6, o: clamp(tIn * 2) * (1 - ex) });
    this.toast.style.transformOrigin = '50% 50%';

    // The agent terminal.
    const tmIn = ease.outQuart(prog(t, A.term, A.term + 0.75));
    tf(this.term, { y: lerp(44, 0, tmIn) - 30 * ex, o: clamp(tmIn * 1.8) * (1 - ex) });
    this.term.style.left = `${LAY.term[0]}px`;
    this.term.style.top = `${LAY.term[1]}px`;
    typeLine(this.tl1, t, A.term + 0.1, 70);
    typeLine(this.tl2, t, A.term + 0.45, 80);
    show(this.term, t >= A.term - 0.05);

    // The pointer goes to Deny and clicks on the beat.
    const d = rectIn(this.deny);
    const dc = [d.left + d.width * 0.5, d.top + d.height * 0.55];
    moveCursor(this.cur, t, [
      [A.cur, ...LAY.cur],
      [A.click - 0.12, dc[0], dc[1]],
      [A.click + 0.4, dc[0] + 10, dc[1] + 6],
      [A.click + 1.2, dc[0] + 200, dc[1] + 400],
    ], [A.click]);
    this.cur.style.opacity = (clamp((t - A.cur) / 0.15) * (1 - prog(t, A.click + 0.6, A.click + 1.0))).toFixed(3);
  },
});

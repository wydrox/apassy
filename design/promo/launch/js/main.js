import * as E from './engine.js';
import * as FX from './fx.js';

// The film: the launch film by default, or a short (?film=3am). A film module registers its
// scenes and exports NAME, DURATION (its own seconds), PACE, and out(format).
const params = new URLSearchParams(location.search);
const FILMS = { launch: './scenes/index.js', '3am': './shorts/3am.js' };
const film = await import(FILMS[params.get('film')] ?? FILMS.launch);
const { PACE } = film;

const stage = document.getElementById('stage');
const content = document.getElementById('content');
document.documentElement.style.setProperty('--W', `${E.W}px`);
document.documentElement.style.setProperty('--H', `${E.H}px`);
document.documentElement.classList.add(E.FORMAT, `film-${film.NAME}`);
E.setContent(content);
FX.install(stage);
E.mount(content);

// The scenes run in film seconds; the film plays PACE times slower. Everything outside the
// page (render.mjs, audio.mjs, the preview) uses real seconds.
const DURATION = film.DURATION * PACE;
window.PROMO = { film: film.NAME, width: E.W, height: E.H, duration: DURATION, pace: PACE, out: film.out(E.FORMAT) };
window.CUES = E.cues
  .map((c) => ({ ...c, t: Math.round(c.t * PACE * 1000) / 1000, ...(c.dur != null ? { dur: c.dur * PACE } : {}) }))
  .sort((a, b) => a.t - b.t);
window.renderAt = (t) => E.renderAt(Math.max(0, t) / PACE);

const capture = params.has('capture');
let now = Number(params.get('t') || 0);

(async () => {
  await document.fonts.ready;
  window.renderAt(now);
  window.READY = true;
  if (capture) return;

  // Preview: fit the stage to the window, a scrubber, and real-time playback with audio.
  const fit = () => {
    const s = Math.min(innerWidth / E.W, (innerHeight - 44) / E.H);
    stage.style.transform = `scale(${s})`;
    document.body.style.overflow = 'hidden';
  };
  document.documentElement.style.width = document.body.style.width = '100vw';
  document.documentElement.style.height = document.body.style.height = '100vh';
  fit();
  addEventListener('resize', fit);
  const ctl = E.el('div', '', document.body);
  ctl.id = 'ctl';
  const play = E.el('button', '', ctl, 'Play');
  const range = E.el('input', '', ctl);
  range.type = 'range';
  range.min = 0;
  range.max = DURATION;
  range.step = 1 / 60;
  const label = E.el('span', '', ctl);
  const audio = new Audio(film.NAME === 'launch' ? 'out/audio.wav' : `out/audio-${film.NAME}.wav`);
  let playing = false;
  let t0 = 0;
  let n0 = 0;
  const draw = () => {
    window.renderAt(now);
    range.value = now;
    label.textContent = `${now.toFixed(2)} s · bar ${Math.floor(now / (E.bar(1) * PACE)) + 1}`;
  };
  const tick = (ms) => {
    if (!playing) return;
    now = n0 + (ms - t0) / 1000;
    if (now >= DURATION) {
      now = DURATION;
      toggle();
    }
    draw();
    requestAnimationFrame(tick);
  };
  const toggle = () => {
    playing = !playing;
    play.textContent = playing ? 'Pause' : 'Play';
    if (playing) {
      if (now >= DURATION - 0.01) now = 0;
      n0 = now;
      t0 = performance.now();
      audio.currentTime = now;
      audio.play().catch(() => {});
      requestAnimationFrame(tick);
    } else {
      audio.pause();
    }
  };
  play.onclick = toggle;
  range.oninput = () => {
    now = Number(range.value);
    if (playing) toggle();
    draw();
  };
  addEventListener('keydown', (e) => {
    if (e.code === 'Space') {
      e.preventDefault();
      toggle();
    } else if (e.code === 'ArrowRight' || e.code === 'ArrowLeft') {
      const d = (e.shiftKey ? 1 : 1 / 60) * (e.code === 'ArrowRight' ? 1 : -1);
      now = E.clamp(now + d, 0, DURATION);
      draw();
    }
  });
  draw();
})();

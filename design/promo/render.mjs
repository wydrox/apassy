// Render a promo page with WebKit and ffmpeg.
//
//   node render.mjs                        -> index.html to out/apassy-promo-12s.mp4 (1920x1080)
//   node render.mjs --page x.html          -> x.html to its own file (see window.PROMO)
//   node render.mjs --stills 0.9,3.9       -> out/still-<t>.png for a quick look
//   node render.mjs --fps 30 --out a.mp4   -> another frame rate or file name
//
// A page can set window.PROMO = { width, height, duration, out }. The sizes are CSS
// pixels. The output is 1.5 times larger.
import { spawn } from 'node:child_process';
import { mkdirSync } from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { webkit } from 'playwright';

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
};

const FPS = Number(arg('--fps', 60));
const outDir = path.join(here, 'out');
mkdirSync(outDir, { recursive: true });

const browser = await webkit.launch();
const page = await browser.newPage({ viewport: { width: 1280, height: 720 }, deviceScaleFactor: 1.5 });
await page.goto('file://' + path.join(here, arg('--page', 'index.html')) + '?capture=1');
await page.evaluate(() => document.fonts.ready);
const promo = {
  width: 1280,
  height: 720,
  duration: 12,
  out: 'apassy-promo-12s.mp4',
  ...(await page.evaluate(() => window.PROMO || {})),
};
await page.setViewportSize({ width: promo.width, height: promo.height });

const stills = arg('--stills', null);
if (stills) {
  for (const s of stills.split(',')) {
    await page.evaluate((t) => window.renderAt(t), Number(s));
    const file = path.join(outDir, `still-${s}.png`);
    await page.screenshot({ path: file });
    console.log(file);
  }
} else {
  const file = path.join(outDir, arg('--out', promo.out));
  const ff = spawn('ffmpeg', [
    '-y', '-loglevel', 'error',
    '-f', 'image2pipe', '-framerate', String(FPS), '-c:v', 'png', '-i', '-',
    '-c:v', 'libx264', '-preset', 'slow', '-crf', '14', '-tune', 'animation',
    '-pix_fmt', 'yuv420p', '-profile:v', 'high', '-level', '4.2',
    '-movflags', '+faststart', file,
  ], { stdio: ['pipe', 'inherit', 'inherit'] });
  const total = Math.round(FPS * promo.duration);
  for (let i = 0; i < total; i++) {
    await page.evaluate((t) => window.renderAt(t), i / FPS);
    const png = await page.screenshot({ type: 'png' });
    if (!ff.stdin.write(png)) await new Promise((r) => ff.stdin.once('drain', r));
    if (i % FPS === 0) process.stdout.write(`\r${i}/${total}`);
  }
  ff.stdin.end();
  const code = await new Promise((r) => ff.on('close', r));
  console.log(`\n${file} (ffmpeg exit ${code})`);
}
await browser.close();

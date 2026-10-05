// Render the launch video: WebKit draws each frame, ffmpeg encodes.
//
//   node render.mjs                         full video, 1920×1080, 60 fps, motion blur
//   node render.mjs --stills 1.5,9,12.25    JPEG stills in out/stills/ (times in real seconds)
//   node render.mjs --sheet 0,69,1          a contact sheet: from, to, step (s)
//   node render.mjs --from 8 --to 16        a part of the video
//   node render.mjs --fps 30 --mb 1 --scale 0.5 --workers 6   a fast draft
//   node render.mjs --cues                  write out/cues.json only
//   node render.mjs --mux                   put a new out/audio.wav into the rendered video
//   node render.mjs --format tall           the 9:16 version (1080×1920) for Reels, TikTok, Shorts
//   node render.mjs --film 3am --format tall   a short: 9:16, or --format feed for 4:5 (1080×1350)
//
// Frames are drawn by Helium (Chromium). Each film has its own cues and sound track:
// out/cues.json and out/audio.wav for the launch film, out/cues-<film>.json and
// out/audio-<film>.wav for a short.
//
// Motion blur: --mb N renders N sub-frames for each frame over a 180° shutter and mixes
// them. The audio (out/audio.wav, from audio.mjs) is muxed in when it exists.
import { spawn } from 'node:child_process';
import { createReadStream, existsSync, mkdirSync, statSync, writeFileSync } from 'node:fs';
import http from 'node:http';
import os from 'node:os';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { chromium } from 'playwright';

const HELIUM = '/Applications/Helium.app/Contents/MacOS/Helium';
const launchBrowser = () => chromium.launch({ executablePath: HELIUM });

const here = path.dirname(fileURLToPath(import.meta.url));
const argv = process.argv.slice(2);
const arg = (name, fallback) => {
  const i = argv.indexOf(name);
  return i >= 0 ? argv[i + 1] : fallback;
};
const flag = (name) => argv.includes(name);

const FPS = Number(arg('--fps', 60));
const MB = Number(arg('--mb', 4));
const SHUTTER = Number(arg('--shutter', 0.5));
const SCALE = Number(arg('--scale', 1));
const WORKERS = Number(arg('--workers', Math.max(1, Math.min(8, os.cpus().length - 2))));
const FORMAT = arg('--format', 'wide');
const FILM = arg('--film', 'launch');
const [VW, VH] = { wide: [1920, 1080], tall: [1080, 1920], feed: [1080, 1350] }[FORMAT] ?? [1920, 1080];
const outDir = path.join(here, 'out');
const suffix = FILM === 'launch' ? '' : `-${FILM}`;
const cuesFile = path.join(outDir, `cues${suffix}.json`);
const audioFile = path.join(outDir, `audio${suffix}.wav`);
mkdirSync(outDir, { recursive: true });

// A static file server, so the page can load ES modules.
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.svg': 'image/svg+xml', '.wav': 'audio/wav', '.json': 'application/json' };
const server = http.createServer((req, res) => {
  const url = decodeURIComponent(req.url.split('?')[0]);
  if (url === '/favicon.ico') {
    res.writeHead(204);
    res.end();
    return;
  }
  const file = path.join(here, url === '/' ? 'index.html' : url);
  if (!file.startsWith(here) || !existsSync(file) || statSync(file).isDirectory()) {
    res.writeHead(404);
    res.end();
    return;
  }
  res.writeHead(200, { 'Content-Type': types[path.extname(file)] || 'application/octet-stream', 'Cache-Control': 'no-store' });
  createReadStream(file).pipe(res);
});
await new Promise((r) => server.listen(0, '127.0.0.1', r));
const base = `http://127.0.0.1:${server.address().port}/index.html?capture=1&format=${FORMAT}&film=${FILM}`;

async function openPage(browser) {
  const page = await browser.newPage({ viewport: { width: VW, height: VH }, deviceScaleFactor: SCALE });
  page.on('pageerror', (e) => console.error('page error:', e.message));
  page.on('crash', () => console.error('\npage crashed'));
  page.on('console', (m) => {
    if (m.type() === 'error') console.error('console:', m.text());
  });
  await page.goto(base);
  await page.waitForFunction(() => window.READY === true, null, { timeout: 60000 });
  return page;
}

const browser0 = await launchBrowser();
const page0 = await openPage(browser0);
const promo = await page0.evaluate(() => window.PROMO);
const cues = await page0.evaluate(() => window.CUES);
writeFileSync(cuesFile, JSON.stringify({ film: promo.film, duration: promo.duration, pace: promo.pace, cues }, null, 1));
console.log(`cues: ${cues.length} → ${path.relative(here, cuesFile)}`);

async function shot(page, t, type = 'png') {
  await page.evaluate((t) => window.renderAt(t), t);
  return type === 'jpeg'
    ? page.screenshot({ type: 'jpeg', quality: 90, animations: 'allow', caret: 'initial' })
    : page.screenshot({ type: 'png', animations: 'allow', caret: 'initial' });
}

if (flag('--cues')) {
  // Done: cues only.
} else if (flag('--mux')) {
  // Replace the sound track of the rendered video with out/audio.wav (no new frames).
  const out = path.join(outDir, arg('--out', promo.out));
  const tmp = out.replace(/\.mp4$/, '.remux.mp4');
  await run('ffmpeg', ['-y', '-loglevel', 'error', '-i', out, '-i', audioFile, '-map', '0:v', '-map', '1:a',
    '-c:v', 'copy', '-c:a', 'aac', '-b:a', '320k', '-ar', '48000', '-movflags', '+faststart', '-shortest', tmp]);
  const { renameSync } = await import('node:fs');
  renameSync(tmp, out);
  console.log(out);
} else if (arg('--stills') || arg('--sheet')) {
  const dir = path.join(outDir, 'stills');
  mkdirSync(dir, { recursive: true });
  let times;
  if (arg('--stills')) times = arg('--stills').split(',').map(Number);
  else {
    const [a, b, s] = arg('--sheet').split(',').map(Number);
    times = [];
    for (let t = a; t <= b + 1e-9; t += s) times.push(Math.round(t * 1000) / 1000);
  }
  const files = [];
  for (const t of times) {
    const file = path.join(dir, `t${t.toFixed(3).padStart(7, '0')}.jpg`);
    writeFileSync(file, await shot(page0, t, 'jpeg'));
    files.push(file);
  }
  console.log(files.join('\n'));
  if (arg('--sheet')) {
    // Tile the stills with their times.
    const cols = Number(arg('--cols', 5));
    const sheet = path.join(outDir, arg('--out', 'sheet.jpg'));
    await run('python3', [path.join(here, 'sheet.py'), sheet, String(cols), ...files]);
    console.log(sheet);
  }
} else {
  // Workers render frames in parallel; one ffmpeg process gets them in order and writes the
  // final file once (with the audio). No segment files, so the disk footprint stays small.
  const from = Number(arg('--from', 0));
  const to = Number(arg('--to', promo.duration));
  const total = Math.round((to - from) * FPS);
  const n = Math.min(WORKERS, total);
  const width = Math.round(VW * SCALE);
  const height = Math.round(VH * SCALE);
  const name = arg('--out', from === 0 && to === promo.duration ? promo.out : `part-${from}-${to}.mp4`);
  const out = path.join(outDir, name);
  const audio = audioFile;
  const useAudio = existsSync(audio) && !flag('--silent');
  console.log(`${total} frames, ${FPS} fps, motion blur ${MB}, ${width}×${height}, ${n} workers → ${name}`);

  const vf = [
    ...(MB > 1 ? [`tmix=frames=${MB}`, `select='not(mod(n+1\,${MB}))'`, `setpts=N/(${FPS}*TB)`] : []),
    'scale=out_color_matrix=bt709:out_range=tv:flags=spline+accurate_rnd+full_chroma_int',
    'format=yuv420p',
  ].join(',');
  const ffArgs = ['-y', '-loglevel', 'error', '-f', 'image2pipe', '-framerate', String(FPS * MB), '-c:v', 'png', '-i', '-'];
  if (useAudio) ffArgs.push('-ss', String(from), '-t', String(to - from), '-i', audio);
  ffArgs.push('-vf', vf, '-r', String(FPS), '-map', '0:v');
  if (useAudio) ffArgs.push('-map', '1:a', '-c:a', 'aac', '-b:a', '320k', '-ar', '48000');
  ffArgs.push('-c:v', 'libx264', '-preset', arg('--preset', 'medium'), '-crf', String(arg('--crf', 18)),
    '-profile:v', 'high', '-level', '4.2', '-x264-params', 'aq-mode=3:aq-strength=0.9:deblock=-1,-1',
    '-color_primaries', 'bt709', '-color_trc', 'bt709', '-colorspace', 'bt709',
    '-movflags', '+faststart', '-shortest', out);
  const ff = spawn('ffmpeg', ffArgs, { stdio: ['pipe', 'inherit', 'inherit'] });
  const ffDone = new Promise((r) => ff.on('close', r));

  const started = Date.now();
  let next = 0; // the next frame for ffmpeg
  const ready = new Map();
  const AHEAD = 4 * n; // frames that may wait in memory
  const tick = () => new Promise((r) => setTimeout(r, 4));
  const progress = setInterval(() => {
    const el = (Date.now() - started) / 1000;
    const rate = next / el;
    process.stdout.write(`\r${next}/${total} frames · ${rate.toFixed(1)} fps · eta ${rate ? ((total - next) / rate).toFixed(0) : '?'} s   `);
  }, 2000);

  const work = async (w) => {
    let browser = w === 0 ? browser0 : await launchBrowser();
    let page = w === 0 ? page0 : await openPage(browser);
    for (let i = w; i < total; i += n) {
      while (i >= next + AHEAD) await tick();
      const t = from + i / FPS;
      // A browser that dies is started again; the frame is drawn again from its time.
      for (let attempt = 0; ; attempt++) {
        try {
          const shots = [];
          for (let k = 0; k < MB; k++) {
            const dt = MB > 1 ? ((k + 0.5) / MB - 0.5) * (SHUTTER / FPS) : 0;
            shots.push(await shot(page, t + dt));
          }
          ready.set(i, shots);
          break;
        } catch (e) {
          if (attempt >= 3) throw e;
          console.error(`\nworker ${w}, frame ${i}: ${e.message.split('\n')[0]}; starting its browser again`);
          await browser.close().catch(() => {});
          browser = await launchBrowser();
          page = await openPage(browser);
        }
      }
    }
    await browser.close().catch(() => {});
  };
  const write = async () => {
    while (next < total) {
      const shots = ready.get(next);
      if (!shots) {
        await tick();
        continue;
      }
      ready.delete(next);
      for (const png of shots) if (!ff.stdin.write(png)) await new Promise((r) => ff.stdin.once('drain', r));
      next++;
    }
    ff.stdin.end();
  };
  await Promise.all([write(), ...Array.from({ length: n }, (_, w) => work(w))]);
  const code = await ffDone;
  clearInterval(progress);
  console.log(`\n${out} (ffmpeg exit ${code}) in ${((Date.now() - started) / 1000).toFixed(0)} s`);
  if (code !== 0) process.exitCode = 1;
}

await browser0.close().catch(() => {});
server.close();

function run(cmd, args) {
  return new Promise((resolve, reject) => {
    const p = spawn(cmd, args, { stdio: ['ignore', 'inherit', 'inherit'] });
    p.on('close', (c) => (c === 0 ? resolve() : reject(new Error(`${cmd} exit ${c}`))));
  });
}

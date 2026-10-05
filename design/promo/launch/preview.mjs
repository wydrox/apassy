// Serve the launch video page for a live preview in a browser.
//
//   node preview.mjs          → http://127.0.0.1:8777/  (Space: play, ← →: step, add ?t=12)
import { createReadStream, existsSync, statSync } from 'node:fs';
import http from 'node:http';
import path from 'node:path';
import { fileURLToPath } from 'node:url';

const here = path.dirname(fileURLToPath(import.meta.url));
const port = Number(process.argv[2] || 8777);
const types = { '.html': 'text/html', '.js': 'text/javascript', '.mjs': 'text/javascript', '.css': 'text/css', '.png': 'image/png', '.wav': 'audio/wav', '.json': 'application/json' };

http
  .createServer((req, res) => {
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
  })
  .listen(port, '127.0.0.1', () => console.log(`http://127.0.0.1:${port}/`));

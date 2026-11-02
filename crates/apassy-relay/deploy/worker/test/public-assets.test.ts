import { test, type TestContext } from 'node:test';
import assert from 'node:assert/strict';
import { createHash } from 'node:crypto';
import { execFile } from 'node:child_process';
import { mkdtempSync, mkdirSync, readFileSync, readdirSync, rmSync, writeFileSync } from 'node:fs';
import { createServer } from 'node:http';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { promisify } from 'node:util';

const execute = promisify(execFile);
const script = fileURLToPath(new URL('../scripts/check-public-assets.py', import.meta.url));
const commit = 'a'.repeat(40);

async function fixture(t: TestContext, mode: string) {
  const dir = mkdtempSync(join(tmpdir(), 'relay-public-assets-'));
  t.after(() => rmSync(dir, { recursive: true, force: true }));
  const publicDir = join(dir, 'public');
  mkdirSync(join(publicDir, 'dl'), { recursive: true });
  const files = new Map<string, Buffer>();
  const artifacts: Record<string, { filename: string; sha256: string; size: number }> = {};
  const sums = [];
  for (const platform of ['linux-x86_64', 'darwin-arm64']) {
    const filename = `apassy-team-${platform}`;
    const blob = Buffer.from(platform);
    const sha256 = createHash('sha256').update(blob).digest('hex');
    files.set('/dl/' + filename, blob);
    artifacts[platform] = { filename, sha256, size: blob.length };
    sums.push(`${sha256}  ${filename}`);
  }
  files.set('/dl/SHA256SUMS', Buffer.from(sums.join('\n') + '\n'));
  files.set('/dl/release.json', Buffer.from(JSON.stringify({ version: '0.5.8', commit, artifacts })));
  files.set('/install.sh', Buffer.from('installer'));
  files.set('/guide', Buffer.from('guide'));
  for (const [path, blob] of files) {
    writeFileSync(join(publicDir, path === '/guide' ? 'guide.html' : path.slice(1)), blob);
  }
  const requests: { path: string; ua: string; method: string }[] = [];
  let firstRequests = 0;
  const server = createServer((req, res) => {
    const path = req.url!;
    const ua = req.headers['user-agent'] ?? '';
    requests.push({ path, ua, method: req.method! });
    res.setHeader('cf-ray', 'fixture-ray');
    if (ua.startsWith('Python-urllib/')) {
      res.writeHead(403, { 'content-type': 'text/plain' });
      res.end('error code: 1010\n');
      return;
    }
    if (path === '/dl/apassy-team-linux-x86_64') {
      firstRequests++;
      if (mode === 'challenge' || mode === 'transient' && firstRequests === 1) {
        res.writeHead(403, { 'cf-mitigated': 'challenge', 'content-type': 'text/html' });
        res.end('<html>challenge</html>');
        return;
      }
      if (mode === 'rate-limit' && firstRequests === 1) {
        res.writeHead(429, { 'retry-after': '1' });
        res.end('rate limited');
        return;
      }
      if (mode === 'wrong-bytes' || mode === 'stale' && firstRequests === 1) {
        res.end('old release');
        return;
      }
      if (mode === 'redirect') {
        res.writeHead(302, { location: '/install.sh' });
        res.end();
        return;
      }
    }
    if (!files.has(path)) { res.writeHead(404); res.end(); return; }
    res.end(files.get(path));
  });
  await new Promise<void>(resolve => server.listen(0, '127.0.0.1', resolve));
  t.after(() => new Promise<void>((resolve, reject) => server.close(error => error ? reject(error) : resolve())));
  const address = server.address();
  assert.ok(address && typeof address !== 'string');
  const base = `http://127.0.0.1:${address.port}`;
  const evidence = join(dir, 'evidence');
  const args = [script, '--base-url', base, '--public-dir', publicDir, '--version', '0.5.8',
    '--commit', commit, '--evidence-dir', evidence, '--attempts', '3', '--backoff', '0'];
  return { base, evidence, requests, run: () => execute('python3', args) };
}

test('reproduces urllib 403/1010 and verifies every file with an application user agent', async t => {
  const f = await fixture(t, 'normal');
  const legacy = await execute('python3', ['-c', `import urllib.request,urllib.error\ntry:\n urllib.request.urlopen('${f.base}/dl/apassy-team-linux-x86_64')\nexcept urllib.error.HTTPError as e:\n print(e.code,e.read().decode())`]);
  assert.match(legacy.stdout, /403 error code: 1010/);
  const result = await f.run();
  assert.match(result.stdout, /PASS public delivery: 0.5.8/);
  assert.equal(f.requests.length, 7);
  assert.ok(f.requests.slice(1).every(r => r.ua === 'apassy-release-check/0.5.8' && r.method === 'GET'));
  assert.equal(readdirSync(f.evidence).length, 6);
});

for (const mode of ['transient', 'stale', 'rate-limit']) {
  test(`retries ${mode} responses and retains failed headers and body`, async t => {
    const f = await fixture(t, mode);
    const result = await f.run();
    assert.match(result.stdout, /Retry in 0/);
    assert.match(result.stdout, /PASS public delivery/);
    assert.equal(f.requests.filter(r => r.path === '/dl/apassy-team-linux-x86_64').length, 2);
    const failed = JSON.parse(readFileSync(join(f.evidence, '1-1.json'), 'utf8'));
    assert.equal(failed.accepted, false);
    assert.equal(failed.headers['cf-ray'], 'fixture-ray');
    if (mode === 'transient') assert.equal(failed.cf_mitigated, 'challenge');
    if (mode === 'rate-limit') assert.equal(failed.headers['retry-after'], '1');
    assert.ok(readFileSync(join(f.evidence, '1-1.body')).length > 0);
  });
}

for (const mode of ['challenge', 'wrong-bytes', 'redirect']) {
  test(`fails closed on persistent ${mode}`, async t => {
    const f = await fixture(t, mode);
    await assert.rejects(f.run(), /Public delivery failed/);
    assert.equal(f.requests.length, mode === 'redirect' ? 1 : 3);
    const last = JSON.parse(readFileSync(join(f.evidence, mode === 'redirect' ? '1-1.json' : '1-3.json'), 'utf8'));
    assert.equal(last.accepted, false);
  });
}

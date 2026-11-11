// The deploy preflight of RELAY_MODE (scripts/check-relay-mode.mjs): a deploy whose
// wrangler.jsonc mode is not the relay's is refused. No network: the relay is a fake fetch.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { execFile } from 'node:child_process';
import { readFileSync } from 'node:fs';
import { createServer, type Server } from 'node:http';
import type { AddressInfo } from 'node:net';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import {
  checkRelayMode,
  configuredMode,
  healthUrl,
  liveMode,
  main,
  parseJsonc,
  RelayUnreachable,
  reportedMode,
} from '../scripts/check-relay-mode.mjs';

const worker = join(dirname(fileURLToPath(import.meta.url)), '..');

test('reads the mode and the health URL from the wrangler.jsonc of the repository', () => {
  const config = parseJsonc(readFileSync(join(worker, 'wrangler.jsonc'), 'utf8'));
  assert.ok(['relay', 'connect'].includes(configuredMode(config)));
  assert.equal(healthUrl(config), 'https://apassy-relay.wyderka.cc/healthz');
  assert.equal(healthUrl(config, { APASSY_EDGE_HEALTH_URL: 'https://relay.example.test/healthz' }), 'https://relay.example.test/healthz');
  // The build hook and the preflight both run the check.
  assert.match(config.build.command, /check-relay-mode\.mjs/);
  const pkg = JSON.parse(readFileSync(join(worker, 'package.json'), 'utf8'));
  assert.match(pkg.scripts.preflight, /check-relay-mode\.mjs/);
});

test('parses comments and trailing commas outside strings and keeps them inside', () => {
  const config = parseJsonc(`{
    // a comment with "quotes"
    "vars": { "RELAY_MODE": "connect", "URL": "https://x.example/a//b", /* block */ "S": "a,}b\\"c", },
    "routes": [{ "pattern": "relay.example.test", "custom_domain": true },],
  }`);
  assert.equal(config.vars.URL, 'https://x.example/a//b');
  assert.equal(config.vars.S, 'a,}b"c');
  assert.equal(configuredMode(config), 'connect');
  assert.equal(healthUrl(config), 'https://relay.example.test/healthz');
});

test('the configured mode: unset or empty is relay, a bad value is refused', () => {
  assert.equal(configuredMode({}), 'relay');
  assert.equal(configuredMode({ vars: { RELAY_MODE: '' } }), 'relay');
  assert.equal(configuredMode({ vars: { RELAY_MODE: ' relay ' } }), 'relay');
  assert.equal(configuredMode({ vars: { RELAY_MODE: 'connect' } }), 'connect');
  assert.throws(() => configuredMode({ vars: { RELAY_MODE: 'conect' } }), /only "relay" and "connect"/);
  assert.throws(() => healthUrl({ routes: [{ pattern: 'apassy-relay.example.test/*' }] }), /APASSY_EDGE_HEALTH_URL/);
  assert.throws(() => healthUrl({}), /APASSY_EDGE_HEALTH_URL/);
});

test('the reported mode: the header, none for a relay before it, and no answer is no mode', () => {
  assert.equal(reportedMode(200, 'connect'), 'connect');
  assert.equal(reportedMode(200, 'relay'), 'relay');
  // A relay before the header (0.5.19 and older): no mode, which only a relay deploy accepts.
  assert.equal(reportedMode(200, null), null);
  assert.throws(() => reportedMode(502, null), /502/);
  assert.throws(() => reportedMode(503, 'connect'), /503/);
  assert.throws(() => reportedMode(200, 'hosted'), /unknown mode/);
});

test('a deploy whose mode is not the relay\'s is refused, in both directions', () => {
  checkRelayMode('relay', 'relay');
  checkRelayMode('connect', 'connect');
  assert.throws(() => checkRelayMode('relay', 'connect'), /turn \/internal\/push and the free Connect guards back on/);
  assert.throws(() => checkRelayMode('connect', 'relay'), /turn \/internal\/push off/);
  // No header: a relay before it, in relay mode. A relay deploy passes; a connect one does not.
  checkRelayMode('relay', null);
  assert.throws(() => checkRelayMode('connect', null), /without x-apassy-relay-mode/);
});

test('reads the mode with one GET of /healthz, never HEAD', async () => {
  const asked: { url: string; method?: string }[] = [];
  const fake = (header: string | null, status = 200) => async (url: string, init?: RequestInit) => {
    asked.push({ url, method: init?.method });
    return { status, headers: { get: (name: string) => (name === 'x-apassy-relay-mode' ? header : null) } };
  };
  assert.equal(await liveMode('https://relay.example.test/healthz', fake('connect')), 'connect');
  assert.equal(await liveMode('https://relay.example.test/healthz', fake(null)), null);
  await assert.rejects(liveMode('https://relay.example.test/healthz', fake(null, 404)), /404/);
  // A gateway error without the header is an edge that did not reach the relay.
  await assert.rejects(liveMode('https://relay.example.test/healthz', fake(null, 502)), RelayUnreachable);
  // A relay that answers an error with its header is reached: no mode, not unreachable.
  await assert.rejects(liveMode('https://relay.example.test/healthz', fake('relay', 502)), (error: Error) =>
    !(error instanceof RelayUnreachable) && /502/.test(error.message));
  assert.deepEqual(asked.map((call) => call.method), ['GET', 'GET', 'GET', 'GET', 'GET']);
});

/** The lines of one run of `main`, by kind. */
function recorder() {
  const lines: { kind: string; line: string }[] = [];
  const out = {
    log: (line: string) => lines.push({ kind: 'log', line }),
    warn: (line: string) => lines.push({ kind: 'warn', line }),
    error: (line: string) => lines.push({ kind: 'error', line }),
  };
  return { lines, out, text: () => lines.map((entry) => entry.line).join('\n') };
}

const answering = (header: string | null, status = 200) => async () => ({
  status,
  headers: { get: (name: string) => (name === 'x-apassy-relay-mode' ? header : null) },
});
const failing = (name: string) => async () => {
  const error = new Error(name === 'TimeoutError' ? 'The operation timed out.' : 'fetch failed');
  error.name = name;
  throw error;
};
const configOf = (mode: string) => ({ vars: { RELAY_MODE: mode }, routes: [{ pattern: 'relay.example.test', custom_domain: true }] });

test('main: the skip passes only a relay that cannot be reached; a relay that answers is checked', async () => {
  const skip = { APASSY_EDGE_MODE_CHECK: 'skip' };
  for (const fetchImpl of [failing('TypeError'), failing('TimeoutError'), answering(null, 502), answering(null, 522)]) {
    // Not reached, no skip: refused, with the way to skip.
    let run = recorder();
    assert.equal(await main({ config: configOf('connect'), fetchImpl, out: run.out }), 1);
    assert.match(run.text(), /cannot be reached|not reached/);
    assert.match(run.text(), /APASSY_EDGE_MODE_CHECK=skip/);
    // Not reached, skip: passes, and says so on the console.
    run = recorder();
    assert.equal(await main({ config: configOf('connect'), env: skip, fetchImpl, out: run.out }), 0);
    assert.equal(run.lines[0]!.kind, 'warn');
    assert.match(run.text(), /SKIPPED/);
  }
  // The relay answers: the skip is ignored and the check refuses a mode that differs.
  for (const [mode, fetchImpl] of [
    ['relay', answering('connect')],
    ['connect', answering('relay')],
    ['connect', answering(null)],
  ] as const) {
    const run = recorder();
    assert.equal(await main({ config: configOf(mode), env: skip, fetchImpl, out: run.out }), 1, `${mode}`);
    assert.match(run.text(), /is ignored: the relay answers/);
    assert.match(run.text(), /preflight failed/);
  }
  // The relay answers with an error of its own (its header is there): checked, refused.
  let run = recorder();
  assert.equal(await main({ config: configOf('relay'), env: skip, fetchImpl: answering('relay', 503), out: run.out }), 1);
  assert.match(run.text(), /answered 503/);
  run = recorder();
  assert.equal(await main({ config: configOf('relay'), env: skip, fetchImpl: answering(null, 404), out: run.out }), 1);
  // The same modes pass, with or without the skip.
  for (const env of [{}, skip]) {
    for (const [mode, header] of [['relay', 'relay'], ['connect', 'connect'], ['relay', null]] as const) {
      run = recorder();
      assert.equal(await main({ config: configOf(mode), env, fetchImpl: answering(header), out: run.out }), 0, `${mode} ${header}`);
    }
  }
  // An unknown value of the switch is refused before any request.
  run = recorder();
  assert.equal(await main({ config: configOf('relay'), env: { APASSY_EDGE_MODE_CHECK: 'skipp' }, fetchImpl: answering('relay'), out: run.out }), 1);
  assert.match(run.text(), /only "skip"/);
});

/** A local HTTP server that answers `/healthz` with `status` and the mode header `mode`. */
async function healthServer(status: number, mode: string | null): Promise<{ server: Server; url: string }> {
  const server = createServer((request, response) => {
    const headers: Record<string, string> = mode === null ? {} : { 'x-apassy-relay-mode': mode };
    response.writeHead(request.method === 'GET' && request.url === '/healthz' ? status : 404, headers);
    response.end('ok');
  });
  await new Promise<void>((done) => server.listen(0, '127.0.0.1', done));
  return { server, url: `http://127.0.0.1:${(server.address() as AddressInfo).port}/healthz` };
}

/** One run of the script itself, as the build hook runs it: its exit code and its output. */
function runScript(env: Record<string, string>): Promise<{ code: number; output: string }> {
  return new Promise((done) => {
    execFile(
      process.execPath,
      [join(worker, 'scripts', 'check-relay-mode.mjs')],
      { cwd: worker, env: { PATH: process.env.PATH ?? '', ...env }, timeout: 30_000 },
      (error, stdout, stderr) => done({ code: error ? Number(error.code ?? 1) : 0, output: `${stdout}${stderr}` }),
    );
  });
}

test('the script itself: exit 0 only for the relay\'s mode, and the skip only for a relay that cannot be reached', async () => {
  const configured = configuredMode(parseJsonc(readFileSync(join(worker, 'wrangler.jsonc'), 'utf8')));
  const other = configured === 'relay' ? 'connect' : 'relay';
  const same = await healthServer(200, configured);
  const differs = await healthServer(200, other);
  const gone = await healthServer(200, configured);
  const goneUrl = gone.url;
  await new Promise<void>((done) => gone.server.close(() => done()));
  try {
    let run = await runScript({ APASSY_EDGE_HEALTH_URL: same.url });
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, /is the mode that the relay reports/);
    run = await runScript({ APASSY_EDGE_HEALTH_URL: differs.url });
    assert.equal(run.code, 1, run.output);
    // The relay answers: the skip does not pass a mode that differs.
    run = await runScript({ APASSY_EDGE_HEALTH_URL: differs.url, APASSY_EDGE_MODE_CHECK: 'skip' });
    assert.equal(run.code, 1, run.output);
    assert.match(run.output, /is ignored: the relay answers/);
    // Nothing listens: refused without the skip, passed with it.
    run = await runScript({ APASSY_EDGE_HEALTH_URL: goneUrl });
    assert.equal(run.code, 1, run.output);
    assert.match(run.output, /cannot be reached/);
    run = await runScript({ APASSY_EDGE_HEALTH_URL: goneUrl, APASSY_EDGE_MODE_CHECK: 'skip' });
    assert.equal(run.code, 0, run.output);
    assert.match(run.output, /SKIPPED/);
  } finally {
    await new Promise<void>((done) => same.server.close(() => done()));
    await new Promise<void>((done) => differs.server.close(() => done()));
  }
});

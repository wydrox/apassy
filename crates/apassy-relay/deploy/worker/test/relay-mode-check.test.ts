// The deploy preflight of RELAY_MODE (scripts/check-relay-mode.mjs): a deploy whose
// wrangler.jsonc mode is not the relay's is refused. No network: the relay is a fake fetch.
import { test } from 'node:test';
import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { dirname, join } from 'node:path';
import { fileURLToPath } from 'node:url';
import { checkRelayMode, configuredMode, healthUrl, liveMode, parseJsonc, reportedMode } from '../scripts/check-relay-mode.mjs';

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

test('the reported mode: the header, relay without it, and no answer is no mode', () => {
  assert.equal(reportedMode(200, 'connect'), 'connect');
  assert.equal(reportedMode(200, 'relay'), 'relay');
  // A relay before the header (0.5.19 and older) is in relay mode.
  assert.equal(reportedMode(200, null), 'relay');
  assert.throws(() => reportedMode(502, null), /502/);
  assert.throws(() => reportedMode(503, 'connect'), /503/);
  assert.throws(() => reportedMode(200, 'hosted'), /unknown mode/);
});

test('a deploy whose mode is not the relay\'s is refused, in both directions', () => {
  checkRelayMode('relay', 'relay');
  checkRelayMode('connect', 'connect');
  assert.throws(() => checkRelayMode('relay', 'connect'), /turn \/internal\/push and the free Connect guards back on/);
  assert.throws(() => checkRelayMode('connect', 'relay'), /turn \/internal\/push off/);
});

test('reads the mode with one GET of /healthz, never HEAD', async () => {
  const asked: { url: string; method?: string }[] = [];
  const fake = (header: string | null, status = 200) => async (url: string, init?: RequestInit) => {
    asked.push({ url, method: init?.method });
    return { status, headers: { get: (name: string) => (name === 'x-apassy-relay-mode' ? header : null) } };
  };
  assert.equal(await liveMode('https://relay.example.test/healthz', fake('connect')), 'connect');
  assert.equal(await liveMode('https://relay.example.test/healthz', fake(null)), 'relay');
  await assert.rejects(liveMode('https://relay.example.test/healthz', fake(null, 404)), /404/);
  assert.deepEqual(asked.map((call) => call.method), ['GET', 'GET', 'GET']);
});

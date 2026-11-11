// The deploy preflight of the Worker's mode (docs/operations/connect.md, section 9.3): a
// deploy refuses a RELAY_MODE in wrangler.jsonc that is not the mode of the relay behind
// the Worker, as the relay's `GET /healthz` reports it in `x-apassy-relay-mode`. So a deploy
// from a checkout that still says "relay" cannot turn `/internal/push` and the free Connect
// guards back on in front of Apassy Connect, and a "connect" Worker cannot go in front of
// the hosted relay. A relay before that header (0.5.19 and older) is in relay mode. The
// Wrangler build hook runs this check on every `wrangler deploy`, as `npm run preflight`.
// `APASSY_EDGE_HEALTH_URL` names another health URL (a self-run Worker); only a relay that
// cannot answer (stopped) needs `APASSY_EDGE_MODE_CHECK=skip`, which says so on the console.
import { readFileSync } from 'node:fs';
import { dirname, join, resolve } from 'node:path';
import { fileURLToPath } from 'node:url';

/** JSON with comments (`//`, `/* *\/`) and trailing commas, as Wrangler reads it. Text in strings is kept. */
export function parseJsonc(text) {
  let bare = '';
  for (let i = 0; i < text.length; i++) {
    const c = text[i];
    if (c === '"') {
      let end = i + 1;
      while (end < text.length && text[end] !== '"') end += text[end] === '\\' ? 2 : 1;
      bare += text.slice(i, end + 1);
      i = end;
    } else if (c === '/' && text[i + 1] === '/') {
      while (i < text.length && text[i] !== '\n') i++;
      bare += '\n';
    } else if (c === '/' && text[i + 1] === '*') {
      const end = text.indexOf('*/', i + 2);
      if (end < 0) throw new Error('An unclosed comment in wrangler.jsonc.');
      i = end + 1;
    } else {
      bare += c;
    }
  }
  let json = '';
  for (let i = 0; i < bare.length; i++) {
    const c = bare[i];
    if (c === '"') {
      let end = i + 1;
      while (end < bare.length && bare[end] !== '"') end += bare[end] === '\\' ? 2 : 1;
      json += bare.slice(i, end + 1);
      i = end;
    } else if (c === ',' && /^\s*[}\]]/.test(bare.slice(i + 1))) {
      // A trailing comma: dropped.
    } else {
      json += c;
    }
  }
  return JSON.parse(json);
}

/** The mode that the configuration sets: `relay` when RELAY_MODE is unset or empty. */
export function configuredMode(config) {
  const value = config?.vars?.RELAY_MODE;
  const mode = value === undefined ? '' : String(value).trim();
  if (mode === '' || mode === 'relay') return 'relay';
  if (mode === 'connect') return 'connect';
  throw new Error(`wrangler.jsonc sets RELAY_MODE ${JSON.stringify(value)}: only "relay" and "connect" are known.`);
}

/** The relay's health URL: APASSY_EDGE_HEALTH_URL, else the first route of the configuration. */
export function healthUrl(config, env = {}) {
  if (env.APASSY_EDGE_HEALTH_URL) return env.APASSY_EDGE_HEALTH_URL;
  const route = config?.routes?.[0];
  const pattern = typeof route === 'string' ? route : route?.pattern;
  if (typeof pattern !== 'string' || pattern === '' || /[*/]/.test(pattern)) {
    throw new Error('wrangler.jsonc has no plain route to read the relay\'s mode from: set APASSY_EDGE_HEALTH_URL.');
  }
  return `https://${pattern}/healthz`;
}

/** The mode that the relay reports on `GET /healthz`. */
export function reportedMode(status, header) {
  if (status !== 200) throw new Error(`The relay's health check answered ${status}, so its mode is unknown.`);
  if (header === null || header === undefined) return 'relay';
  const mode = header.trim();
  if (mode === 'relay' || mode === 'connect') return mode;
  throw new Error(`The relay reports an unknown mode (x-apassy-relay-mode: ${JSON.stringify(header)}).`);
}

/** Refuses a deploy whose mode is not the relay's. */
export function checkRelayMode(configured, reported) {
  if (configured === reported) return;
  const effect = configured === 'relay'
    ? 'turn /internal/push and the free Connect guards back on in front of Apassy Connect'
    : 'turn /internal/push off in front of the hosted relay';
  throw new Error(
    `wrangler.jsonc sets RELAY_MODE "${configured}", but the relay reports x-apassy-relay-mode: ${reported}. ` +
      `This deploy would ${effect}. Set RELAY_MODE to "${reported}" in wrangler.jsonc ` +
      '(docs/operations/connect.md, section 9.3), or deploy after the relay has changed its mode.',
  );
}

/** The mode of the relay at `url`, read with one GET (`/healthz` answers no HEAD). */
export async function liveMode(url, fetchImpl = fetch) {
  const response = await fetchImpl(url, {
    method: 'GET',
    redirect: 'manual',
    headers: { 'cache-control': 'no-cache' },
    signal: AbortSignal.timeout(15_000),
  });
  return reportedMode(response.status, response.headers.get('x-apassy-relay-mode'));
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  try {
    const worker = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    const config = parseJsonc(readFileSync(join(worker, 'wrangler.jsonc'), 'utf8'));
    const configured = configuredMode(config);
    if (process.env.APASSY_EDGE_MODE_CHECK === 'skip') {
      console.warn(`The relay mode check is SKIPPED (APASSY_EDGE_MODE_CHECK=skip): this deploy sets RELAY_MODE "${configured}" without reading the relay's mode.`);
    } else {
      const url = healthUrl(config, process.env);
      checkRelayMode(configured, await liveMode(url));
      console.log(`RELAY_MODE "${configured}" is the mode that the relay reports (${url}).`);
    }
  } catch (error) {
    console.error(`Worker relay mode preflight failed: ${error.message}`);
    process.exitCode = 1;
  }
}

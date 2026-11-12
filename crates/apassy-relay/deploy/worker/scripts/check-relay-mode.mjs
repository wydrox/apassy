// The deploy preflight of the Worker's mode (docs/operations/connect.md, section 9.3): a
// deploy refuses a RELAY_MODE in wrangler.jsonc that is not the mode of the relay behind
// the Worker, as the relay's `GET /healthz` reports it in `x-apassy-relay-mode`. So a deploy
// from a checkout that still says "relay" cannot turn `/internal/push` and the free Connect
// guards back on in front of Apassy Connect, and a "connect" Worker cannot go in front of
// the hosted relay. A relay that answers 200 without that header is a relay before it
// (0.5.19 and older), in relay mode: that passes a "relay" deploy and refuses a "connect"
// one. The Wrangler build hook runs this check on every `wrangler deploy`, as `npm run
// preflight`. `APASSY_EDGE_HEALTH_URL` names another health URL (a self-run Worker).
// `APASSY_EDGE_MODE_CHECK=skip` is honoured only when the relay cannot be reached (the
// request fails or times out, or the edge answers a gateway error such as the Worker's own
// 502 "relay unreachable", without a mode header); a relay that answers is always checked.
// What this cannot see: a change of RELAY_MODE in the Cloudflare dashboard, and a rollback
// to an older version of the Worker (dashboard or `wrangler rollback`): neither runs a build.
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

/** The answers of an edge that did not reach the relay: the Worker's 502 "relay unreachable", a gateway timeout, and Cloudflare's origin errors. */
const GATEWAY_ERRORS = new Set([502, 504, 520, 521, 522, 523, 524, 525, 526, 527, 530]);

/**
 * The mode that the relay reports on `GET /healthz`: `relay`, `connect`, or `null` when a
 * relay answers 200 without the header (a relay before it, 0.5.19 and older).
 */
export function reportedMode(status, header) {
  if (status !== 200) throw new Error(`The relay's health check answered ${status}, so its mode is unknown.`);
  if (header === null || header === undefined) return null;
  const mode = header.trim();
  if (mode === 'relay' || mode === 'connect') return mode;
  throw new Error(`The relay reports an unknown mode (x-apassy-relay-mode: ${JSON.stringify(header)}).`);
}

/** Refuses a deploy whose mode is not the relay's. `reported` null: a relay before the header, in relay mode. */
export function checkRelayMode(configured, reported) {
  if (reported === null) {
    if (configured === 'relay') return;
    throw new Error(
      'wrangler.jsonc sets RELAY_MODE "connect", but the relay answers /healthz without x-apassy-relay-mode: ' +
        'a relay before that header (0.5.19 and older) is in relay mode, so this deploy would turn /internal/push off ' +
        'in front of the hosted relay. Deploy "connect" only in front of a relay that reports x-apassy-relay-mode: connect ' +
        '(docs/operations/connect.md, section 9.3).',
    );
  }
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

/** The relay could not be reached: the request failed or timed out, or the edge answered a gateway error for it. */
export class RelayUnreachable extends Error {}

/**
 * The relay's answer to one GET of `url` (`/healthz` answers no HEAD): its status and mode
 * header. Throws `RelayUnreachable` when it cannot be reached.
 */
export async function probe(url, fetchImpl = fetch, timeoutMs = 15_000) {
  let response;
  try {
    response = await fetchImpl(url, {
      method: 'GET',
      redirect: 'manual',
      headers: { 'cache-control': 'no-cache' },
      signal: AbortSignal.timeout(timeoutMs),
    });
  } catch (error) {
    throw new RelayUnreachable(`The relay cannot be reached at ${url} (${error?.name ?? 'Error'}: ${error?.message ?? error}).`);
  }
  const header = response.headers.get('x-apassy-relay-mode');
  if (GATEWAY_ERRORS.has(response.status) && (header === null || header === undefined)) {
    throw new RelayUnreachable(`The edge answered ${response.status} for ${url} without x-apassy-relay-mode: the relay is not reached.`);
  }
  return { status: response.status, header };
}

/** The mode of the relay at `url` (see `reportedMode`). */
export async function liveMode(url, fetchImpl = fetch, timeoutMs = 15_000) {
  const { status, header } = await probe(url, fetchImpl, timeoutMs);
  return reportedMode(status, header);
}

/**
 * The preflight: reads the mode of `config` and checks it against the relay. Answers the
 * exit code (0 or 1) and writes its lines to `out`. The skip of `env.APASSY_EDGE_MODE_CHECK`
 * passes only a relay that cannot be reached.
 */
export async function main({ config, env = {}, fetchImpl = fetch, out = console, timeoutMs = 15_000 }) {
  try {
    const configured = configuredMode(config);
    const url = healthUrl(config, env);
    const skip = env.APASSY_EDGE_MODE_CHECK === 'skip';
    if (env.APASSY_EDGE_MODE_CHECK !== undefined && env.APASSY_EDGE_MODE_CHECK !== '' && !skip) {
      throw new Error(`APASSY_EDGE_MODE_CHECK=${JSON.stringify(env.APASSY_EDGE_MODE_CHECK)}: only "skip" is known.`);
    }
    let reported;
    try {
      reported = await liveMode(url, fetchImpl, timeoutMs);
    } catch (error) {
      if (!(error instanceof RelayUnreachable)) throw error;
      if (!skip) {
        throw new Error(
          `${error.message} Its mode is unknown, so the deploy is refused. Only while the relay is stopped on purpose, ` +
            'set APASSY_EDGE_MODE_CHECK=skip (docs/operations/connect.md, section 9.3).',
        );
      }
      out.warn(
        `The relay mode check is SKIPPED (APASSY_EDGE_MODE_CHECK=skip): ${error.message} ` +
          `This deploy sets RELAY_MODE "${configured}" without the relay's mode.`,
      );
      return 0;
    }
    if (skip) out.warn('APASSY_EDGE_MODE_CHECK=skip is ignored: the relay answers, so its mode is checked.');
    checkRelayMode(configured, reported);
    out.log(
      reported === null
        ? `RELAY_MODE "relay": the relay answers without x-apassy-relay-mode, a relay before that header, in relay mode (${url}).`
        : `RELAY_MODE "${configured}" is the mode that the relay reports (${url}).`,
    );
    return 0;
  } catch (error) {
    out.error(`Worker relay mode preflight failed: ${error.message}`);
    return 1;
  }
}

if (process.argv[1] && resolve(process.argv[1]) === fileURLToPath(import.meta.url)) {
  let config;
  try {
    const worker = resolve(dirname(fileURLToPath(import.meta.url)), '..');
    config = parseJsonc(readFileSync(join(worker, 'wrangler.jsonc'), 'utf8'));
  } catch (error) {
    console.error(`Worker relay mode preflight failed: ${error.message}`);
    process.exitCode = 1;
  }
  if (config !== undefined) process.exitCode = await main({ config, env: process.env });
}

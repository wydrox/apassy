// The limits of the push gateway (docs/contracts/push-gateway-v1.md section 13).
//
// A Cloudflare Rate Limiting binding counts per 10 or 60 seconds only, so the hourly and
// daily limits of the contract are kept by the counter that section 13 allows: one
// Durable Object per limit and key, where the key is SHA-256 of the handle, the client
// address, or the APNs token (`limitKey`). The object stores one window, `[start, count]`,
// and nothing else: never a handle, a token, or an address. An alarm deletes the window
// when it ends, so a counter leaves nothing behind.
//
// Erasable TypeScript, with no `cloudflare:` import, so Node runs it in the tests. The
// Worker's main module (index.ts) exports `LimitCounter`.

/** One limit: at most `limit` requests per key in a fixed window of `period` seconds. */
export interface Limit {
  limit: number;
  period: number;
}

/** The limits of section 13 and of N8-3. */
export const LIMITS = {
  /** Pushes per handle: 60 per hour. Key: SHA-256 of the handle text. */
  pushes_per_handle: { limit: 60, period: 3600 },
  /** Pushes per node address: 600 per hour. Key: SHA-256 of the client address. */
  pushes_per_address: { limit: 600, period: 3600 },
  /** Handle creations per address: 30 per hour. Key: SHA-256 of the client address. */
  handles_per_address: { limit: 30, period: 3600 },
  /** Handle creations per APNs token: 10 per day. Key: SHA-256 of the token. */
  handles_per_token: { limit: 10, period: 86400 },
  /** Pushes per APNs token, over all its handles: 30 per hour. Key: SHA-256 of the token. */
  pushes_per_token: { limit: 30, period: 3600 },
} as const satisfies Record<string, Limit>;

export type LimitName = keyof typeof LIMITS;

/** A window: its start (Unix seconds) and the requests counted in it. */
export type Window = readonly [start: number, count: number];

/** The answer of a limit: `retryAfter` is the seconds until the window ends. */
export interface Allowed {
  success: boolean;
  retryAfter?: number;
}

/**
 * One request at `now` against `window`. A window starts at its first request and lasts
 * `period` seconds. A refused request is not counted, so asking again does not extend
 * the wait.
 */
export function step(window: Window | undefined, now: number, { limit, period }: Limit): { window: Window; allowed: Allowed } {
  const current: Window = window && now < window[0] + period && now >= window[0] ? window : [now, 0];
  const retryAfter = Math.max(1, current[0] + period - now);
  if (current[1] >= limit) return { window: current, allowed: { success: false, retryAfter } };
  return { window: [current[0], current[1] + 1], allowed: { success: true, retryAfter } };
}

/** The part of the Durable Object storage API that the counter uses. */
export interface CounterStorage {
  get<T>(key: string): Promise<T | undefined>;
  put<T>(key: string, value: T): Promise<void>;
  deleteAll(): Promise<void>;
  setAlarm(scheduledTime: number): Promise<void>;
}

/** The Durable Object of one limit and one key. */
export class LimitCounter {
  private readonly storage: CounterStorage;
  private readonly now: () => number;

  constructor(state: { storage: CounterStorage }, _env?: unknown, now: () => number = () => Math.floor(Date.now() / 1000)) {
    this.storage = state.storage;
    this.now = now;
  }

  /** `POST` with `{"limit":n,"period":s}`: `{"success":bool,"retry_after":s}`. */
  async fetch(request: Request): Promise<Response> {
    let parsed: unknown;
    try {
      parsed = await request.json();
    } catch {
      return new Response("", { status: 400 });
    }
    const { limit, period } = (parsed ?? {}) as Partial<Limit>;
    if (!Number.isSafeInteger(limit) || !Number.isSafeInteger(period) || limit! < 1 || period! < 1) {
      return new Response("", { status: 400 });
    }
    const now = this.now();
    const stored = await this.storage.get<Window>("w");
    const { window, allowed } = step(stored, now, { limit: limit!, period: period! });
    if (window !== stored) {
      await this.storage.put("w", window);
      if (!stored || stored[0] !== window[0]) await this.storage.setAlarm((window[0] + period!) * 1000);
    }
    return new Response(JSON.stringify({ success: allowed.success, retry_after: allowed.retryAfter }), {
      headers: { "content-type": "application/json" },
    });
  }

  /** The window ended: nothing stays. */
  async alarm(): Promise<void> {
    await this.storage.deleteAll();
  }
}

/** The part of a Durable Object namespace that the gateway uses. */
export interface CounterNamespace {
  idFromName(name: string): unknown;
  get(id: unknown): { fetch(input: string, init?: RequestInit): Promise<Response> };
}

/** A limit as the gateway calls it, given a key that is already SHA-256 hex. */
export interface RateLimit {
  limit(input: { key: string }): Promise<Allowed>;
}

/** The limit `name` through the counters of `namespace`. A failed counter throws. */
export function counterLimit(namespace: CounterNamespace, name: LimitName): RateLimit {
  const { limit, period } = LIMITS[name];
  return {
    async limit({ key }) {
      const stub = namespace.get(namespace.idFromName(`${name}:${key}`));
      const response = await stub.fetch("https://limit.invalid/", {
        method: "POST",
        headers: { "content-type": "application/json" },
        body: JSON.stringify({ limit, period }),
      });
      if (!response.ok) throw new Error("counter");
      const answer = (await response.json()) as { success?: unknown; retry_after?: unknown };
      if (typeof answer.success !== "boolean") throw new Error("counter");
      return {
        success: answer.success,
        retryAfter: typeof answer.retry_after === "number" ? answer.retry_after : undefined,
      };
    },
  };
}

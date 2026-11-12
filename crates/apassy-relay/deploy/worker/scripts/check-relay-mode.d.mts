export type RelayMode = 'relay' | 'connect';
type FetchLike = (
  input: string,
  init?: RequestInit,
) => Promise<{ status: number; headers: { get(name: string): string | null } }>;
export function parseJsonc(text: string): any;
export function configuredMode(config: unknown): RelayMode;
export function healthUrl(config: unknown, env?: Record<string, string | undefined>): string;
export function reportedMode(status: number, header: string | null | undefined): RelayMode | null;
export function checkRelayMode(configured: RelayMode, reported: RelayMode | null): void;
export class RelayUnreachable extends Error {}
export function probe(
  url: string,
  fetchImpl?: FetchLike,
  timeoutMs?: number,
): Promise<{ status: number; header: string | null }>;
export function liveMode(url: string, fetchImpl?: FetchLike, timeoutMs?: number): Promise<RelayMode | null>;
export function main(options: {
  config: unknown;
  env?: Record<string, string | undefined>;
  fetchImpl?: FetchLike;
  out?: { log(line: string): void; warn(line: string): void; error(line: string): void };
  timeoutMs?: number;
}): Promise<number>;

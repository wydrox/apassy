export type RelayMode = 'relay' | 'connect';
export function parseJsonc(text: string): any;
export function configuredMode(config: unknown): RelayMode;
export function healthUrl(config: unknown, env?: Record<string, string | undefined>): string;
export function reportedMode(status: number, header: string | null | undefined): RelayMode;
export function checkRelayMode(configured: RelayMode, reported: RelayMode): void;
export function liveMode(
  url: string,
  fetchImpl?: (input: string, init?: RequestInit) => Promise<{ status: number; headers: { get(name: string): string | null } }>,
): Promise<RelayMode>;

import { ProviderError } from "./errors.ts";

const DEFAULT_REQUEST_TIMEOUT_MS = 10 * 1000;

export type ProviderFetchOptions = {
  /** The provider's origin; Better Auth serves its API under `/api/auth` there. */
  issuer: string;
  fetch?: typeof fetch;
  /** The bound on every request; ten seconds by default. */
  timeoutMs?: number;
};

export function providerEndpoint(issuer: string, path: string): string {
  return new URL(path, issuer).toString();
}

/**
 * The provider's API base, `<issuer>/api/auth`: the issuer identifier it
 * stamps on tokens and authorization responses as `iss`, and the resource it
 * accepts by default.
 */
export function apiBase(issuer: string): string {
  return providerEndpoint(issuer, "/api/auth");
}

export async function providerFetch(
  options: ProviderFetchOptions,
  path: string,
  init: RequestInit = {},
  deadline?: number,
): Promise<Response> {
  const doFetch = options.fetch ?? globalThis.fetch.bind(globalThis);
  const timeoutMs = options.timeoutMs ?? DEFAULT_REQUEST_TIMEOUT_MS;
  const remaining =
    deadline === undefined
      ? timeoutMs
      : Math.min(timeoutMs, deadline - Date.now());
  if (remaining <= 0) {
    throw new ProviderError("Provider request deadline passed", 0);
  }
  return doFetch(providerEndpoint(options.issuer, path), {
    ...init,
    cache: "no-store",
    signal: AbortSignal.timeout(remaining),
  });
}

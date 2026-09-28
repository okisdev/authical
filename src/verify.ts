import { ProviderError } from "./errors.ts";
import {
  apiBase,
  providerFetch,
  type ProviderFetchOptions,
} from "./provider.ts";

export { ProviderError } from "./errors.ts";

export type TokenClaims = {
  iss: string;
  sub: string;
  aud: string | string[];
  exp: number;
  iat?: number;
  nbf?: number;
  scope?: string;
  client_id?: string;
  email?: string;
  name?: string;
  picture?: string;
  sid?: string;
} & Record<string, unknown>;

export type TokenVerifierConfig = {
  /** The provider's origin; Better Auth serves its API under `/api/auth` there. */
  issuer: string;
  /** The audience the token must name: the resource for an access token, the client id for an id token. */
  audience: string | string[];
  /** How long a fetched key set is served before it is read again; ten minutes by default. */
  keysMaxAgeMs?: number;
  /** How soon after a read for an unknown key id the next such read may happen; thirty seconds by default. */
  keysRetryMs?: number;
  /** Tolerance on `exp` and `nbf`; thirty seconds by default. */
  clockSkewMs?: number;
  requestTimeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
};

type Jwk = {
  kty?: string;
  crv?: string;
  x?: string;
  kid?: string;
  alg?: string;
};

type KeySet = { keys: Map<string, CryptoKey>; loadedAt: number };

const DEFAULT_KEYS_MAX_AGE_MS = 10 * 60 * 1000;
const DEFAULT_KEYS_RETRY_MS = 30 * 1000;
const DEFAULT_CLOCK_SKEW_MS = 30 * 1000;

function fromBase64Url(value: string): Uint8Array<ArrayBuffer> {
  const padded = value.replace(/-/g, "+").replace(/_/g, "/");
  const binary = atob(padded + "=".repeat((4 - (padded.length % 4)) % 4));
  const bytes = new Uint8Array(binary.length);
  for (let index = 0; index < binary.length; index++) {
    bytes[index] = binary.charCodeAt(index);
  }
  return bytes;
}

function decodeSegment(segment: string): Record<string, unknown> | null {
  try {
    const parsed: unknown = JSON.parse(
      new TextDecoder().decode(fromBase64Url(segment)),
    );
    return typeof parsed === "object" &&
      parsed !== null &&
      !Array.isArray(parsed)
      ? (parsed as Record<string, unknown>)
      : null;
  } catch {
    return null;
  }
}

/**
 * The Ed25519 keys of a key set, by key id. An entry that is not one, or
 * that WebCrypto refuses, is left out rather than failing the set, so one
 * bad entry in a rotation cannot take every token down with it.
 */
async function importKeys(jwks: unknown): Promise<Map<string, CryptoKey>> {
  const entries =
    typeof jwks === "object" &&
    jwks !== null &&
    Array.isArray((jwks as { keys?: unknown }).keys)
      ? ((jwks as { keys: unknown[] }).keys as Jwk[])
      : null;
  if (entries === null) throw new Error("The key set has no keys array");
  const keys = new Map<string, CryptoKey>();
  for (const [index, jwk] of entries.entries()) {
    if (
      typeof jwk !== "object" ||
      jwk === null ||
      jwk.kty !== "OKP" ||
      jwk.crv !== "Ed25519" ||
      typeof jwk.x !== "string"
    ) {
      continue;
    }
    try {
      const key = await crypto.subtle.importKey(
        "jwk",
        { kty: jwk.kty, crv: jwk.crv, x: jwk.x },
        { name: "Ed25519" },
        false,
        ["verify"],
      );
      keys.set(typeof jwk.kid === "string" ? jwk.kid : `#${index}`, key);
    } catch {}
  }
  return keys;
}

/**
 * Verifies a JWT the provider issued, for a server that receives one as a
 * bearer token: the EdDSA signature against the provider's key set at
 * `<issuer>/api/auth/jwks`, then `iss`, `aud`, `exp`, `nbf` and `sub`. A
 * token that fails any of them answers null; only a key set that cannot be
 * read at all, with nothing cached to fall back on, throws, because that is
 * the verifier's outage rather than the caller's bad token. Keys are cached
 * and re-read once when a token names a key id the cache does not hold,
 * which is how a rotation shows up.
 */
export function createTokenVerifier(config: TokenVerifierConfig) {
  const now = config.now ?? Date.now;
  const issuer = apiBase(config.issuer);
  const audiences = new Set(
    Array.isArray(config.audience) ? config.audience : [config.audience],
  );
  const keysMaxAgeMs = config.keysMaxAgeMs ?? DEFAULT_KEYS_MAX_AGE_MS;
  const keysRetryMs = config.keysRetryMs ?? DEFAULT_KEYS_RETRY_MS;
  const clockSkewMs = config.clockSkewMs ?? DEFAULT_CLOCK_SKEW_MS;
  const fetchOptions: ProviderFetchOptions = {
    issuer: config.issuer,
    fetch: config.fetch,
    timeoutMs: config.requestTimeoutMs,
  };
  let cached: KeySet | null = null;
  let loading: Promise<KeySet> | null = null;

  function load(): Promise<KeySet> {
    loading ??= (async () => {
      try {
        const response = await providerFetch(fetchOptions, "/api/auth/jwks");
        if (!response.ok) {
          throw new ProviderError(
            `Failed to load the key set: ${response.status}`,
            response.status,
          );
        }
        let keys: Map<string, CryptoKey>;
        try {
          keys = await importKeys(await response.json());
        } catch (error) {
          throw new ProviderError(
            `Failed to read the key set: ${
              error instanceof Error ? error.message : String(error)
            }`,
            response.status,
          );
        }
        cached = { keys, loadedAt: now() };
        return cached;
      } finally {
        loading = null;
      }
    })();
    return loading;
  }

  async function reload(): Promise<KeySet> {
    try {
      return await load();
    } catch (error) {
      if (cached) return cached;
      throw error;
    }
  }

  let missedAt = Number.NEGATIVE_INFINITY;

  async function candidates(kid: string | null): Promise<CryptoKey[]> {
    let set =
      cached && now() - cached.loadedAt < keysMaxAgeMs
        ? cached
        : await reload();
    if (kid !== null && !set.keys.has(kid) && now() - missedAt >= keysRetryMs) {
      missedAt = now();
      set = await reload();
    }
    if (kid === null) return [...set.keys.values()];
    const key = set.keys.get(kid);
    return key ? [key] : [];
  }

  return {
    /**
     * The claims of a token the provider issued, or null. `scopes` names the
     * scopes the endpoint needs; a token missing any of them is null as well.
     */
    async verify(
      token: string,
      options: { scopes?: string[] } = {},
    ): Promise<TokenClaims | null> {
      const segments = token.split(".");
      if (segments.length !== 3) return null;
      const header = decodeSegment(segments[0]!);
      const payload = decodeSegment(segments[1]!);
      if (!header || !payload || header.alg !== "EdDSA") return null;
      let signature: Uint8Array<ArrayBuffer>;
      try {
        signature = fromBase64Url(segments[2]!);
      } catch {
        return null;
      }
      const signed = new TextEncoder().encode(`${segments[0]}.${segments[1]}`);
      let valid = false;
      for (const key of await candidates(
        typeof header.kid === "string" ? header.kid : null,
      )) {
        if (await crypto.subtle.verify("Ed25519", key, signature, signed)) {
          valid = true;
          break;
        }
      }
      if (!valid) return null;
      if (payload.iss !== issuer) return null;
      const aud = Array.isArray(payload.aud)
        ? payload.aud
        : typeof payload.aud === "string"
          ? [payload.aud]
          : [];
      if (
        !aud.some((value) => typeof value === "string" && audiences.has(value))
      ) {
        return null;
      }
      const seconds = now() / 1000;
      const skew = clockSkewMs / 1000;
      if (typeof payload.exp !== "number" || payload.exp + skew <= seconds) {
        return null;
      }
      if (typeof payload.nbf === "number" && payload.nbf - skew > seconds) {
        return null;
      }
      if (typeof payload.sub !== "string" || payload.sub === "") return null;
      if (options.scopes?.length) {
        const granted = new Set(
          typeof payload.scope === "string" ? payload.scope.split(" ") : [],
        );
        if (!options.scopes.every((scope) => granted.has(scope))) return null;
      }
      return payload as TokenClaims;
    },
  };
}

export type TokenVerifier = ReturnType<typeof createTokenVerifier>;

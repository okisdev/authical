import { OAuthTokenError } from "./errors.ts";
import {
  apiBase,
  providerFetch,
  type ProviderFetchOptions,
} from "./provider.ts";
import {
  fetchUserInfo,
  refusesResource,
  requestToken,
  tokenErrorFrom,
  tokensFromResponse,
  type TokenClientOptions,
} from "./token.ts";
import type { TokenResponse, TokenSet, User } from "./types.ts";

export { isAccessDenied, OAuthTokenError, ProviderError } from "./errors.ts";
export type { TokenSet, User } from "./types.ts";

export const DEVICE_CODE_GRANT_TYPE =
  "urn:ietf:params:oauth:grant-type:device_code";

const SLOW_DOWN_STEP_MS = 5 * 1000;
const DEFAULT_REFRESH_BEFORE_EXPIRY_MS = 5 * 60 * 1000;

export type DeviceLoginConfig = {
  /** The provider's origin; Better Auth serves its API under `/api/auth` there. */
  issuer: string;
  clientId: string;
  scope?: string;
  /**
   * The resource the tokens are minted for; `<issuer>/api/auth` unless set,
   * `false` for opaque tokens. Sent with the device code request, so the
   * approval binds it, and again when the code is redeemed.
   */
  audience?: string | false;
  /** How close to expiry `ensureFresh` refreshes; five minutes by default. */
  refreshBeforeExpiryMs?: number;
  requestTimeoutMs?: number;
  fetch?: typeof fetch;
  now?: () => number;
  /** The wait between polls, for tests; a plain timer otherwise. */
  sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
};

export type DeviceAuthorization = {
  deviceCode: string;
  userCode: string;
  verificationUri: string;
  verificationUriComplete: string;
  expiresAt: number;
  intervalMs: number;
  /** The resource the approval binds; null when the provider refused it. */
  resource: string | null;
};

export type DeviceCredentials = {
  user: User;
  tokens: TokenSet;
};

function timerSleep(ms: number, signal?: AbortSignal): Promise<void> {
  return new Promise((resolve, reject) => {
    if (signal?.aborted) {
      reject(signal.reason ?? new Error("Device login aborted"));
      return;
    }
    const timer = setTimeout(() => {
      signal?.removeEventListener("abort", abort);
      resolve();
    }, ms);
    function abort() {
      clearTimeout(timer);
      reject(signal?.reason ?? new Error("Device login aborted"));
    }
    signal?.addEventListener("abort", abort, { once: true });
  });
}

/**
 * The RFC 8628 device authorization grant, for a desktop app, a CLI, or any
 * process without a browser of its own: `start` asks for a code, the person
 * approves it on the provider's device page, `wait` polls the token endpoint
 * until the approval lands, and `refresh` and `ensureFresh` keep the token set
 * alive afterwards. The credentials the flow hands back belong to the device,
 * not to the browser session that approved them, so they outlive it. Where
 * they are stored is the app's decision.
 */
export function createDeviceLogin(config: DeviceLoginConfig) {
  const now = config.now ?? Date.now;
  const sleep = config.sleep ?? timerSleep;
  const scope = config.scope ?? "openid profile email offline_access";
  const audience =
    config.audience === undefined
      ? apiBase(config.issuer)
      : config.audience || null;
  const refreshBeforeExpiryMs =
    config.refreshBeforeExpiryMs ?? DEFAULT_REFRESH_BEFORE_EXPIRY_MS;
  const fetchOptions: ProviderFetchOptions = {
    issuer: config.issuer,
    fetch: config.fetch,
    timeoutMs: config.requestTimeoutMs,
  };
  const tokenOptions = (resource: string | null): TokenClientOptions => ({
    ...fetchOptions,
    clientId: config.clientId,
    audience: resource,
  });

  async function requestCode(
    resource: string | null,
  ): Promise<DeviceAuthorization> {
    const body = new URLSearchParams({ client_id: config.clientId, scope });
    if (resource) body.set("resource", resource);
    const response = await providerFetch(
      fetchOptions,
      "/api/auth/device/code",
      {
        method: "POST",
        headers: { "Content-Type": "application/x-www-form-urlencoded" },
        body,
      },
    );
    if (!response.ok) {
      const error = await tokenErrorFrom(response);
      if (resource && refusesResource(error)) return requestCode(null);
      throw error;
    }
    const data = (await response.json()) as {
      device_code: string;
      user_code: string;
      verification_uri: string;
      verification_uri_complete: string;
      expires_in: number;
      interval?: number;
    };
    return {
      deviceCode: data.device_code,
      userCode: data.user_code,
      verificationUri: data.verification_uri,
      verificationUriComplete: data.verification_uri_complete,
      expiresAt: now() + data.expires_in * 1000,
      intervalMs: (data.interval ?? 5) * 1000,
      resource,
    };
  }

  async function credentialsFrom(
    response: TokenResponse,
    previous: DeviceCredentials | null,
  ): Promise<DeviceCredentials> {
    const tokens = tokensFromResponse(
      response,
      previous?.tokens ?? null,
      now(),
    );
    const user =
      previous?.user ?? (await fetchUserInfo(fetchOptions, tokens.accessToken));
    return { user, tokens };
  }

  return {
    /** Asks the provider for a device code and the user code to show. */
    start(): Promise<DeviceAuthorization> {
      return requestCode(audience);
    },

    /**
     * Polls until the person approves, at the interval the provider asked for
     * (`slow_down` adds five seconds), and resolves with the token set and the
     * profile from userinfo. Rejects with `OAuthTokenError` `access_denied`
     * when the person refuses and `expired_token` when nobody answers in time.
     */
    async wait(
      authorization: DeviceAuthorization,
      options: { signal?: AbortSignal } = {},
    ): Promise<DeviceCredentials> {
      let intervalMs = authorization.intervalMs;
      for (;;) {
        if (now() >= authorization.expiresAt) {
          throw new OAuthTokenError(
            400,
            "expired_token",
            "The device code expired before it was approved",
          );
        }
        await sleep(intervalMs, options.signal);
        try {
          const response = await requestToken(
            tokenOptions(authorization.resource),
            {
              grant_type: DEVICE_CODE_GRANT_TYPE,
              device_code: authorization.deviceCode,
            },
          );
          return await credentialsFrom(response, null);
        } catch (error) {
          if (error instanceof OAuthTokenError) {
            if (error.code === "authorization_pending") continue;
            if (error.code === "slow_down") {
              intervalMs += SLOW_DOWN_STEP_MS;
              continue;
            }
          }
          throw error;
        }
      }
    },

    /**
     * Spends the refresh token for a new token set. A provider that rotates
     * refresh tokens, as Better Auth does, hands back a new one on every use,
     * so the credentials this resolves with replace the ones passed in. A
     * rejection that `isAccessDenied` accepts means the login is over;
     * anything else says nothing about it.
     */
    async refresh(credentials: DeviceCredentials): Promise<DeviceCredentials> {
      const { refreshToken } = credentials.tokens;
      if (!refreshToken) {
        throw new OAuthTokenError(
          400,
          "invalid_grant",
          "The credentials carry no refresh token",
        );
      }
      const response = await requestToken(tokenOptions(audience), {
        grant_type: "refresh_token",
        refresh_token: refreshToken,
      });
      return credentialsFrom(response, credentials);
    },

    /** The credentials as they are while the access token has time left, refreshed otherwise. */
    async ensureFresh(
      credentials: DeviceCredentials,
    ): Promise<DeviceCredentials> {
      if (
        credentials.tokens.accessTokenExpiresAt - refreshBeforeExpiryMs >
        now()
      ) {
        return credentials;
      }
      return this.refresh(credentials);
    },

    /**
     * Revokes the refresh token at the provider (RFC 7009), which ends the
     * login there; forgetting the credentials stays the caller's part. A
     * login without a refresh token has nothing to revoke.
     */
    async revoke(credentials: DeviceCredentials): Promise<void> {
      const { refreshToken } = credentials.tokens;
      if (!refreshToken) return;
      const response = await providerFetch(
        fetchOptions,
        "/api/auth/oauth2/revoke",
        {
          method: "POST",
          headers: { "Content-Type": "application/x-www-form-urlencoded" },
          body: new URLSearchParams({
            client_id: config.clientId,
            token: refreshToken,
            token_type_hint: "refresh_token",
          }),
        },
      );
      if (!response.ok) throw await tokenErrorFrom(response);
    },
  };
}

export type DeviceLogin = ReturnType<typeof createDeviceLogin>;

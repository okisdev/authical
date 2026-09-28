import { OAuthTokenError, ProviderError } from "./errors.ts";
import { providerFetch, type ProviderFetchOptions } from "./provider.ts";
import type { TokenResponse, TokenSet, User } from "./types.ts";

export type TokenClientOptions = ProviderFetchOptions & {
  clientId: string;
  clientSecret?: string;
  /** Sent as `resource`; null asks for no particular one. */
  audience: string | null;
};

export async function tokenErrorFrom(
  response: Response,
): Promise<OAuthTokenError> {
  const text = await response.text().catch(() => "");
  let code = "unknown_error";
  let description = text;
  try {
    const parsed = JSON.parse(text) as {
      error?: string;
      error_description?: string;
    };
    code = parsed.error ?? code;
    description = parsed.error_description ?? description;
  } catch {}
  return new OAuthTokenError(response.status, code, description);
}

/** Whether the provider refused the `resource` itself rather than the grant. */
export function refusesResource(error: OAuthTokenError): boolean {
  return (
    error.code === "invalid_target" ||
    (error.code === "invalid_request" && /resource/i.test(error.description))
  );
}

/**
 * Posts a grant to the token endpoint, with `client_secret` when the client
 * has one (client_secret_post) and `resource` when it names an audience.
 * Rejects with `OAuthTokenError` for an OAuth error response.
 */
export function requestToken(
  options: TokenClientOptions,
  params: Record<string, string>,
  deadline?: number,
): Promise<TokenResponse> {
  return postToken(options, params, deadline, true);
}

async function postToken(
  options: TokenClientOptions,
  params: Record<string, string>,
  deadline: number | undefined,
  withAudience: boolean,
): Promise<TokenResponse> {
  const body = new URLSearchParams({ client_id: options.clientId, ...params });
  if (options.clientSecret) body.set("client_secret", options.clientSecret);
  if (options.audience && withAudience) body.set("resource", options.audience);
  const response = await providerFetch(
    options,
    "/api/auth/oauth2/token",
    {
      method: "POST",
      headers: { "Content-Type": "application/x-www-form-urlencoded" },
      body,
    },
    deadline,
  );
  if (!response.ok) {
    const error = await tokenErrorFrom(response);
    // A provider that does not accept the audience still issues opaque tokens.
    if (withAudience && options.audience && refusesResource(error)) {
      return postToken(options, params, deadline, false);
    }
    throw error;
  }
  return (await response.json()) as TokenResponse;
}

export async function fetchUserInfo(
  options: ProviderFetchOptions,
  accessToken: string,
): Promise<User> {
  const response = await providerFetch(options, "/api/auth/oauth2/userinfo", {
    headers: { Authorization: `Bearer ${accessToken}` },
  });
  if (!response.ok) {
    throw new ProviderError(
      `Failed to load user info: ${response.status}`,
      response.status,
    );
  }
  const data = (await response.json()) as {
    sub: string;
    email?: string;
    name?: string;
    picture?: string;
  };
  return {
    id: data.sub,
    email: data.email ?? "",
    name: data.name ?? data.email ?? data.sub,
    image: data.picture ?? null,
  };
}

export function tokensFromResponse(
  response: TokenResponse,
  previous: { refreshToken: string | null; idToken: string | null } | null,
  now: number,
): TokenSet {
  return {
    accessToken: response.access_token,
    refreshToken: response.refresh_token ?? previous?.refreshToken ?? null,
    idToken: response.id_token ?? previous?.idToken ?? null,
    accessTokenExpiresAt:
      typeof response.expires_at === "number"
        ? response.expires_at * 1000
        : now + (response.expires_in ?? 3600) * 1000,
  };
}

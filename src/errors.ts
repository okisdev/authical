/**
 * A request to the provider that failed: `status` is the HTTP status it
 * answered with, or 0 when the request's deadline passed before it was sent.
 */
export class ProviderError extends Error {
  readonly status: number;

  constructor(message: string, status: number) {
    super(message);
    this.name = "ProviderError";
    this.status = status;
  }
}

export class OAuthTokenError extends ProviderError {
  readonly code: string;
  readonly description: string;

  constructor(status: number, code: string, description: string) {
    super(`Token request failed: ${status} ${code} ${description}`, status);
    this.name = "OAuthTokenError";
    this.code = code;
    this.description = description;
  }
}

const TRANSIENT_STATUSES = new Set([408, 425, 429]);

/**
 * Whether the provider rejected the token, the client, or the user, which
 * ends the login built on them, as opposed to failing to answer, which keeps
 * it. Any 4xx but a timeout or a rate limit counts: a provider answers a
 * revoked token or a disabled client with 400 as readily as with 401.
 */
export function isAccessDenied(error: unknown): boolean {
  return (
    error instanceof ProviderError &&
    error.status >= 400 &&
    error.status < 500 &&
    !TRANSIENT_STATUSES.has(error.status)
  );
}

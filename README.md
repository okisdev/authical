# authical

An OAuth client for apps that sign in through a [Better Auth](https://www.better-auth.com) OAuth provider: the device authorization grant for desktop apps and CLIs, and access token verification for resource servers. It needs nothing but `fetch` and WebCrypto, so it runs in Node, Electron and Cloudflare Workers alike, and has no dependencies.

Every entry takes the provider as its origin in `issuer`. Better Auth serves its API under `/api/auth` there, and `<issuer>/api/auth` is also the issuer identifier its tokens carry as `iss`.

```sh
npm install authical
```

## Signing in without a browser of your own

`authical/device` runs the device authorization grant (RFC 8628): the app shows a code, the person approves it on the provider's device page, and the app receives a token set that belongs to the device rather than to the browser session that approved it.

```ts
import { createDeviceLogin } from "authical/device";

const login = createDeviceLogin({
  issuer: "https://accounts.example.com",
  clientId: "my-app",
  scope: "openid profile email offline_access",
  audience: "https://api.example.com",
});

const authorization = await login.start();
console.log(`Confirm ${authorization.userCode} at ${authorization.verificationUriComplete}`);
let credentials = await login.wait(authorization);

credentials = await login.ensureFresh(credentials);
await fetch("https://api.example.com/items", {
  headers: { Authorization: `Bearer ${credentials.tokens.accessToken}` },
});

await login.revoke(credentials);
```

- `wait` polls at the interval the provider asks for, adds five seconds on `slow_down`, and resolves with the token set and the profile from userinfo. It rejects with `OAuthTokenError` `access_denied` when the person refuses and `expired_token` when nobody answers in time, and stops when the `signal` passed to it aborts.
- `refresh` spends the refresh token, and `ensureFresh` does so once the access token is within five minutes of expiry. Better Auth rotates refresh tokens on every use, so store the credentials they resolve with in place of the old ones.
- A failure that `isAccessDenied` accepts, a 4xx other than 408, 425 or 429, means the login is over. Anything else is an outage that says nothing about the grant, so keep the credentials and try again later.
- `revoke` revokes the refresh token at the provider (RFC 7009). Forgetting the credentials is the app's part, as is storing them in the first place.
- `audience` is sent as `resource` and binds the approval. It defaults to the provider's own API base, and `false` asks for opaque tokens. A provider that refuses the resource is asked once more without it.

## Verifying access tokens

`authical/verify` checks a bearer token without calling the provider: the EdDSA signature against the key set at `<issuer>/api/auth/jwks`, then `iss`, `aud`, `exp`, `nbf` and `sub` with thirty seconds of clock skew, and the scopes an endpoint names against the token's `scope` claim.

```ts
import { createTokenVerifier } from "authical/verify";

const verifier = createTokenVerifier({
  issuer: "https://accounts.example.com",
  audience: "https://api.example.com",
});

const claims = await verifier.verify(bearer, { scopes: ["api:write"] });
if (!claims) return new Response(null, { status: 401 });
```

A token that fails any check answers `null`. Only a key set that cannot be read, with nothing cached to fall back on, throws a `ProviderError`, because that is the verifier's outage rather than the caller's bad token. Keys are cached for ten minutes and read again when a token names a key id the cache does not hold, at most once every thirty seconds, which is how a key rotation shows up.

## The token client

The root entry holds what both flows are built on, for a client that runs another grant: `requestToken` posts a grant to the token endpoint (with `client_secret` when the client has one, and the same `resource` fallback), `fetchUserInfo` reads the profile, `tokensFromResponse` turns a token response into a token set, and `providerFetch` is the request every one of them makes, bounded by a timeout of ten seconds unless `timeoutMs` says otherwise. `ProviderError`, `OAuthTokenError` and `isAccessDenied` are the same classes and function every entry exports.

## License

MIT

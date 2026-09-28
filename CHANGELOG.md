# authical

## 0.0.1

### added

- `authical/device`: the RFC 8628 device authorization grant for a desktop app or CLI. `createDeviceLogin({ issuer, clientId })` gives `start`, which asks for a device code and the user code to show; `wait`, which polls at the interval the provider asks for, adds five seconds on `slow_down`, and resolves with the token set and the profile from userinfo; `refresh` and `ensureFresh` for the token set afterwards; and `revoke`, which revokes the refresh token at the provider (RFC 7009).
- `authical/verify`: `createTokenVerifier({ issuer, audience })` for a server that receives the provider's JWT as a bearer token. it checks the EdDSA signature against the provider's key set, then `iss`, `aud`, `exp`, `nbf` and `sub`, and the scopes an endpoint names, answers null for a token that fails any of them, and throws only when the key set cannot be read with nothing cached.
- `authical`: the token client both are built on (`requestToken`, `fetchUserInfo`, `tokensFromResponse`, `providerFetch`), the errors (`ProviderError`, `OAuthTokenError`) and `isAccessDenied`, which reads a 4xx other than 408, 425 or 429 as the provider refusing the grant and anything else as an outage.

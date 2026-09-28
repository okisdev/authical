# authical

An OAuth client for apps that sign in through a Better Auth OAuth provider, published on npm; `README.md` is the consumer manual.

## Commands

- `pnpm test` runs the suites against `src/` without a build; after `pnpm build` it also runs `test/dist.test.ts` against `dist/`.
- `pnpm typecheck`, and `pnpm build` followed by a look at `dist/` after touching the entry map in `tsdown.config.ts` and `package.json`.

## Rules

- Take no runtime dependency and stay on `fetch` and WebCrypto, because the same entries run in Node, Electron and Cloudflare Workers.
- Send every request to the provider through `providerFetch`, because a fetch without its timeout is a hang waiting to happen.
- Keep one copy of the error classes across entries (`test/dist.test.ts`), because `isAccessDenied` reads them with `instanceof`.
- Read a failure through `isAccessDenied` everywhere: a 4xx other than 408, 425 or 429 ends a login, anything else keeps it, because a client that retries a refusal is a token endpoint storm and a client that drops a login on an outage signs everyone out.
- Keep the device login polling at the interval the provider asks for, adding five seconds on `slow_down`.
- Make `createTokenVerifier` answer null for a token that fails any check and throw only for a key set it cannot read with nothing cached, because a bad token is the caller's 401 and an unreadable key set is the verifier's outage.
- Give source imports the `.ts` extension, because the tests run on `node --experimental-strip-types` against `src/`.
- Add a test in `test/` with every behaviour change.
- Keep publishing manual and the version on `0.0.x`, and follow a release with a range bump in each consumer, because a caret on `0.0.x` resolves to that single patch.

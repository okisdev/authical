import assert from "node:assert/strict";
import test from "node:test";
import { createTokenVerifier, ProviderError } from "../src/verify.ts";
import { createProviderStub, TEST_NOW, toBase64Url } from "./helpers.ts";

const AUDIENCE = "https://accounts.test/api/auth";

async function keyPair(kid: string) {
  const pair = (await crypto.subtle.generateKey({ name: "Ed25519" }, true, [
    "sign",
    "verify",
  ])) as CryptoKeyPair;
  const exported = await crypto.subtle.exportKey("jwk", pair.publicKey);
  return {
    privateKey: pair.privateKey,
    jwk: {
      kid,
      kty: exported.kty,
      crv: exported.crv,
      x: exported.x,
      alg: "EdDSA",
    },
  };
}

function encode(value: unknown): string {
  return toBase64Url(new TextEncoder().encode(JSON.stringify(value)));
}

async function sign(
  privateKey: CryptoKey,
  header: Record<string, unknown>,
  payload: Record<string, unknown>,
): Promise<string> {
  const signed = `${encode(header)}.${encode(payload)}`;
  const signature = await crypto.subtle.sign(
    "Ed25519",
    privateKey,
    new TextEncoder().encode(signed),
  );
  return `${signed}.${toBase64Url(new Uint8Array(signature))}`;
}

function claims(overrides: Record<string, unknown> = {}) {
  return {
    iss: AUDIENCE,
    sub: "user_1",
    aud: AUDIENCE,
    exp: Math.floor(TEST_NOW / 1000) + 3600,
    iat: Math.floor(TEST_NOW / 1000),
    scope: "openid profile email",
    client_id: "test-client",
    ...overrides,
  };
}

async function setup(audience: string | string[] = AUDIENCE) {
  const harness = createProviderStub();
  const key = await keyPair("k1");
  const verifier = createTokenVerifier({
    issuer: "https://accounts.test",
    audience,
    fetch: harness.fetch,
    now: harness.now,
  });
  harness.responses.push({ body: { keys: [key.jwk] } });
  return { ...harness, key, verifier };
}

test("a token the provider signed verifies against its key set, fetched once", async () => {
  const { key, verifier, requests } = await setup();
  const token = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims(),
  );

  const first = await verifier.verify(token);
  const second = await verifier.verify(token);

  assert.equal(first?.sub, "user_1");
  assert.equal(first?.client_id, "test-client");
  assert.equal(second?.sub, "user_1");
  assert.equal(requests.length, 1);
  assert.equal(requests[0]?.url, "https://accounts.test/api/auth/jwks");
});

test("a key id the cache does not hold reads the key set again", async () => {
  const { key, verifier, requests, responses } = await setup();
  const rotated = await keyPair("k2");
  responses.push({ body: { keys: [key.jwk, rotated.jwk] } });
  const token = await sign(
    rotated.privateKey,
    { alg: "EdDSA", kid: "k2" },
    claims(),
  );

  assert.equal((await verifier.verify(token))?.sub, "user_1");
  assert.equal(requests.length, 2);
});

test("a forged, foreign, expired or premature token answers null", async () => {
  const { key, verifier } = await setup();
  const other = await keyPair("k1");
  const cases = [
    await sign(other.privateKey, { alg: "EdDSA", kid: "k1" }, claims()),
    await sign(key.privateKey, { alg: "RS256", kid: "k1" }, claims()),
    await sign(
      key.privateKey,
      { alg: "EdDSA", kid: "k1" },
      claims({ iss: "https://other.test/api/auth" }),
    ),
    await sign(
      key.privateKey,
      { alg: "EdDSA", kid: "k1" },
      claims({ aud: "someone-else" }),
    ),
    await sign(
      key.privateKey,
      { alg: "EdDSA", kid: "k1" },
      claims({ exp: Math.floor(TEST_NOW / 1000) - 60 }),
    ),
    await sign(
      key.privateKey,
      { alg: "EdDSA", kid: "k1" },
      claims({ nbf: Math.floor(TEST_NOW / 1000) + 600 }),
    ),
    await sign(
      key.privateKey,
      { alg: "EdDSA", kid: "k1" },
      claims({ sub: "" }),
    ),
    await sign(
      key.privateKey,
      { alg: "EdDSA", kid: "k1" },
      claims({ exp: "soon" }),
    ),
    "not.a.jwt.at.all",
    "garbage",
  ];
  for (const token of cases) {
    assert.equal(await verifier.verify(token), null, token.slice(0, 40));
  }
});

test("an audience list and an aud array match on any common entry", async () => {
  const { key, verifier } = await setup([AUDIENCE, "test-client"]);
  const idToken = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims({ aud: "test-client" }),
  );
  const listed = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims({ aud: ["other", AUDIENCE] }),
  );

  assert.equal((await verifier.verify(idToken))?.aud, "test-client");
  assert.deepEqual((await verifier.verify(listed))?.aud, ["other", AUDIENCE]);
});

test("a token inside the clock skew still verifies", async () => {
  const { key, verifier } = await setup();
  const token = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims({
      exp: Math.floor(TEST_NOW / 1000) - 10,
      nbf: Math.floor(TEST_NOW / 1000) + 10,
    }),
  );

  assert.equal((await verifier.verify(token))?.sub, "user_1");
});

test("a token without a key id is checked against every key", async () => {
  const { key, verifier } = await setup();
  const token = await sign(key.privateKey, { alg: "EdDSA" }, claims());

  assert.equal((await verifier.verify(token))?.sub, "user_1");
});

test("a key set that cannot be read throws unless a cached one exists", async () => {
  const harness = createProviderStub();
  const key = await keyPair("k1");
  const verifier = createTokenVerifier({
    issuer: "https://accounts.test",
    audience: AUDIENCE,
    keysMaxAgeMs: 1000,
    fetch: harness.fetch,
    now: harness.now,
  });
  const token = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims(),
  );

  harness.responses.push({ status: 503, body: {} });
  await assert.rejects(
    verifier.verify(token),
    (error: unknown) =>
      error instanceof ProviderError && error.status === 503,
  );

  harness.responses.push({ body: { keys: [key.jwk] } });
  assert.equal((await verifier.verify(token))?.sub, "user_1");

  harness.setNow(TEST_NOW + 2000);
  harness.responses.push({ status: 503, body: {} });
  assert.equal((await verifier.verify(token))?.sub, "user_1");
  assert.equal(harness.requests.length, 3);
});

test("an endpoint's scopes are checked against the token's scope claim", async () => {
  const { key, verifier } = await setup();
  const token = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims(),
  );
  const bare = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims({ scope: undefined }),
  );

  assert.equal(
    (await verifier.verify(token, { scopes: ["openid", "email"] }))?.sub,
    "user_1",
  );
  assert.equal(
    await verifier.verify(token, { scopes: ["openid", "api:write"] }),
    null,
  );
  assert.equal(await verifier.verify(bare, { scopes: ["openid"] }), null);
  assert.equal((await verifier.verify(bare, { scopes: [] }))?.sub, "user_1");
});

test("a key set that answers 200 without keys is a read failure, and a bad entry is skipped", async () => {
  const harness = createProviderStub();
  const key = await keyPair("k1");
  const verifier = createTokenVerifier({
    issuer: "https://accounts.test",
    audience: AUDIENCE,
    fetch: harness.fetch,
    now: harness.now,
  });
  const token = await sign(
    key.privateKey,
    { alg: "EdDSA", kid: "k1" },
    claims(),
  );

  harness.responses.push({ body: "not a key set" });
  await assert.rejects(
    verifier.verify(token),
    (error: unknown) =>
      error instanceof ProviderError &&
      error.status === 200 &&
      /key set/.test(error.message),
  );

  harness.responses.push({
    body: {
      keys: [
        { kid: "bad", kty: "OKP", crv: "Ed25519", x: "not-a-key" },
        "not an object",
        key.jwk,
      ],
    },
  });
  assert.equal((await verifier.verify(token))?.sub, "user_1");
});

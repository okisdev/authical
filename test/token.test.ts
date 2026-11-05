import assert from "node:assert/strict";
import test from "node:test";
import {
  ProviderError,
  REFRESH_REFUSAL_RETRY_MS,
  refreshTokens,
  requestToken,
} from "../src/index.ts";
import { createProviderStub } from "./helpers.ts";

test("a token request asks again without the resource when the provider refuses it", async () => {
  const stub = createProviderStub();
  stub.responses.push({
    status: 400,
    body: { error: "invalid_target", error_description: "unknown resource" },
  });
  stub.responses.push({ body: { access_token: "at_1", expires_in: 3600 } });

  const response = await requestToken(
    {
      issuer: "https://accounts.test",
      clientId: "test-client",
      clientSecret: "secret",
      audience: "https://api.test",
      fetch: stub.fetch,
    },
    { grant_type: "refresh_token", refresh_token: "rt_0" },
  );

  assert.equal(
    stub.requests[0]?.url,
    "https://accounts.test/api/auth/oauth2/token",
  );
  assert.deepEqual(stub.requests[0]?.body, {
    client_id: "test-client",
    grant_type: "refresh_token",
    refresh_token: "rt_0",
    client_secret: "secret",
    resource: "https://api.test",
  });
  assert.equal("resource" in stub.requests[1]!.body, false);
  assert.equal(response.access_token, "at_1");
});

test("a token request past its deadline fails without asking", async () => {
  const stub = createProviderStub();

  await assert.rejects(
    requestToken(
      {
        issuer: "https://accounts.test",
        clientId: "test-client",
        audience: null,
        fetch: stub.fetch,
      },
      { grant_type: "refresh_token", refresh_token: "rt_0" },
      Date.now() - 1,
    ),
    (error: unknown) => error instanceof ProviderError && error.status === 0,
  );
  assert.equal(stub.requests.length, 0);
});

test("refreshTokens tries once more after a refusal, and only a refusal", async () => {
  const { fetch, responses, requests } = createProviderStub();
  const options = {
    issuer: "https://accounts.test",
    clientId: "cloud",
    audience: null,
    fetch,
  };
  const pauses: number[] = [];
  const sleep = async (ms: number) => {
    pauses.push(ms);
  };
  const refused = {
    status: 400,
    body: { error: "invalid_grant", error_description: "rotated" },
  };

  responses.push(refused, { body: { access_token: "at_1" } });
  assert.equal(
    (await refreshTokens(options, "rt_0", sleep)).access_token,
    "at_1",
  );
  assert.deepEqual(pauses, [REFRESH_REFUSAL_RETRY_MS]);
  assert.equal(requests.length, 2);

  responses.push(refused, refused);
  await assert.rejects(refreshTokens(options, "rt_0", sleep), /invalid_grant/);
  assert.equal(requests.length, 4);

  responses.push(
    { status: 429, body: { error: "slow_down" } },
    { body: { access_token: "at_2" } },
  );
  await assert.rejects(refreshTokens(options, "rt_0", sleep), /slow_down/);
  assert.equal(requests.length, 5);
});

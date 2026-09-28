import assert from "node:assert/strict";
import test from "node:test";
import { ProviderError, requestToken } from "../src/index.ts";
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

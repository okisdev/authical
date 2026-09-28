import assert from "node:assert/strict";
import test from "node:test";
import {
  createDeviceLogin,
  DEVICE_CODE_GRANT_TYPE,
  isAccessDenied,
  OAuthTokenError,
  type DeviceAuthorization,
  type DeviceCredentials,
} from "../src/device.ts";
import { createProviderStub, TEST_NOW } from "./helpers.ts";

const CODE_RESPONSE = {
  device_code: "dc_1",
  user_code: "ABCD-EFGH",
  verification_uri: "https://accounts.test/device",
  verification_uri_complete: "https://accounts.test/device?user_code=ABCD-EFGH",
  expires_in: 600,
  interval: 5,
};

const TOKEN_RESPONSE = {
  access_token: "at_1",
  refresh_token: "rt_1",
  id_token: "idt_1",
  expires_in: 3600,
};

const USERINFO = {
  sub: "user_1",
  email: "u@test",
  name: "U",
  picture: "https://img.test/u.png",
};

function createLogin(
  overrides: {
    sleep?: (ms: number, signal?: AbortSignal) => Promise<void>;
  } = {},
) {
  const harness = createProviderStub();
  const sleeps: number[] = [];
  const login = createDeviceLogin({
    issuer: "https://accounts.test",
    clientId: "test-client",
    fetch: harness.fetch,
    now: harness.now,
    sleep:
      overrides.sleep ??
      (async (ms) => {
        sleeps.push(ms);
      }),
  });
  return { ...harness, login, sleeps };
}

function authorization(
  overrides: Partial<DeviceAuthorization> = {},
): DeviceAuthorization {
  return {
    deviceCode: "dc_1",
    userCode: "ABCD-EFGH",
    verificationUri: "https://accounts.test/device",
    verificationUriComplete: "https://accounts.test/device?user_code=ABCD-EFGH",
    expiresAt: TEST_NOW + 600_000,
    intervalMs: 5000,
    resource: "https://accounts.test/api/auth",
    ...overrides,
  };
}

function credentials(
  overrides: Partial<DeviceCredentials["tokens"]> = {},
): DeviceCredentials {
  return {
    user: { id: "user_1", email: "u@test", name: "U", image: null },
    tokens: {
      accessToken: "at_0",
      refreshToken: "rt_0",
      idToken: "idt_0",
      accessTokenExpiresAt: TEST_NOW + 3600_000,
      ...overrides,
    },
  };
}

test("start asks for a device code with the client, the scope and the resource", async () => {
  const { login, requests, responses } = createLogin();
  responses.push({ body: CODE_RESPONSE });

  const started = await login.start();

  assert.equal(requests[0]?.url, "https://accounts.test/api/auth/device/code");
  assert.deepEqual(requests[0]?.body, {
    client_id: "test-client",
    scope: "openid profile email offline_access",
    resource: "https://accounts.test/api/auth",
  });
  assert.deepEqual(started, {
    deviceCode: "dc_1",
    userCode: "ABCD-EFGH",
    verificationUri: "https://accounts.test/device",
    verificationUriComplete: "https://accounts.test/device?user_code=ABCD-EFGH",
    expiresAt: TEST_NOW + 600_000,
    intervalMs: 5000,
    resource: "https://accounts.test/api/auth",
  });
});

test("start asks again without the resource when the provider refuses it", async () => {
  const { login, requests, responses } = createLogin();
  responses.push({
    status: 400,
    body: { error: "invalid_target", error_description: "unknown resource" },
  });
  responses.push({ body: CODE_RESPONSE });

  const started = await login.start();

  assert.equal(requests.length, 2);
  assert.equal("resource" in requests[1]!.body, false);
  assert.equal(started.resource, null);
});

test("start surfaces a refusal that is not about the resource", async () => {
  const { login, responses } = createLogin();
  responses.push({
    status: 400,
    body: { error: "invalid_client", error_description: "no such client" },
  });

  await assert.rejects(
    login.start(),
    (error: unknown) =>
      error instanceof OAuthTokenError && error.code === "invalid_client",
  );
});

test("wait polls at the interval, slows down when asked, and resolves with the credentials", async () => {
  const { login, requests, responses, sleeps } = createLogin();
  responses.push({ status: 400, body: { error: "authorization_pending" } });
  responses.push({ status: 400, body: { error: "slow_down" } });
  responses.push({ body: TOKEN_RESPONSE });
  responses.push({ body: USERINFO });

  const result = await login.wait(authorization());

  assert.deepEqual(sleeps, [5000, 5000, 10_000]);
  assert.equal(requests.length, 4);
  for (const request of requests.slice(0, 3)) {
    assert.equal(request.url, "https://accounts.test/api/auth/oauth2/token");
    assert.deepEqual(request.body, {
      client_id: "test-client",
      grant_type: DEVICE_CODE_GRANT_TYPE,
      device_code: "dc_1",
      resource: "https://accounts.test/api/auth",
    });
  }
  assert.equal(
    requests[3]?.url,
    "https://accounts.test/api/auth/oauth2/userinfo",
  );
  assert.deepEqual(result, {
    user: {
      id: "user_1",
      email: "u@test",
      name: "U",
      image: "https://img.test/u.png",
    },
    tokens: {
      accessToken: "at_1",
      refreshToken: "rt_1",
      idToken: "idt_1",
      accessTokenExpiresAt: TEST_NOW + 3600_000,
    },
  });
});

test("wait redeems without the resource when the approval was bound without one", async () => {
  const { login, requests, responses } = createLogin();
  responses.push({ body: TOKEN_RESPONSE });
  responses.push({ body: USERINFO });

  await login.wait(authorization({ resource: null }));

  assert.equal("resource" in requests[0]!.body, false);
});

test("wait rejects when the person denies, and when the code has expired without asking", async () => {
  const { login, requests, responses, setNow } = createLogin();
  responses.push({
    status: 400,
    body: { error: "access_denied", error_description: "denied" },
  });

  await assert.rejects(
    login.wait(authorization()),
    (error: unknown) =>
      error instanceof OAuthTokenError && error.code === "access_denied",
  );
  assert.equal(requests.length, 1);

  setNow(TEST_NOW + 600_000);
  await assert.rejects(
    login.wait(authorization()),
    (error: unknown) =>
      error instanceof OAuthTokenError && error.code === "expired_token",
  );
  assert.equal(requests.length, 1);
});

test("wait stops when its signal aborts", async () => {
  const harness = createProviderStub();
  const login = createDeviceLogin({
    issuer: "https://accounts.test",
    clientId: "test-client",
    fetch: harness.fetch,
    now: harness.now,
  });
  const reason = new Error("stopped");

  await assert.rejects(
    login.wait(authorization({ intervalMs: 60_000 }), {
      signal: AbortSignal.abort(reason),
    }),
    (error: unknown) => error === reason,
  );
  assert.equal(harness.requests.length, 0);
});

test("refresh rotates the token set and keeps the captured profile", async () => {
  const { login, requests, responses } = createLogin();
  responses.push({
    body: { access_token: "at_1", refresh_token: "rt_1", expires_in: 3600 },
  });

  const refreshed = await login.refresh(credentials());

  assert.deepEqual(requests[0]?.body, {
    client_id: "test-client",
    grant_type: "refresh_token",
    refresh_token: "rt_0",
    resource: "https://accounts.test/api/auth",
  });
  assert.equal(requests.length, 1);
  assert.deepEqual(refreshed, {
    user: { id: "user_1", email: "u@test", name: "U", image: null },
    tokens: {
      accessToken: "at_1",
      refreshToken: "rt_1",
      idToken: "idt_0",
      accessTokenExpiresAt: TEST_NOW + 3600_000,
    },
  });
});

test("ensureFresh spends the refresh token only inside the refresh window", async () => {
  const { login, requests, responses, setNow } = createLogin();
  const current = credentials();

  assert.equal(await login.ensureFresh(current), current);
  assert.equal(requests.length, 0);

  setNow(TEST_NOW + 3600_000 - 4 * 60_000);
  responses.push({
    body: { access_token: "at_1", refresh_token: "rt_1", expires_in: 3600 },
  });
  const refreshed = await login.ensureFresh(current);
  assert.equal(requests.length, 1);
  assert.equal(refreshed.tokens.accessToken, "at_1");
});

test("a refused refresh reads as access denied and an outage does not", async () => {
  const { login, responses } = createLogin();
  responses.push({
    status: 400,
    body: { error: "invalid_grant", error_description: "session not found" },
  });
  responses.push({ status: 503, body: {} });

  await assert.rejects(login.refresh(credentials()), (error: unknown) =>
    isAccessDenied(error),
  );
  await assert.rejects(
    login.refresh(credentials()),
    (error: unknown) => !isAccessDenied(error),
  );
  await assert.rejects(
    login.refresh(credentials({ refreshToken: null })),
    (error: unknown) => isAccessDenied(error),
  );
});

test("revoke posts the refresh token to the revocation endpoint", async () => {
  const { login, requests, responses } = createLogin();
  responses.push({ body: {} });

  await login.revoke(credentials());

  assert.equal(
    requests[0]?.url,
    "https://accounts.test/api/auth/oauth2/revoke",
  );
  assert.deepEqual(requests[0]?.body, {
    client_id: "test-client",
    token: "rt_0",
    token_type_hint: "refresh_token",
  });
});

test("revoke asks nothing without a refresh token and rejects a refusal", async () => {
  const { login, requests, responses } = createLogin();

  await login.revoke(credentials({ refreshToken: null }));
  assert.equal(requests.length, 0);

  responses.push({
    status: 401,
    body: { error: "invalid_client", error_description: "no such client" },
  });
  await assert.rejects(
    login.revoke(credentials()),
    (error: unknown) =>
      error instanceof OAuthTokenError && error.code === "invalid_client",
  );
});

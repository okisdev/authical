import assert from "node:assert/strict";
import { existsSync } from "node:fs";
import test from "node:test";

// The specifier is computed so that a typecheck without a build has nothing to resolve.
const entry = (path: string): Promise<Record<string, any>> =>
  import(new URL(`../dist/${path}`, import.meta.url).href);

test(
  "built entries share error classes",
  {
    skip: existsSync(new URL("../dist/index.js", import.meta.url))
      ? false
      : "dist/index.js does not exist",
  },
  async () => {
    const [index, device, verify] = await Promise.all([
      entry("index.js"),
      entry("device.js"),
      entry("verify.js"),
    ]);
    assert.strictEqual(device.ProviderError, index.ProviderError);
    assert.strictEqual(verify.ProviderError, index.ProviderError);
    assert.strictEqual(device.OAuthTokenError, index.OAuthTokenError);
    assert.strictEqual(device.isAccessDenied, index.isAccessDenied);
  },
);

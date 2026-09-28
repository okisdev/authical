export const TEST_NOW = 1_700_000_000_000;

export type RecordedRequest = {
  url: string;
  body: Record<string, string>;
};

export type QueuedResponse = {
  body: unknown;
  status?: number;
};

/** A provider that answers from a queue and records every request, on a clock the test moves. */
export function createProviderStub() {
  let now = TEST_NOW;
  const requests: RecordedRequest[] = [];
  const responses: QueuedResponse[] = [];
  const fetch: typeof globalThis.fetch = async (input, init) => {
    const response = responses.shift();
    if (!response) throw new Error("No queued fetch response");
    const body = init?.body;
    const form = new URLSearchParams(
      body instanceof URLSearchParams ? body : String(body ?? ""),
    );
    requests.push({
      url: input instanceof Request ? input.url : input.toString(),
      body: Object.fromEntries(form.entries()),
    });
    return new Response(JSON.stringify(response.body), {
      status: response.status ?? 200,
      headers: { "content-type": "application/json" },
    });
  };

  return {
    fetch,
    now: () => now,
    requests,
    responses,
    setNow(ms: number) {
      now = ms;
    },
  };
}

export function toBase64Url(bytes: Uint8Array): string {
  let binary = "";
  for (const byte of bytes) binary += String.fromCharCode(byte);
  return btoa(binary)
    .replace(/\+/g, "-")
    .replace(/\//g, "_")
    .replace(/=+$/g, "");
}

import { beforeEach, describe, it, expect, vi } from "vitest";

const transportFetch = vi.fn();
const closeAgent = vi.fn(async () => {});

vi.mock("undici", () => ({
  Agent: class FakeAgent {
    close() {
      return closeAgent();
    }
  },
  fetch: (...args) => transportFetch(...args),
}));

const { safeFetch, SafeFetchError } = await import("../src/safeFetch.js");

const publicLookup = async () => [
  { address: "93.184.216.34", family: 4 },
];

function res({ status = 200, headers = {}, body = "" }) {
  const h = new Map(
    Object.entries(headers).map(([k, v]) => [k.toLowerCase(), v]),
  );
  return {
    status,
    ok: status >= 200 && status < 300,
    headers: { get: (k) => h.get(k.toLowerCase()) ?? null },
    async text() {
      return body;
    },
  };
}

describe("safeFetch", () => {
  beforeEach(() => {
    transportFetch.mockReset();
    closeAgent.mockClear();
  });

  it("returns response object for a 200 text/html response", async () => {
    transportFetch.mockImplementation(async () =>
      res({
        headers: { "content-type": "text/html; charset=utf-8" },
        body: "<html>hi</html>",
      }),
    );
    const response = await safeFetch("https://example.com/e/1", {
      lookupImpl: publicLookup,
    });
    
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("<html>hi</html>");
  });

  it("re-validates every redirect hop against SSRF, blocking a redirect to a private address", async () => {
    transportFetch.mockImplementation(async (url) => {
      if (url === "https://example.com/e/1") {
        return res({
          status: 302,
          headers: { location: "http://169.254.169.254/" },
        });
      }
      return res({ headers: { "content-type": "text/html" }, body: "secret" });
    });
    // The metadata IP must be rejected on the second hop.
    await expect(
      safeFetch("https://example.com/e/1", {
        lookupImpl: publicLookup,
      }),
    ).rejects.toMatchObject({ code: "unsafe_url" });
  });

  it("caps redirects", async () => {
    transportFetch.mockImplementation(async () =>
      res({ status: 302, headers: { location: "https://example.com/next" } }),
    );
    await expect(
      safeFetch("https://example.com/e/1", {
        lookupImpl: publicLookup,
        maxRedirects: 2,
      }),
    ).rejects.toMatchObject({ code: "redirect_limit" });
  });

  it("enforces the body size cap on .text()", async () => {
    transportFetch.mockImplementation(async () =>
      res({
        headers: { "content-type": "text/html", "content-length": "999999" },
        body: "x".repeat(999999),
      }),
    );
      
    const response = await safeFetch("https://example.com/e/1", {
      lookupImpl: publicLookup,
    });
    
    // safeFetch itself doesn't read the body yet, but it overrides reading on the SafeResponse
    response._maxBytes = 1024; // Override for testing the read wrapper
    
    await expect(response.text()).rejects.toMatchObject({ code: "response_too_large" });
  });

  it("surfaces AbortError as a timeout code", async () => {
    transportFetch.mockImplementation(async () => {
      const e = new Error("aborted");
      e.name = "AbortError";
      throw e;
    });
    await expect(
      safeFetch("https://example.com/e/1", {
        lookupImpl: publicLookup,
      }),
    ).rejects.toMatchObject({ code: "timeout" });
  });

  it("keeps the timeout active until the response body is consumed", async () => {
    transportFetch.mockImplementation(async (_url, init) => ({
      status: 200,
      statusText: "OK",
      ok: true,
      headers: { get: () => null },
      body: {
        getReader() {
          return {
            read() {
              return new Promise((_, reject) => {
                init.signal.addEventListener("abort", () => {
                  const error = new Error("aborted");
                  error.name = "AbortError";
                  reject(error);
                }, { once: true });
              });
            },
            releaseLock() {},
          };
        },
        async cancel() {},
      },
    }));

    const response = await safeFetch("https://example.com/e/1", {
      lookupImpl: publicLookup,
      timeoutMs: 5,
    });

    await expect(response.text()).rejects.toMatchObject({ code: "timeout" });
    expect(closeAgent).toHaveBeenCalledTimes(1);
  });

  it("drops credentials when a redirect crosses origins", async () => {
    transportFetch
      .mockResolvedValueOnce(
        res({
          status: 302,
          headers: { location: "https://cdn.example.net/event" },
        }),
      )
      .mockResolvedValueOnce(res({ body: "ok" }));

    const response = await safeFetch("https://example.com/e/1", {
      lookupImpl: publicLookup,
      headers: {
        authorization: "Bearer secret",
        cookie: "session=secret",
        "x-request-id": "safe-to-forward",
      },
    });
    await response.text();

    const redirectedHeaders = transportFetch.mock.calls[1][1].headers;
    expect(redirectedHeaders.authorization).toBeUndefined();
    expect(redirectedHeaders.cookie).toBeUndefined();
    expect(redirectedHeaders["x-request-id"]).toBe("safe-to-forward");
  });

  it("SafeFetchError carries a code", () => {
    expect(new SafeFetchError("x").code).toBe("x");
  });
});

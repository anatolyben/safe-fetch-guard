import { describe, it, expect } from "vitest";
import { safeFetch, SafeFetchError } from "../src/safeFetch.js";

const okPublic = async () => ({ ok: true });

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
  it("returns response object for a 200 text/html response", async () => {
    const fetchImpl = async () =>
      res({
        headers: { "content-type": "text/html; charset=utf-8" },
        body: "<html>hi</html>",
      });
    const response = await safeFetch("https://example.com/e/1", {
      fetchImpl,
    });
    
    expect(response.status).toBe(200);
    expect(await response.text()).toBe("<html>hi</html>");
  });

  it("re-validates every redirect hop against SSRF, blocking a redirect to a private address", async () => {
    const fetchImpl = async (url) => {
      if (url === "https://example.com/e/1") {
        return res({
          status: 302,
          headers: { location: "http://169.254.169.254/" },
        });
      }
      return res({ headers: { "content-type": "text/html" }, body: "secret" });
    };
    // The metadata IP must be rejected on the second hop.
    await expect(
      safeFetch("https://example.com/e/1", { fetchImpl }),
    ).rejects.toMatchObject({ code: "unsafe_url" });
  });

  it("caps redirects", async () => {
    const fetchImpl = async () =>
      res({ status: 302, headers: { location: "https://example.com/next" } });
    await expect(
      safeFetch("https://example.com/e/1", {
        fetchImpl,
        maxRedirects: 2,
      }),
    ).rejects.toMatchObject({ code: "redirect_limit" });
  });

  it("enforces the body size cap on .text()", async () => {
    const fetchImpl = async () =>
      res({
        headers: { "content-type": "text/html", "content-length": "999999" },
        body: "x".repeat(999999),
      });
      
    const response = await safeFetch("https://example.com/e/1", {
      fetchImpl,
    });
    
    // safeFetch itself doesn't read the body yet, but it overrides reading on the SafeResponse
    response._maxBytes = 1024; // Override for testing the read wrapper
    
    await expect(response.text()).rejects.toMatchObject({ code: "response_too_large" });
  });

  it("surfaces AbortError as a timeout code", async () => {
    const fetchImpl = async () => {
      const e = new Error("aborted");
      e.name = "AbortError";
      throw e;
    };
    await expect(
      safeFetch("https://example.com/e/1", {
        fetchImpl,
      }),
    ).rejects.toMatchObject({ code: "timeout" });
  });

  it("SafeFetchError carries a code", () => {
    expect(new SafeFetchError("x").code).toBe("x");
  });
});

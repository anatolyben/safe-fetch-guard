import { beforeEach, describe, expect, it, vi } from "vitest";

const agentOptions = [];
const closeAgent = vi.fn(async () => {});
const transportFetch = vi.fn();

vi.mock("undici", () => ({
  Agent: class FakeAgent {
    constructor(options) {
      agentOptions.push(options);
    }

    close() {
      return closeAgent();
    }
  },
  fetch: (...args) => transportFetch(...args),
}));

const { safeFetch } = await import("../src/safeFetch.js");

function response(body = "ok") {
  return {
    status: 200,
    statusText: "OK",
    ok: true,
    headers: { get: () => null },
    async text() {
      return body;
    },
  };
}

function runLookup(lookup, hostname, options = {}) {
  return new Promise((resolve, reject) => {
    lookup(hostname, options, (error, address, family) => {
      if (error) reject(error);
      else resolve({ address, family });
    });
  });
}

describe("safeFetch DNS pinning", () => {
  beforeEach(() => {
    agentOptions.length = 0;
    closeAgent.mockClear();
    transportFetch.mockReset();
  });

  it("uses the address validated during preflight for the actual connection", async () => {
    const lookupImpl = vi.fn(async () => [
      { address: "93.184.216.34", family: 4 },
    ]);

    transportFetch.mockImplementation(async (_url, init) => {
      expect(init.dispatcher).toBeDefined();
      const connected = await runLookup(
        agentOptions[0].connect.lookup,
        "example.com",
      );
      expect(connected).toEqual({
        address: "93.184.216.34",
        family: 4,
      });
      return response();
    });

    const result = await safeFetch("https://example.com/event", {
      lookupImpl,
    });

    expect(await result.text()).toBe("ok");
    expect(lookupImpl).toHaveBeenCalledTimes(1);
    expect(closeAgent).toHaveBeenCalledTimes(1);
  });

  it("refuses to resolve any hostname other than the validated target", async () => {
    transportFetch.mockImplementation(async (_url, init) => {
      await expect(
        runLookup(agentOptions[0].connect.lookup, "attacker.example"),
      ).rejects.toMatchObject({ code: "ENOTFOUND" });
      return response();
    });

    const result = await safeFetch("https://example.com/event", {
      lookupImpl: async () => [
        { address: "93.184.216.34", family: 4 },
      ],
    });

    await result.text();
  });

  it("does not let callers replace the DNS-bound transport", async () => {
    const unboundFetch = vi.fn(async () => response("unsafe"));
    transportFetch.mockResolvedValue(response("safe"));

    const result = await safeFetch("https://example.com/event", {
      fetchImpl: unboundFetch,
      lookupImpl: async () => [
        { address: "93.184.216.34", family: 4 },
      ],
    });

    expect(await result.text()).toBe("safe");
    expect(unboundFetch).not.toHaveBeenCalled();
    expect(transportFetch).toHaveBeenCalledTimes(1);
  });
});

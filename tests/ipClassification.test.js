import { describe, expect, it } from "vitest";
import {
  assertPublicUrl,
  isPrivateIp,
} from "../src/ssrfGuard.js";

describe("IP classification", () => {
  it("allows globally routable IPv4 and IPv6 addresses", () => {
    expect(isPrivateIp("8.8.8.8")).toBe(false);
    expect(isPrivateIp("2606:4700:4700::1111")).toBe(false);
  });

  it.each([
    "192.0.2.10",
    "198.51.100.10",
    "203.0.113.10",
    "ff02::1",
    "2001:db8::1",
    "2002:7f00:1::",
    "64:ff9b::a00:1",
  ])("rejects non-global or transition address %s", (address) => {
    expect(isPrivateIp(address)).toBe(true);
  });

  it("rejects a hostname if any resolved address is non-public", async () => {
    const result = await assertPublicUrl("https://example.com", {
      lookupImpl: async () => [
        { address: "93.184.216.34", family: 4 },
        { address: "127.0.0.1", family: 4 },
      ],
    });

    expect(result).toEqual({
      ok: false,
      reason: "resolves_to_private_ip",
    });
  });
});

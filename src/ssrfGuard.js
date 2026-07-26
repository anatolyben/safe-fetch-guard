import dns from "dns";
import net from "net";

// Hostnames that are obviously non-public even before DNS resolution.
const PRIVATE_HOST_RE = /^(localhost|.*\.local|.*\.internal|.*\.localhost)$/i;

export function ipv4ToLong(ip) {
  const parts = ip.split(".");
  if (parts.length !== 4) return null;
  let long = 0;
  for (const part of parts) {
    const n = Number(part);
    if (!Number.isInteger(n) || n < 0 || n > 255) return null;
    long = long * 256 + n;
  }
  return long >>> 0;
}

// Private, loopback, link-local and reserved IPv4 blocks (CIDR base + prefix).
const DEFAULT_V4_BLOCKS = [
  ["0.0.0.0", 8], // "this" network
  ["10.0.0.0", 8], // private
  ["100.64.0.0", 10], // carrier-grade NAT
  ["127.0.0.0", 8], // loopback
  ["169.254.0.0", 16], // link-local (incl. 169.254.169.254 cloud metadata)
  ["172.16.0.0", 12], // private
  ["192.0.0.0", 24], // IETF protocol assignments
  ["192.168.0.0", 16], // private
  ["198.18.0.0", 15], // benchmarking
  ["224.0.0.0", 4], // multicast
  ["240.0.0.0", 4], // reserved (incl. 255.255.255.255)
];

function compileV4Blocks(blocks) {
  return blocks.map(([base, bits]) => {
    const baseLong = ipv4ToLong(base);
    const mask = bits === 0 ? 0 : (0xffffffff << (32 - bits)) >>> 0;
    return { baseLong: (baseLong & mask) >>> 0, mask };
  });
}

let compiledV4Blocks = compileV4Blocks(DEFAULT_V4_BLOCKS);

export function configureV4Blocks(blocks) {
  compiledV4Blocks = compileV4Blocks(blocks);
}

function isPrivateV4(ip) {
  const long = ipv4ToLong(ip);
  if (long === null) return true; // unparseable → treat as unsafe
  return compiledV4Blocks.some(
    ({ baseLong, mask }) => (long & mask) >>> 0 === baseLong
  );
}

// Expand any valid IPv6 string (compressed, or with an embedded dotted-quad)
// into its 8 hextets as integers. Returns null if it cannot be parsed.
export function expandV6(ip) {
  let s = ip
    .toLowerCase()
    .replace(/^\[|\]$/g, "")
    .replace(/%.*$/, ""); // strip zone id
  // Convert a trailing embedded dotted-quad to two hextets.
  const dotted = s.match(/^(.*:)(\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3})$/);
  if (dotted) {
    const v4 = dotted[2].split(".").map(Number);
    if (v4.some((n) => n > 255)) return null;
    const h1 = ((v4[0] << 8) | v4[1]).toString(16);
    const h2 = ((v4[2] << 8) | v4[3]).toString(16);
    s = `${dotted[1]}${h1}:${h2}`;
  }
  const halves = s.split("::");
  if (halves.length > 2) return null;
  const head = halves[0] ? halves[0].split(":") : [];
  const tail = halves.length === 2 && halves[1] ? halves[1].split(":") : [];
  const missing = 8 - head.length - tail.length;
  if (halves.length === 1 && missing !== 0) return null; // no "::" → must be exactly 8
  if (missing < 0) return null;
  const full = [...head, ...Array(missing).fill("0"), ...tail];
  if (full.length !== 8) return null;
  return full.map((h) => parseInt(h || "0", 16));
}

function isPrivateV6(ip) {
  const h = expandV6(ip);
  if (!h) return true; // unparseable → unsafe by default
  if (h.every((x) => x === 0)) return true; // :: unspecified
  if (h.slice(0, 7).every((x) => x === 0) && h[7] === 1) return true; // ::1 loopback
  // ::ffff:0:0/96 — IPv4-mapped: check the embedded IPv4 (dotted OR hex form).
  if (
    h[0] === 0 &&
    h[1] === 0 &&
    h[2] === 0 &&
    h[3] === 0 &&
    h[4] === 0 &&
    h[5] === 0xffff
  ) {
    const v4 = `${h[6] >> 8}.${h[6] & 0xff}.${h[7] >> 8}.${h[7] & 0xff}`;
    return isPrivateV4(v4);
  }
  if ((h[0] & 0xfe00) === 0xfc00) return true; // fc00::/7 unique-local
  if ((h[0] & 0xffc0) === 0xfe80) return true; // fe80::/10 link-local
  return false;
}

/** True for any loopback / private / link-local / reserved IP literal. */
export function isPrivateIp(ip) {
  const family = net.isIP(ip);
  if (family === 4) return isPrivateV4(ip);
  if (family === 6) return isPrivateV6(ip);
  return true; // not a valid IP literal → unsafe by default
}

/**
 * Syntactic validation only. Returns the parsed URL when the shape is a public
 * http(s) URL, or null otherwise. Does not touch the network.
 */
export function isSafeUrlSyntax(url, opts = {}) {
  const { allowLocalhost = false } = opts;
  if (typeof url !== "string") return null;
  let parsed;
  try {
    parsed = new URL(url.trim());
  } catch {
    return null;
  }
  if (!["http:", "https:"].includes(parsed.protocol)) return null;
  
  const host = parsed.hostname.replace(/^\[|\]$/g, "");
  
  if (!allowLocalhost && PRIVATE_HOST_RE.test(host)) return null;
  
  if (net.isIP(host)) {
    if (!allowLocalhost && isPrivateIp(host)) return null;
    if (allowLocalhost && isPrivateIp(host) && host !== '127.0.0.1' && host !== '::1') {
      return null; // even with allowLocalhost, we block other private IPs
    }
  }
  
  if (host.length < 3) return null;
  return parsed;
}

/**
 * Full pre-flight check for dispatch time. Validates syntax, then resolves the
 * hostname and rejects if any resolved address is private/reserved.
 * @returns {Promise<{ok: true, parsed: URL} | {ok: false, reason: string}>}
 */
export async function assertPublicUrl(url, opts = {}) {
  const { allowLocalhost = false } = opts;
  const parsed = isSafeUrlSyntax(url, { allowLocalhost });
  if (!parsed) return { ok: false, reason: "invalid_or_private_url" };

  const host = parsed.hostname.replace(/^\[|\]$/g, "");

  // Literal IP: already covered by isSafeUrlSyntax, but be explicit.
  if (net.isIP(host)) {
    if (allowLocalhost && (host === '127.0.0.1' || host === '::1')) {
      return { ok: true, parsed };
    }
    return isPrivateIp(host)
      ? { ok: false, reason: "private_ip" }
      : { ok: true, parsed };
  }

  let addresses;
  try {
    addresses = await dns.promises.lookup(host, { all: true });
  } catch {
    return { ok: false, reason: "dns_resolution_failed" };
  }
  if (!addresses.length) return { ok: false, reason: "dns_no_records" };
  
  const hasPrivate = addresses.some((a) => isPrivateIp(a.address));
  
  if (hasPrivate) {
    if (allowLocalhost && addresses.every(a => a.address === '127.0.0.1' || a.address === '::1')) {
      return { ok: true, parsed };
    }
    return { ok: false, reason: "resolves_to_private_ip" };
  }
  
  return { ok: true, parsed };
}

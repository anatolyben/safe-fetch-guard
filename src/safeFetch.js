import { assertPublicUrl } from "./ssrfGuard.js";
import { Agent, fetch as transportFetch } from "undici";

const DEFAULTS = {
  timeoutMs: 8000,
  maxRedirects: 4,
  maxBytes: 2 * 1024 * 1024,
  userAgent: "ssrf-guard/1.0",
};

export class SafeFetchError extends Error {
  constructor(code, message = code) {
    super(message);
    this.name = "SafeFetchError";
    this.code = code;
  }
}

async function readBounded(response, maxBytes) {
  const declared = Number(response.headers.get("content-length"));
  if (Number.isFinite(declared) && declared > maxBytes) {
    throw new SafeFetchError("response_too_large");
  }
  if (!response.body || typeof response.body.getReader !== "function") {
    const text = await response.text();
    if (Buffer.byteLength(text, "utf8") > maxBytes) {
      throw new SafeFetchError("response_too_large");
    }
    return Buffer.from(text, "utf8");
  }
  
  const reader = response.body.getReader();
  const chunks = [];
  let total = 0;
  
  try {
    for (;;) {
      const { done, value } = await reader.read();
      if (done) break;
      total += value.byteLength;
      if (total > maxBytes) {
        await reader.cancel().catch(() => {});
        throw new SafeFetchError("response_too_large");
      }
      chunks.push(Buffer.from(value));
    }
    return Buffer.concat(chunks);
  } finally {
    reader.releaseLock();
  }
}

class SafeResponse {
  constructor(response, maxBytes, finalUrl, controller, cleanup) {
    this._response = response;
    this._maxBytes = maxBytes;
    this._controller = controller;
    this._cleanup = cleanup;
    this._closed = false;
    this.status = response.status;
    this.statusText = response.statusText;
    this.ok = response.ok;
    this.headers = response.headers;
    this.url = finalUrl;
  }

  async arrayBuffer() {
    try {
      const buf = await readBounded(this._response, this._maxBytes);
      return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
    } catch (error) {
      if (error?.name === "AbortError" || this._controller.signal.aborted) {
        throw new SafeFetchError("timeout");
      }
      throw error;
    } finally {
      await this.close();
    }
  }

  async text() {
    try {
      const buf = await readBounded(this._response, this._maxBytes);
      return buf.toString("utf8");
    } catch (error) {
      if (error?.name === "AbortError" || this._controller.signal.aborted) {
        throw new SafeFetchError("timeout");
      }
      throw error;
    } finally {
      await this.close();
    }
  }

  async json() {
    const txt = await this.text();
    return JSON.parse(txt);
  }

  async close() {
    if (this._closed) return;
    this._closed = true;
    await this._response.body?.cancel?.().catch(() => {});
    await this._cleanup();
  }

  async [Symbol.asyncDispose]() {
    await this.close();
  }
}

function normalizedHostname(hostname) {
  return hostname.toLowerCase().replace(/\.$/, "");
}

function lookupError(hostname) {
  const error = new Error(`getaddrinfo ENOTFOUND ${hostname}`);
  error.code = "ENOTFOUND";
  error.hostname = hostname;
  return error;
}

function createPinnedLookup(expectedHostname, addresses) {
  const expected = normalizedHostname(expectedHostname);
  const pinned = addresses.map(({ address, family }) => ({ address, family }));

  return (hostname, options, callback) => {
    if (normalizedHostname(hostname) !== expected) {
      queueMicrotask(() => callback(lookupError(hostname)));
      return;
    }

    const requestedFamily = Number(options?.family) || 0;
    const matching = requestedFamily
      ? pinned.filter(({ family }) => family === requestedFamily)
      : pinned;

    if (!matching.length) {
      queueMicrotask(() => callback(lookupError(hostname)));
      return;
    }

    if (options?.all) {
      queueMicrotask(() => callback(null, matching));
      return;
    }

    const [{ address, family }] = matching;
    queueMicrotask(() => callback(null, address, family));
  };
}

function createPinnedDispatcher(parsed, addresses) {
  return new Agent({
    connect: {
      lookup: createPinnedLookup(parsed.hostname, addresses),
    },
  });
}

async function closeResponseAndDispatcher(response, dispatcher) {
  await response?.body?.cancel?.().catch(() => {});
  await dispatcher.close();
}

function normalizeHeaders(headers) {
  return Object.fromEntries(new Headers(headers).entries());
}

function stripCrossOriginCredentials(headers) {
  const sanitized = { ...headers };
  for (const name of [
    "authorization",
    "proxy-authorization",
    "cookie",
    "cookie2",
  ]) {
    delete sanitized[name];
  }
  return sanitized;
}

/**
 * safeFetch — bounded, SSRF-safe HTTP request for untrusted outbound URLs.
 *
 * @param {string} startUrl absolute http(s) URL to fetch
 * @param {object} [opts]
 * @param {number} [opts.timeoutMs]
 * @param {number} [opts.maxRedirects]
 * @param {number} [opts.maxBytes]
 * @param {boolean} [opts.allowLocalhost] 
 * @param {AbortSignal} [opts.signal]
 * @param {string} [opts.method="GET"]
 * @param {object} [opts.headers]
 * @param {string|Buffer} [opts.body]
 * @param {typeof import("node:dns").promises.lookup} [opts.lookupImpl]
 * @returns {Promise<SafeResponse>}
 */
export async function safeFetch(startUrl, opts = {}) {
  const {
    timeoutMs = DEFAULTS.timeoutMs,
    maxRedirects = DEFAULTS.maxRedirects,
    maxBytes = DEFAULTS.maxBytes,
    userAgent = DEFAULTS.userAgent,
    allowLocalhost = false,
    signal,
    method = "GET",
    headers = {},
    body,
    lookupImpl,
  } = opts;

  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  let externalAbort;
  let responseOwnsCleanup = false;

  if (signal) {
    if (signal.aborted) {
      clearTimeout(timer);
      throw new SafeFetchError("timeout", "AbortError");
    }
    externalAbort = () => controller.abort();
    signal.addEventListener("abort", externalAbort, { once: true });
  }

  let currentUrl = startUrl;
  let initOpts = {
    method,
    headers: {
      "user-agent": userAgent,
      ...normalizeHeaders(headers),
    },
    body,
    redirect: "manual",
    signal: controller.signal,
  };

  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const safe = await assertPublicUrl(currentUrl, {
        allowLocalhost,
        lookupImpl,
      });
      if (!safe.ok) {
        throw new SafeFetchError("unsafe_url", safe.reason);
      }

      const dispatcher = createPinnedDispatcher(safe.parsed, safe.addresses);
      let response;
      try {
        response = await transportFetch(currentUrl, {
          ...initOpts,
          dispatcher,
        });
      } catch (error) {
        await dispatcher.close();
        throw error;
      }

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location || hop === maxRedirects) {
          await closeResponseAndDispatcher(response, dispatcher);
          throw new SafeFetchError("redirect_limit");
        }
        const previousOrigin = new URL(currentUrl).origin;
        currentUrl = new URL(location, currentUrl).toString();
        await closeResponseAndDispatcher(response, dispatcher);
        if (new URL(currentUrl).origin !== previousOrigin) {
          initOpts.headers = stripCrossOriginCredentials(initOpts.headers);
        }
        
        // On 303, or 301/302 POST, change to GET and drop body
        if (
          response.status === 303 ||
          ((response.status === 301 || response.status === 302) &&
            initOpts.method === "POST")
        ) {
          initOpts.method = "GET";
          delete initOpts.body;
        }
        continue;
      }
      
      responseOwnsCleanup = true;
      return new SafeResponse(
        response,
        maxBytes,
        currentUrl,
        controller,
        async () => {
          clearTimeout(timer);
          if (signal && externalAbort) {
            signal.removeEventListener("abort", externalAbort);
          }
          await dispatcher.close();
        },
      );
    }
    throw new SafeFetchError("redirect_limit");
  } catch (error) {
    if (error?.name === "AbortError" || controller.signal.aborted) {
      throw new SafeFetchError("timeout");
    }
    throw error;
  } finally {
    if (!responseOwnsCleanup) {
      clearTimeout(timer);
      if (signal && externalAbort) {
        signal.removeEventListener("abort", externalAbort);
      }
    }
  }
}

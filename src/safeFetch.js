import { assertPublicUrl } from "./ssrfGuard.js";

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
    return text;
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
  constructor(response, maxBytes, finalUrl) {
    this._response = response;
    this._maxBytes = maxBytes;
    this.status = response.status;
    this.statusText = response.statusText;
    this.ok = response.ok;
    this.headers = response.headers;
    this.url = finalUrl;
  }

  async arrayBuffer() {
    const buf = await readBounded(this._response, this._maxBytes);
    return buf.buffer.slice(buf.byteOffset, buf.byteOffset + buf.byteLength);
  }

  async text() {
    const buf = await readBounded(this._response, this._maxBytes);
    return buf.toString("utf8");
  }

  async json() {
    const txt = await this.text();
    return JSON.parse(txt);
  }
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
 * @param {typeof fetch} [opts.fetchImpl] injectable fetch (tests)
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
    fetchImpl = fetch,
  } = opts;

  const controller = new AbortController();
  
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  
  if (signal) {
    if (signal.aborted) {
      clearTimeout(timer);
      throw new SafeFetchError("timeout", "AbortError");
    }
    signal.addEventListener("abort", () => controller.abort());
  }

  let currentUrl = startUrl;
  let initOpts = {
    method,
    headers: {
      "User-Agent": userAgent,
      ...headers,
    },
    body,
    redirect: "manual",
    signal: controller.signal,
  };

  try {
    for (let hop = 0; hop <= maxRedirects; hop++) {
      const safe = await assertPublicUrl(currentUrl, { allowLocalhost });
      if (!safe.ok) {
        throw new SafeFetchError("unsafe_url", safe.reason);
      }

      const response = await fetchImpl(currentUrl, initOpts);

      if (response.status >= 300 && response.status < 400) {
        const location = response.headers.get("location");
        if (!location || hop === maxRedirects) {
          throw new SafeFetchError("redirect_limit");
        }
        currentUrl = new URL(location, currentUrl).toString();
        
        // On 303, or 301/302 POST, change to GET and drop body
        if (
          response.status === 303 ||
          ((response.status === 301 || response.status === 302) && method === "POST")
        ) {
          initOpts.method = "GET";
          delete initOpts.body;
        }
        continue;
      }
      
      return new SafeResponse(response, maxBytes, currentUrl);
    }
    throw new SafeFetchError("redirect_limit");
  } catch (error) {
    if (error?.name === "AbortError" || controller.signal.aborted) {
      throw new SafeFetchError("timeout");
    }
    throw error;
  } finally {
    clearTimeout(timer);
  }
}

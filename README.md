# safe-fetch-guard

DNS-pinned, bounded HTTP fetching for untrusted outbound URLs in Node.js, plus preflight URL validation middleware for Express.

## The Problem
Server-Side Request Forgery (SSRF) occurs when a web application makes HTTP requests to an arbitrary URL provided by a user. If left unchecked, attackers can force your server to make requests to internal resources (like AWS/GCP metadata endpoints `169.254.169.254`, loopback addresses `127.0.0.1`, or internal private subnets like `10.0.0.0/8`). 

Standard libraries like `fetch` or `axios` do **not** protect against this by default, and a simple Regex check is often bypassable via DNS rebinding (e.g., setting a public domain to resolve to `127.0.0.1`).

**`safe-fetch-guard` solves this by:**
1. Rejecting bad URL syntax and known private IPs.
2. Resolving every address at dispatch time, rejecting private results, and pinning the actual connection to the validated address set.
3. Automatically breaking redirect loops and validating every hop in a redirect chain.
4. Enforcing byte-size caps on incoming response bodies.

## Installation

```bash
npm install safe-fetch-guard
```

## Usage as a Utility (`safeFetch`)

`safeFetch` is the protected dispatch path. It deliberately uses its own Undici transport so callers cannot accidentally replace the DNS-bound connection with an unvalidated fetch implementation.

```javascript
import { safeFetch, SafeFetchError } from 'safe-fetch-guard';

try {
  // Pass an untrusted webhook or scraping URL safely
  const response = await safeFetch('https://example.com/webhook', {
    method: 'GET',
    timeoutMs: 5000,
    maxBytes: 1024 * 1024, // 1MB cap
  });

  const body = await response.json();
  console.log(body);
} catch (error) {
  if (error instanceof SafeFetchError) {
    console.error('Fetch failed securely:', error.code, error.message);
  }
}
```

## Usage as Express Middleware

The Express middleware checks URL syntax and its current DNS resolution before accepting a request. That is useful input validation, but it cannot secure a later, separate HTTP client call. Use `safeFetch` when the application eventually dispatches the URL.

```javascript
import express from 'express';
import { ssrfMiddleware } from 'safe-fetch-guard';

const app = express();
app.use(express.json());

// Protect the `webhookUrl` field in req.body
app.post('/api/register-webhook', ssrfMiddleware({ bodyFields: ['webhookUrl'] }), (req, res) => {
  // Preflight passed. Persist the URL, then use safeFetch when dispatching it.
  res.send('Webhook registered!');
});

app.listen(3000);
```

## Features
- **DNS Rebinding Protection:** `safeFetch` pins the connection lookup to the exact public address set validated immediately before each request.
- **Internal IP Blocking:** By default, loopback addresses (`127.0.0.1`), link-local IPs (like `169.254.169.254`), and all private RFC1918 blocks are strictly rejected.
- **Redirect Validation:** If the target server redirects, `safe-fetch-guard` manually checks the redirect location to ensure it is not attempting to pivot into an internal network.
- **Credential Isolation:** Authorization and cookie headers are removed when a redirect crosses origins.
- **Bounded Lifetime:** The timeout remains active until the response body is consumed or explicitly closed.
- **Size Capping:** Safely caps the response body size while streaming to prevent memory exhaustion (DoS).
- **Extensible:** Override user-agents, timeout limits, and even toggle localhost allowances for testing environments.

## Response cleanup

Calling `text()`, `json()`, or `arrayBuffer()` consumes the bounded body and releases the transport. If you intentionally do not consume the body, call `await response.close()`.

## Version 2

Version 2 removes the injectable fetch implementation because an arbitrary client could ignore the pinned dispatcher and silently reintroduce DNS rebinding. It also makes Undici an explicit dependency and requires Node.js 20 or newer.

## License
MIT

# ssrf-guard

A robust, drop-in framework for making SSRF-safe HTTP requests in Node.js, and an Express middleware to protect your application from malicious user-submitted URLs.

## The Problem
Server-Side Request Forgery (SSRF) occurs when a web application makes HTTP requests to an arbitrary URL provided by a user. If left unchecked, attackers can force your server to make requests to internal resources (like AWS/GCP metadata endpoints `169.254.169.254`, loopback addresses `127.0.0.1`, or internal private subnets like `10.0.0.0/8`). 

Standard libraries like `fetch` or `axios` do **not** protect against this by default, and a simple Regex check is often bypassable via DNS rebinding (e.g., setting a public domain to resolve to `127.0.0.1`).

**`ssrf-guard` solves this by:**
1. Rejecting bad URL syntax and known private IPs.
2. Resolving the URL at dispatch time and verifying the resolved IP is public.
3. Automatically breaking redirect loops and validating every hop in a redirect chain.
4. Enforcing byte-size caps on incoming response bodies.

## Installation

```bash
npm install ssrf-guard
```

## Usage as a Utility (`safeFetch`)

`safeFetch` is designed as a secure, drop-in replacement for standard `fetch`.

```javascript
import { safeFetch, SafeFetchError } from 'ssrf-guard';

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

You can use the built-in Express middleware to automatically intercept and validate any URL found in incoming request bodies or query parameters.

```javascript
import express from 'express';
import { ssrfMiddleware } from 'ssrf-guard';

const app = express();
app.use(express.json());

// Protect the `webhookUrl` field in req.body
app.post('/api/register-webhook', ssrfMiddleware({ bodyFields: ['webhookUrl'] }), (req, res) => {
  // If we reach here, req.body.webhookUrl is syntactically safe
  // and does not resolve to an internal IP!
  res.send('Webhook registered!');
});

app.listen(3000);
```

## Features
- **DNS Rebinding Protection:** Ensures that the URL resolves to a public IP right before the request is made.
- **Internal IP Blocking:** By default, loopback addresses (`127.0.0.1`), link-local IPs (like `169.254.169.254`), and all private RFC1918 blocks are strictly rejected.
- **Redirect Validation:** If the target server redirects, `ssrf-guard` manually checks the redirect location to ensure it is not attempting to pivot into an internal network.
- **Size Capping:** Safely caps the response body size while streaming to prevent memory exhaustion (DoS).
- **Extensible:** Override user-agents, timeout limits, and even toggle localhost allowances for testing environments.

## License
MIT

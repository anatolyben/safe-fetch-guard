import { assertPublicUrl } from "./ssrfGuard.js";

/**
 * Express middleware to validate URLs in incoming requests to prevent SSRF.
 * 
 * @param {object} [opts]
 * @param {string[]} [opts.bodyFields=["url"]] Fields in req.body to check for URLs
 * @param {string[]} [opts.queryFields=["url"]] Fields in req.query to check for URLs
 * @param {boolean} [opts.allowLocalhost=false] Allow loopback addresses
 * @returns {import("express").RequestHandler}
 */
export function ssrfMiddleware(opts = {}) {
  const {
    bodyFields = ["url"],
    queryFields = ["url"],
    allowLocalhost = false,
  } = opts;

  return async (req, res, next) => {
    try {
      const urlsToCheck = [];
      
      if (req.body && typeof req.body === 'object') {
        for (const field of bodyFields) {
          if (typeof req.body[field] === 'string' && req.body[field].trim() !== '') {
            urlsToCheck.push(req.body[field]);
          }
        }
      }
      
      if (req.query && typeof req.query === 'object') {
        for (const field of queryFields) {
          if (typeof req.query[field] === 'string' && req.query[field].trim() !== '') {
            urlsToCheck.push(req.query[field]);
          }
        }
      }

      for (const url of urlsToCheck) {
        const safe = await assertPublicUrl(url, { allowLocalhost });
        if (!safe.ok) {
          if (safe.reason === "private_ip" || safe.reason === "resolves_to_private_ip") {
            return res.status(403).json({ error: "Forbidden", message: `SSRF Blocked: URL resolved to a private IP (${safe.reason})` });
          }
          return res.status(400).json({ error: "Bad Request", message: `Invalid URL: ${safe.reason}` });
        }
      }
      
      next();
    } catch (error) {
      next(error);
    }
  };
}

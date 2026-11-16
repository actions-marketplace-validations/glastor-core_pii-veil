/**
 * Express & Fastify DLP middleware for pii-veil.
 */

const { Veil } = require('../../index');

function piiVeilMiddleware(options = {}) {
  const veil = new Veil(options);

  return function (req, res, next) {
    req.veil = veil;

    // Sanitize req.body if string or JSON object
    if (req.body) {
      if (typeof req.body === 'string') {
        const { sanitized } = veil.redact(req.body);
        req.rawBody = req.body;
        req.body = sanitized;
      } else if (typeof req.body === 'object') {
        const rawJson = JSON.stringify(req.body);
        const { sanitized } = veil.redact(rawJson);
        try {
          req.rawBody = req.body;
          req.body = JSON.parse(sanitized);
        } catch (_) {}
      }
    }

    // Intercept res.send/res.json to restore outbound LLM placeholders
    if (options.restoreResponse !== false && res && typeof res.send === 'function') {
      const originalSend = res.send.bind(res);
      res.send = function (body) {
        if (typeof body === 'string') {
          return originalSend(veil.restore(body));
        }
        return originalSend(body);
      };
    }

    if (typeof next === 'function') {
      next();
    }
  };
}

module.exports = { piiVeilMiddleware };

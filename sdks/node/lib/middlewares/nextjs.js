/**
 * Next.js App Router (Route Handlers) & Pages Router DLP wrapper.
 */

const { Veil } = require('../../index');

/**
 * Wraps a Next.js App Router POST handler to automatically sanitize incoming prompts
 * and restore responses.
 *
 * Usage:
 * export const POST = withPiiVeil(async (req, { veil }) => {
 *   const { prompt } = await req.json(); // already sanitized!
 *   const reply = await callOpenAI(prompt);
 *   return Response.json({ reply }); // placeholders restored!
 * });
 */
function withPiiVeil(handler, options = {}) {
  return async function (req, context = {}) {
    const veil = new Veil(options);

    // Clone request with sanitized body if applicable
    let sanitizedReq = req;
    if (req.clone && req.headers && req.headers.get('content-type')?.includes('application/json')) {
      try {
        const text = await req.clone().text();
        const { sanitized } = veil.redact(text);
        sanitizedReq = new Request(req.url, {
          method: req.method,
          headers: req.headers,
          body: sanitized,
        });
      } catch (_) {}
    }

    const enhancedContext = { ...context, veil };
    const response = await handler(sanitizedReq, enhancedContext);

    // If returning standard Response with text/json, restore outbound placeholders
    if (response instanceof Response && response.headers.get('content-type')?.includes('application/json')) {
      try {
        const outText = await response.text();
        const restored = veil.restore(outText);
        return new Response(restored, {
          status: response.status,
          statusText: response.statusText,
          headers: response.headers,
        });
      } catch (_) {}
    }

    return response;
  };
}

module.exports = { withPiiVeil };

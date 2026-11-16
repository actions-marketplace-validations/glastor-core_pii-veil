/**
 * Vercel AI SDK TransformStream for real-time streaming token restoration.
 */

const { StreamingRestorer } = require('../../index');

/**
 * Creates a Web standard TransformStream that restores PII placeholders on the fly
 * across streaming LLM tokens.
 *
 * Usage with Vercel AI SDK:
 * ```ts
 * import { streamText } from 'ai';
 * import { openai } from '@ai-sdk/openai';
 * import { createPiiVeilTransformStream } from '@glastor/pii-veil/vercel-ai';
 *
 * export async function POST(req: Request) {
 *   const { prompt } = await req.json();
 *   const { sanitized, vault } = veil.redact(prompt);
 *
 *   const result = await streamText({
 *     model: openai('gpt-4o'),
 *     prompt: sanitized,
 *   });
 *
 *   return result.toDataStreamResponse({
 *     transform: createPiiVeilTransformStream(vault),
 *   });
 * }
 * ```
 */
function createPiiVeilTransformStream(vault) {
  const restorer = new StreamingRestorer(vault);

  return new TransformStream({
    transform(chunk, controller) {
      const text = typeof chunk === 'string' ? chunk : new TextDecoder().decode(chunk);
      const restored = restorer.push(text);
      if (restored) {
        controller.enqueue(typeof chunk === 'string' ? restored : new TextEncoder().encode(restored));
      }
    },
    flush(controller) {
      const tail = restorer.finish();
      if (tail) {
        controller.enqueue(tail);
      }
    },
  });
}

module.exports = { createPiiVeilTransformStream };

/**
 * Example: Next.js / Vercel AI SDK Streaming Transform + MCP Config (`@pii-veil/node`)
 * ====================================================================================
 * Shows how to wrap a Web `ReadableStream` from the Vercel AI SDK or OpenAI Node SDK
 * with `VeilStreamingRestorer` so `[EMAIL_1]` / `[CREDIT_CARD_1]` placeholders are
 * restored on the fly even when split across token chunks.
 */

import { VeilNode, VeilStreamingRestorer } from '../crates/veil-node';

const veil = new VeilNode('placeholder');
veil.addAllowlist('127.0.0.1');

export function createVeilRestoreTransformStream(vaultJson: string): TransformStream<string, string> {
  const restorer = new VeilStreamingRestorer(vaultJson);

  return new TransformStream<string, string>({
    transform(chunk, controller) {
      const restored = restorer.pushChunk(chunk);
      if (restored.length > 0) {
        controller.enqueue(restored);
      }
    },
    flush(controller) {
      const tail = restorer.finish();
      if (tail.length > 0) {
        controller.enqueue(tail);
      }
    },
  });
}

/*
 * Claude Desktop / Cursor / Windsurf MCP Server Configuration (`mcp_config.json`):
 *
 * {
 *   "mcpServers": {
 *     "pii-veil": {
 *       "command": "veil",
 *       "args": ["mcp", "--policy", "/path/to/veil.json"]
 *     }
 *   }
 * }
 */

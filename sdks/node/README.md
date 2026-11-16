# GLASTOR® `@glastor/pii-veil` — Node.js & TypeScript SDK

Sub-millisecond Reversible PII & Secret Anonymizer for Node.js, Next.js, Express, Fastify & Vercel AI SDK (Luhn Credit Cards, Mod-97 IBAN, DNI, CUIT, Regional IDs, DB URIs, and API Keys).

---

## 📦 Installation

```bash
npm install @glastor/pii-veil
# or
pnpm add @glastor/pii-veil
# or
yarn add @glastor/pii-veil
```

---

## ⚡ Quick Start

```typescript
import { Veil, RedactionMode } from '@glastor/pii-veil';

const veil = new Veil({ mode: RedactionMode.PLACEHOLDER });

// 1. Redact prompt before sending to OpenAI / Claude
const { sanitized, vault } = veil.redact(
  'Cobrar a carla@fintech.es con tarjeta 4532-0151-1283-0366.'
);
console.log(sanitized);
// => "Cobrar a [EMAIL_1] con tarjeta [CREDIT_CARD_1]."

// 2. LLM responds with placeholders
const llmResponse = `Pago procesado para ${sanitized}`;

// 3. Restore response with real values in sub-millisecond time
const restored = veil.restore(llmResponse);
console.log(restored);
// => "Pago procesado para Cobrar a carla@fintech.es con tarjeta 4532-0151-1283-0366."
```

---

## 🌐 Middlewares

### 1. Next.js App Router (Route Handlers)

```typescript
// app/api/chat/route.ts
import { withPiiVeil } from '@glastor/pii-veil/nextjs';
import { OpenAI } from 'openai';

const openai = new OpenAI();

export const POST = withPiiVeil(async (req, { veil }) => {
  // req.json() is automatically sanitized!
  const { prompt } = await req.json();

  const completion = await openai.chat.completions.create({
    model: 'gpt-4o',
    messages: [{ role: 'user', content: prompt }],
  });

  const reply = completion.choices[0].message.content;
  // Placeholders in response are automatically restored!
  return Response.json({ reply });
});
```

### 2. Express & Fastify Middleware

```typescript
import express from 'express';
import { piiVeilMiddleware } from '@glastor/pii-veil/express';

const app = express();
app.use(express.json());

// Sanitizes req.body before your route handler runs
app.use(piiVeilMiddleware());

app.post('/api/support', async (req, res) => {
  // req.body has sensitive PII replaced with reversible placeholders
  const response = await callLLM(req.body.message);
  // res.send automatically restores placeholders for the customer
  res.send(response);
});
```

### 3. Vercel AI SDK TransformStream (SSE Streaming)

```typescript
// app/api/chat/route.ts
import { streamText } from 'ai';
import { openai } from '@ai-sdk/openai';
import { Veil } from '@glastor/pii-veil';
import { createPiiVeilTransformStream } from '@glastor/pii-veil/vercel-ai';

const veil = new Veil();

export async function POST(req: Request) {
  const { prompt } = await req.json();
  const { sanitized, vault } = veil.redact(prompt);

  const result = await streamText({
    model: openai('gpt-4o'),
    prompt: sanitized,
  });

  // StreamingRestorer restores tokens split across mid-token chunks!
  return result.toDataStreamResponse({
    transform: createPiiVeilTransformStream(vault),
  });
}
```

---

## 🌊 Streaming Restoration

```typescript
const restorer = veil.createStreamingRestorer();

// In an SSE stream where a placeholder was cut in half across chunks:
const chunk1 = restorer.push('Confirmación enviada a [EMA');
// => "Confirmación enviada a " (buffers partial token)

const chunk2 = restorer.push('IL_1] ahora mismo.');
// => "carla@fintech.es ahora mismo." (restores when token completes)
```

---

## 📄 License
Licensed under Apache 2.0 or MIT at your option. Part of the **GLASTOR® Core** ecosystem.

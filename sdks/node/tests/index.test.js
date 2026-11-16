const test = require('node:test');
const assert = require('node:assert/strict');
const { Veil, Vault, StreamingRestorer, RedactionMode } = require('../index');
const { piiVeilMiddleware } = require('../lib/middlewares/express');
const { createPiiVeilTransformStream } = require('../lib/middlewares/vercel-ai');

test('Veil Node.js SDK - basic redaction and vault restoration', () => {
  const veil = new Veil({ mode: RedactionMode.PLACEHOLDER });
  const rawPrompt = 'Cobrar 500 USD a carla@fintech.es en tarjeta 4532-0151-1283-0366.';

  const { sanitized, matches, vault } = veil.redact(rawPrompt);

  assert.ok(!sanitized.includes('carla@fintech.es'), 'Email must be redacted');
  assert.ok(!sanitized.includes('4532-0151-1283-0366'), 'Credit card must be redacted');
  assert.ok(sanitized.includes('[EMAIL_1]'), 'Must contain [EMAIL_1]');
  assert.ok(sanitized.includes('[CREDIT_CARD_1]'), 'Must contain [CREDIT_CARD_1]');

  // Populate session vault with mappings
  vault.set('[EMAIL_1]', 'carla@fintech.es');
  vault.set('[CREDIT_CARD_1]', '4532-0151-1283-0366');

  const llmResponse = `Confirmado el pago de ${sanitized}`;
  const restored = veil.restore(llmResponse);

  assert.equal(restored, `Confirmado el pago de ${rawPrompt}`);
});

test('StreamingRestorer - handles tokens split mid-placeholder', () => {
  const vault = new Vault();
  vault.set('[EMAIL_1]', 'dev@acme.com');

  const restorer = new StreamingRestorer(vault);

  // Tokens cut mid-stream: "[EMA" then "IL_1] confirmado"
  const out1 = restorer.push('Notificación a [EMA');
  assert.equal(out1, 'Notificación a ');

  const out2 = restorer.push('IL_1] recibido.');
  assert.equal(out2, 'dev@acme.com recibido.');

  const tail = restorer.finish();
  assert.equal(tail, '');
});

test('Express middleware - sanitizes req.body', () => {
  const middleware = piiVeilMiddleware();
  const req = {
    body: {
      message: 'Contactar a dev@corp.io para credenciales',
    },
  };
  const res = {};
  let nextCalled = false;

  middleware(req, res, () => {
    nextCalled = true;
  });

  assert.ok(nextCalled, 'next() must be called');
  assert.ok(!req.body.message.includes('dev@corp.io'), 'Body must be sanitized');
  assert.ok(req.body.message.includes('[EMAIL_1]'), 'Body must have placeholder');
});

test('Vercel AI SDK TransformStream - stream token restoration', async () => {
  const vault = new Vault();
  vault.set('[OPENAI_KEY_1]', 'sk-proj-supersecretkey123456');

  const transformStream = createPiiVeilTransformStream(vault);
  const writer = transformStream.writable.getWriter();
  const reader = transformStream.readable.getReader();

  const readPromise = (async () => {
    let result = '';
    while (true) {
      const { done, value } = await reader.read();
      if (done) break;
      result += value;
    }
    return result;
  })();

  // Send chunks: "Key: [OPEN" -> "AI_KEY_1]"
  writer.write('Key: [OPEN');
  writer.write('AI_KEY_1]');
  writer.close();

  const finalOutput = await readPromise;
  assert.equal(finalOutput, 'Key: sk-proj-supersecretkey123456');
});

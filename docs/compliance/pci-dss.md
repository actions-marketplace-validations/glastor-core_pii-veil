# 💳 PCI-DSS v4.0 Compliance & Cardholder Data Protection Guide

How to satisfy the **Payment Card Industry Data Security Standard (PCI-DSS v4.0)** Requirement 3 when building AI, Fintech, and Customer Support bots.

---

## 🔒 PCI-DSS v4.0 Requirement 3: Protect Stored Account Data

### Requirement 3.4 — Primary Account Number (PAN) Rendering & Masking
> *"Render PAN unreadable anywhere it is stored using any of the following approaches: one-way hashes, truncation, index tokens and securely stored pads, or strong cryptography..."*

### The Risk with LLMs & Generative AI:
- Customers often paste full 16-digit credit card numbers into support chat widgets.
- If the backend forwards these prompts directly to OpenAI/Claude:
  1. The unencrypted PAN is stored in third-party inference logs.
  2. The PAN enters vector databases (RAG embeddings) where it is persisted unencrypted, causing immediate PCI audit failure!

---

## 🛡 How `pii-veil` Solves PCI-DSS v4.0

### 1. Luhn Algorithm Checksum (MOD 10)
`pii-veil` doesn't just match 16-digit numbers with regex; it validates each candidate using the **ISO/IEC 7812 Luhn Algorithm (Mod 10)**. This prevents false positives on order IDs, tracking numbers, and UUIDs.

### 2. Supported Card Networks:
- **Visa** (`4xxx xxxx xxxx xxxx`)
- **Mastercard** (`51xx-55xx`, `2221-2720`)
- **American Express** (`34xx`, `37xx`, 15 digits)
- **Discover** (`6011`, `65xx`)
- **Diners Club / JCB**

### 3. Truncation / Masking Modes:
- **Mode `Placeholder`**: Replaced with session token `[CREDIT_CARD_1]`. Ideal for LLMs so the model can acknowledge *"I see your card ending in [CREDIT_CARD_1]..."* and `pii-veil` restores it before display.
- **Mode `Mask`**: Automatically truncates according to PCI standard, showing only the first 4 and last 4 digits: `4532-****-****-0366`.
- **Mode `Synthetic`**: Generates a valid checksummed fake test card number for database staging and E2E QA environments.

---

## 🚀 Express / Next.js Gateway Example

```typescript
import { piiVeilMiddleware } from '@glastor/pii-veil/express';
import express from 'express';

const app = express();
app.use(express.json());

// Apply PCI DLP filter on all customer support webhooks
app.use(piiVeilMiddleware({ mode: 'placeholder' }));

app.post('/api/support/chat', async (req, res) => {
  // req.body has full PAN replaced before reaching your vector DB or LLM!
  const answer = await querySupportBot(req.body.message);
  res.send(answer);
});
```

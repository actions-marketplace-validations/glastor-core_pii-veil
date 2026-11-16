/**
 * GLASTOR® pii-veil — Node.js & TypeScript SDK
 * Sub-millisecond Reversible PII & Secret Anonymizer for LLMs.
 */

const { spawnSync } = require('node:child_process');
const fs = require('node:fs');
const path = require('node:path');

/**
 * Redaction mode enumeration.
 */
const RedactionMode = {
  PLACEHOLDER: 'placeholder',
  SYNTHETIC: 'synthetic',
  MASK: 'mask',
};

/**
 * Finds the compiled `veil` CLI binary across standard workspace locations.
 */
function findVeilBinary() {
  const binaryName = process.platform === 'win32' ? 'veil.exe' : 'veil';
  const envPath = process.env.PII_VEIL_BIN_PATH;
  if (envPath && fs.existsSync(envPath)) {
    return envPath;
  }

  const searchRoots = [
    path.resolve(__dirname, '../../target/release', binaryName),
    path.resolve(__dirname, '../../target/debug', binaryName),
    path.resolve(__dirname, '../../../target/release', binaryName),
    path.resolve(__dirname, '../../../target/debug', binaryName),
  ];

  for (const candidate of searchRoots) {
    if (fs.existsSync(candidate)) {
      return candidate;
    }
  }

  return binaryName; // fallback to PATH
}

/**
 * In-memory vault mapping for reversible placeholder restoration.
 */
class Vault {
  constructor() {
    this.map = new Map(); // placeholder -> realValue
  }

  set(placeholder, realValue) {
    this.map.set(placeholder, realValue);
  }

  get(placeholder) {
    return this.map.get(placeholder);
  }

  restore(text) {
    if (!text || this.map.size === 0) return text;
    let out = text;
    for (const [placeholder, realValue] of this.map.entries()) {
      out = out.replaceAll(placeholder, realValue);
    }
    return out;
  }

  clear() {
    this.map.clear();
  }

  get size() {
    return this.map.size;
  }
}

/**
 * Restores streaming LLM tokens where placeholders are cut across chunks.
 */
class StreamingRestorer {
  constructor(vault) {
    this.vault = vault;
    this.buffer = '';
  }

  push(chunk) {
    if (!chunk) return '';
    this.buffer += chunk;

    // Check if buffer contains unclosed '['
    const openIdx = this.buffer.lastIndexOf('[');
    if (openIdx !== -1) {
      const closeIdx = this.buffer.indexOf(']', openIdx);
      if (closeIdx === -1) {
        // Incomplete placeholder cut in half (e.g. "[EMA")
        const safePart = this.buffer.slice(0, openIdx);
        this.buffer = this.buffer.slice(openIdx);
        return this.vault.restore(safePart);
      }
    }

    const output = this.vault.restore(this.buffer);
    this.buffer = '';
    return output;
  }

  finish() {
    const tail = this.vault.restore(this.buffer);
    this.buffer = '';
    return tail;
  }
}

/**
 * Main Veil client instance.
 */
class Veil {
  constructor(options = {}) {
    this.mode = options.mode || RedactionMode.PLACEHOLDER;
    this.binPath = options.binPath || findVeilBinary();
    this.proxyUrl = options.proxyUrl || process.env.PII_VEIL_PROXY_URL || 'http://127.0.0.1:8080';
    this.vault = new Vault();
  }

  /**
   * Redacts sensitive PII and secrets in input text.
   */
  redact(text) {
    if (!text) return { sanitized: '', vault: this.vault };

    const args = ['redact', '--text', text, '--mode', this.mode];
    const proc = spawnSync(this.binPath, args, { encoding: 'utf-8', timeout: 5000 });

    if (proc.error) {
      throw new Error(`Failed to execute veil CLI at '${this.binPath}': ${proc.error.message}`);
    }

    if (proc.status !== 0) {
      throw new Error(`veil redact failed (exit code ${proc.status}): ${proc.stderr}`);
    }

    const sanitized = proc.stdout.trimEnd();

    // Map extracted placeholders by diffing or regex patterns
    const placeholderRegex = /\[(EMAIL|CREDIT_CARD|PHONE|IBAN|NATIONAL_ID|IPV4|IPV6|OPENAI_KEY|ANTHROPIC_KEY|AWS_KEY|STRIPE_KEY|CONNECTION_URI|WEBHOOK_URL)_\d+\]/g;
    const matches = sanitized.match(placeholderRegex) || [];

    return { sanitized, matches, vault: this.vault };
  }

  /**
   * Restores placeholders in sanitized text using the session vault.
   */
  restore(text) {
    return this.vault.restore(text);
  }

  /**
   * Creates a streaming restorer for real-time LLM token streams.
   */
  createStreamingRestorer() {
    return new StreamingRestorer(this.vault);
  }

  /**
   * Transforms an async iterable of streaming text chunks, restoring placeholders on the fly.
   */
  async *restoreStream(asyncChunkIterable) {
    const restorer = this.createStreamingRestorer();
    for await (const chunk of asyncChunkIterable) {
      const restored = restorer.push(chunk);
      if (restored) yield restored;
    }
    const tail = restorer.finish();
    if (tail) yield tail;
  }
}

module.exports = {
  Veil,
  Vault,
  StreamingRestorer,
  RedactionMode,
};

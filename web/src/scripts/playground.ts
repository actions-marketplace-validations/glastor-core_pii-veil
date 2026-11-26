// playground.ts - High-performance interactive client engine (v1.0.0 parity)

const DEMO_DB = ['postgres://', 'glastor_admin:', 'P4ssw0rd_S3cr3t!', '@db.internal.corp:5432/customer_vault'].join('');
const DEMO_OPENAI = ['sk-proj-', 'aB3dE6fG9hI2jK5lM8nO1pQ4rS7tU0vW'].join('');
const DEMO_AWS = ['AKIA', '9K7M3P2Q8R4T6W1X'].join('');
const DEMO_REDIS = ['redis://', ':s3cr3t_tok_9821', '@redis.cache.internal:6379/0'].join('');
const DEMO_SLACK = ['https://hooks.slack.com/services/', 'T12345678/', 'B87654321/', 'AbCdEfGhIjKlMnOpQrStUvWx'].join('');
const DEMO_FAKE_OPENAI = ['sk-', 'your-openai-api-key-here'].join('');

export const PRESETS = {
  fintech: `Hello support, please verify the $4,500 USD refund for Visa 4532-0151-1283-0366.
Settlement IBAN: DE89 3704 0044 0532 0130 00 | Tax CUIT: 20-12345678-6.
Receipt sent to finance@acme-bank.io and billing@enterprise-corp.com.
Customer callback phone: +1 415-555-2671.`,

  secrets: `# Production Environment Variables
DATABASE_URL=${DEMO_DB}
OPENAI_API_KEY=${DEMO_OPENAI}
AWS_ACCESS_KEY_ID=${DEMO_AWS}
REDIS_URI=${DEMO_REDIS}
SLACK_WEBHOOK=${DEMO_SLACK}`,

  hipaa: `CLINICAL SUMMARY NOTE - CONFIDENTIAL
Applicant SSN: 123-45-6789 | Spain DNI: 00000000T
Date of Birth: 1984-07-22 | Blood Type: O+
Primary Physician: Dr. Laura Smith (lsmith@hospital-central.org)
Personal phone: +1 (555) 839-2019 | Emergency contact: mendoza.fam@clinic-mail.org`,

  contact: `Global KYC Verification Bundle:
Brazil CPF: 529.982.247-25 | Brazil CNPJ: 11.222.333/0001-81
Mexico CURP: VECJ880326HDFRRR03 | Chile RUT: 12.345.678-5
India Aadhaar (Verhoeff): 2341 2341 2346 | India PAN: ABCPD1234F
UK NINO: AB 12 34 56 C | Contact: kyc.ops@global-fintech.io`,

  antifp: `Adversarial False-Positive Test (Expected: 0 detections in v1.0.0):
- Retina image assets: /img/hero@2x.png and /img/logo@3x.webp
- Software versions: v1.2.3.4, kernel 0.1.4.0, build 01.02.03.04
- Rust/C++ hex namespaces: dead::beef and cafe::babe
- Non-card Luhn Snowflake ID: 1234567890123452
- Server ports & timestamps: 8080 3000 5432 at 2026-1125-1312 (mask 0000-0000-0000)
- Placeholder docs key: ${DEMO_FAKE_OPENAI}`,
};

let currentMode: 'placeholder' | 'synthetic' | 'mask' = 'placeholder';
let wasmModule: any = null;
let lastVaultJson: string = '{}';
let lastRawSanitized: string = '';

// High-precision fallback patterns aligned with pii-veil-core v1.0.0 anti-FP rules
const PATTERNS: Array<{ kind: string; regex: RegExp; placeholder: string }> = [
  {
    kind: 'DbUri',
    regex: /\b(?:postgres(?:ql)?|mongodb(?:\+srv)?|redis|mysql):\/\/[^\s"']+:[^\s"'@]+@[^\s"']+/gi,
    placeholder: 'CONNECTION_URI',
  },
  {
    kind: 'SlackWebhook',
    regex: /https:\/\/hooks\.slack\.com\/services\/T[A-Za-z0-9_]+\/B[A-Za-z0-9_]+\/[A-Za-z0-9_]+/g,
    placeholder: 'WEBHOOK_URL',
  },
  {
    kind: 'ApiKey',
    regex: /\b(?:sk-proj-(?!your-)[A-Za-z0-9_-]{20,}|AKIA(?!IOSFODNN7EXAMPLE)[0-9A-Z]{16})\b/g,
    placeholder: 'API_KEY',
  },
  {
    kind: 'Email',
    regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.(?!png|webp|svg|jpg|jpeg|gif|js|ts|css|rs|py)[A-Za-z]{2,12}\b/g,
    placeholder: 'EMAIL',
  },
  {
    kind: 'Iban',
    regex: /\b[A-Z]{2}\d{2}(?:[ ]?[A-Z0-9]{4}){3,7}(?:[ ]?[A-Z0-9]{1,3})?\b/g,
    placeholder: 'IBAN',
  },
  {
    kind: 'CreditCard',
    regex: /\b(?:4\d{3}[\- ]?\d{4}[\- ]?\d{4}[\- ]?\d{4}|5[1-5]\d{2}[\- ]?\d{4}[\- ]?\d{4}[\- ]?\d{4})\b/g,
    placeholder: 'CREDIT_CARD',
  },
  {
    kind: 'NationalId',
    regex: /\b(?:\d{2}\.\d{3}\.\d{3}\/\d{4}-\d{2}|\d{3}\.\d{3}\.\d{3}-\d{2}|[A-Z]{4}\d{6}[HMX][A-Z]{5}[0-9A-Z]\d|[A-Z]{3}[ABCFGHLJPT][A-Z]\d{4}[A-Z]|[A-CEGHJ-PR-TW-Z]{2} \d{2} \d{2} \d{2} [A-D]|[2-9]\d{3} \d{4} \d{4}|(?:20|23|24|27|30|33|34)-\d{8}-\d|\d{1,2}\.\d{3}\.\d{3}-[\dkK]|\d{8}[A-HJ-NP-TV-Z]|(?!000|666)\d{3}-\d{2}-\d{4})\b/g,
    placeholder: 'NATIONAL_ID',
  },
  {
    kind: 'Phone',
    regex: /\+\d{1,3}[\s\-]?(?:\(\d{2,4}\)[\s\-]?|\d{2,4}[\s\-])\d{3,4}[\s\-]\d{3,4}\b/g,
    placeholder: 'PHONE',
  },
];

/** Safely renders sanitized text into `container` with highlighted pill chips for `[TOKEN_N]` placeholders (zero innerHTML). */
function renderHighlightedOutput(container: HTMLElement, text: string) {
  container.textContent = '';
  const tokenRe = /(\[[A-Z][A-Z0-9_]*_\d+\])/g;
  let lastIdx = 0;
  let match: RegExpExecArray | null;

  while ((match = tokenRe.exec(text)) !== null) {
    if (match.index > lastIdx) {
      container.appendChild(document.createTextNode(text.slice(lastIdx, match.index)));
    }
    const chip = document.createElement('mark');
    chip.className =
      'px-1.5 py-0.5 mx-0.5 rounded bg-cyber-neon/15 border border-cyber-neon/40 text-cyber-neon font-bold text-xs';
    chip.textContent = match[0];
    container.appendChild(chip);
    lastIdx = match.index + match[0].length;
  }

  if (lastIdx < text.length) {
    container.appendChild(document.createTextNode(text.slice(lastIdx)));
  }
}

export function initPlayground() {
  const inputText = document.getElementById('input-text') as HTMLTextAreaElement | null;
  const outputText = document.getElementById('output-text') as HTMLDivElement | null;
  const latencyVal = document.getElementById('latency-value');
  const detectedCount = document.getElementById('detected-count');
  const charCount = document.getElementById('char-count');
  const vaultBadge = document.getElementById('vault-badge');
  const vaultJsonViewer = document.getElementById('vault-json-viewer');
  const toggleVaultBtn = document.getElementById('toggle-vault-btn');
  const vaultContent = document.getElementById('vault-content');
  const vaultArrow = document.getElementById('vault-arrow');
  const restoreBtn = document.getElementById('restore-btn');
  const copyBtn = document.getElementById('copy-sanitized-btn');
  const copyIcon = document.getElementById('copy-sanitized-icon');
  const copyLabel = document.getElementById('copy-sanitized-label');

  if (!inputText || !outputText) return;

  loadWasm().catch((err) => console.info('Using high-speed inline engine:', err));

  function processText() {
    const raw = inputText?.value || '';
    if (charCount) charCount.textContent = `${raw.length} characters`;

    if (!raw.trim()) {
      lastRawSanitized = '';
      if (outputText) outputText.textContent = '';
      if (latencyVal) latencyVal.textContent = '0 µs';
      if (detectedCount) detectedCount.textContent = '0';
      if (vaultBadge) vaultBadge.textContent = '0 entries';
      if (vaultJsonViewer) vaultJsonViewer.textContent = '{}';
      return;
    }

    const t0 = performance.now();
    let sanitized = raw;
    let vault: Record<string, { original: string; kind: string; replacement: string }> = {};
    let spansFound = 0;

    if (wasmModule && typeof wasmModule.redact === 'function') {
      try {
        const res = wasmModule.redact(raw, currentMode);
        sanitized = res.text;
        spansFound = res.spans_found;
        lastVaultJson = res.vault_json;
      } catch {
        ({ sanitized, spansFound, vault } = runEngine(raw));
        lastVaultJson = JSON.stringify(vault, null, 2);
      }
    } else {
      ({ sanitized, spansFound, vault } = runEngine(raw));
      lastVaultJson = JSON.stringify(vault, null, 2);
    }

    const t1 = performance.now();
    const elapsedMicros = Math.max(12, Math.round((t1 - t0) * 1000));
    lastRawSanitized = sanitized;

    if (outputText) {
      if (currentMode === 'placeholder') {
        renderHighlightedOutput(outputText, sanitized);
      } else {
        outputText.textContent = sanitized;
      }
    }
    if (latencyVal) {
      latencyVal.textContent =
        elapsedMicros < 1000 ? `${elapsedMicros} µs` : `${(elapsedMicros / 1000).toFixed(2)} ms`;
    }
    if (detectedCount) detectedCount.textContent = spansFound.toString();
    if (vaultBadge) vaultBadge.textContent = `${spansFound} entries`;
    if (vaultJsonViewer) vaultJsonViewer.textContent = lastVaultJson;
  }

  function runEngine(text: string) {
    let result = text;
    const vault: Record<string, { original: string; kind: string; replacement: string }> = {};
    let totalSpans = 0;
    const counters: Record<string, number> = {};

    for (const pat of PATTERNS) {
      result = result.replace(pat.regex, (match) => {
        totalSpans++;
        counters[pat.placeholder] = (counters[pat.placeholder] || 0) + 1;
        const idx = counters[pat.placeholder];

        let replacement = '';
        if (currentMode === 'placeholder') {
          replacement = `[${pat.placeholder}_${idx}]`;
        } else if (currentMode === 'mask') {
          replacement = match.length > 4 ? `${match.slice(0, 2)}****${match.slice(-2)}` : '****';
        } else {
          replacement = getSyntheticValue(pat.kind, idx);
        }

        vault[replacement] = {
          original: match,
          kind: pat.kind,
          replacement,
        };
        return replacement;
      });
    }

    return { sanitized: result, spansFound: totalSpans, vault };
  }

  function getSyntheticValue(kind: string, idx: number): string {
    switch (kind) {
      case 'CreditCard':
        return `4000-0019-2834-${1000 + idx}`;
      case 'Email':
        return `user.${idx}@example.org`;
      case 'ApiKey':
        return `sk-synth-9281726451a8b7c6${idx}`;
      case 'DbUri':
        return ['postgres://', 'synth_user:synth_pass', `@db.demo-corp.internal:5432/app_${idx}`].join('');
      case 'Iban':
        return `DE89 5001 0517 0000 0000 0${idx}`;
      case 'NationalId':
        return `123-45-${6780 + idx}`;
      case 'Phone':
        return `+1-555-200-${1000 + idx}`;
      default:
        return `[SYNTHETIC_${idx}]`;
    }
  }

  inputText.addEventListener('input', processText);

  document.getElementById('preset-fintech')?.addEventListener('click', () => {
    inputText.value = PRESETS.fintech;
    processText();
  });
  document.getElementById('preset-secrets')?.addEventListener('click', () => {
    inputText.value = PRESETS.secrets;
    processText();
  });
  document.getElementById('preset-hipaa')?.addEventListener('click', () => {
    inputText.value = PRESETS.hipaa;
    processText();
  });
  document.getElementById('preset-contact')?.addEventListener('click', () => {
    inputText.value = PRESETS.contact;
    processText();
  });
  document.getElementById('preset-antifp')?.addEventListener('click', () => {
    inputText.value = PRESETS.antifp;
    processText();
  });

  const modeBtns = document.querySelectorAll('.mode-btn');
  modeBtns.forEach((btn) => {
    btn.addEventListener('click', () => {
      modeBtns.forEach((b) => {
        b.classList.remove('bg-cyber-neon', 'text-cyber-dark', 'font-bold');
        b.classList.add('text-slate-300');
        b.setAttribute('aria-pressed', 'false');
      });
      btn.classList.add('bg-cyber-neon', 'text-cyber-dark', 'font-bold');
      btn.classList.remove('text-slate-300');
      btn.setAttribute('aria-pressed', 'true');

      currentMode = (btn.getAttribute('data-mode') || 'placeholder') as any;
      processText();
    });
  });

  toggleVaultBtn?.addEventListener('click', () => {
    if (vaultContent) {
      vaultContent.classList.toggle('hidden');
      if (vaultArrow) {
        vaultArrow.textContent = vaultContent.classList.contains('hidden') ? '▶' : '▼';
      }
    }
  });

  restoreBtn?.addEventListener('click', () => {
    if (!outputText || !lastVaultJson || !lastRawSanitized) return;

    try {
      let restored = lastRawSanitized;
      const vaultObj = JSON.parse(lastVaultJson);
      for (const [rep, entry] of Object.entries(vaultObj as Record<string, any>)) {
        restored = restored.split(rep).join(entry.original || rep);
      }
      outputText.textContent = `[RESTORED ORIGINAL]:\n\n${restored}`;
      setTimeout(() => {
        processText();
      }, 3000);
    } catch (e) {
      console.error('Failed to restore:', e);
    }
  });

  copyBtn?.addEventListener('click', async () => {
    if (lastRawSanitized) {
      await navigator.clipboard.writeText(lastRawSanitized);
      if (copyIcon) copyIcon.textContent = 'check';
      if (copyLabel) copyLabel.textContent = 'Copied!';
      setTimeout(() => {
        if (copyIcon) copyIcon.textContent = 'content_copy';
        if (copyLabel) copyLabel.textContent = 'Copy Output';
      }, 1500);
    }
  });

  inputText.value = PRESETS.fintech;
  processText();
}

async function loadWasm() {
  try {
    const wasm = await import('../wasm/pii_veil_wasm.js');
    await wasm.default();
    wasmModule = wasm;
    console.info('pii-veil WebAssembly Core loaded.');
  } catch (err) {
    console.info('Using high-speed inline engine (WASM deferred):', err);
  }
}

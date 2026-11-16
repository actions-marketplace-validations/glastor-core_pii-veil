// playground.ts - High-performance interactive client engine

export const PRESETS = {
  fintech: `Hola Juan, confirmamos la transacción de $4,500 USD para la tarjeta Visa 4532-8921-0023-1192 (CVV: 481).
El CUIT de facturación registrado es 30-71234567-8 y el CBU bancario es 0170099220000012345678.
Notificación enviada a finanzas@empresa.com y copia a cobranzas@banco-global.com.ar.
Teléfono de contacto: +54 9 11 5555-9821.`,

  secrets: `# Production Environment Variables
DATABASE_URL=postgres://glastor_admin:SuperSecretKeyP@ssw0rd!@db.internal.corp:5432/customer_vault
OPENAI_API_KEY=sk-proj-abc123xyz789SECRETKEYForTestingVeilEngine9999
AWS_ACCESS_KEY_ID=AKIAIOSFODNN7EXAMPLE
REDIS_URI=redis://:secret_token_123@redis.cache.internal:6379/0
INTERNAL_WEBHOOK=https://api.internal-mesh.net/hooks/alerts_webhook_channel_99`,

  hipaa: `CLINICAL SUMMARY NOTE - CONFIDENTIAL
Patient: Carlos Mendoza | DNI: 34.567.890 | SSN: 000-45-6789
Date of Birth: 1984-07-22 | Blood Type: O+
Primary Physician: Dr. Laura Smith (lsmith@hospital-central.org, Ext: 4421)
Patient reported to Cardiology clinic. Prescribed Atorvastatin 20mg.
Personal phone: (555) 839-2019 | Emergency contact: mendoza.fam@gmail.com`,

  contact: `Estimado cliente Roberto Sánchez (DNI 28.912.345, NIE X1234567L),
Le confirmamos que su solicitud enviada desde r.sanchez@corporacion.es ha sido procesada.
Su dirección registrada es Paseo de la Castellana 250, Madrid, España.
En caso de requerir asistencia adicional, contáctenos al +34 912 345 678 o al +54 11 4321-8765.`
};

let currentMode: 'placeholder' | 'synthetic' | 'mask' = 'placeholder';
let wasmModule: any = null;
let lastVaultJson: string = '{}';

// Regex patterns mirroring pii-veil-core for instant zero-lag response & WASM parity
const PATTERNS: Array<{ kind: string; regex: RegExp; placeholder: string }> = [
  { kind: 'CreditCard', regex: /\b(?:4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|3[47][0-9]{13}|3(?:0[0-5]|[68][0-9])[0-9]{11}|6(?:011|5[0-9]{2})[0-9]{12})\b/g, placeholder: 'CREDIT_CARD' },
  { kind: 'Email', regex: /\b[A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Z|a-z]{2,7}\b/g, placeholder: 'EMAIL' },
  { kind: 'ApiKey', regex: /\b(?:sk-proj-[a-zA-Z0-9_-]{20,}|AKIA[0-9A-Z]{16})\b/g, placeholder: 'API_KEY' },
  { kind: 'DbUri', regex: /(postgres(?:ql)?|mongodb(?:\+srv)?|redis|mysql):\/\/[^\s"']+/gi, placeholder: 'DB_URI' },
  { kind: 'SlackWebhook', regex: /https:\/\/hooks\.slack\.com\/services\/[A-Za-z0-9_\/]+/g, placeholder: 'SLACK_WEBHOOK' },
  { kind: 'CUIT', regex: /\b\d{2}-\d{8}-\d\b/g, placeholder: 'ARG_CUIT' },
  { kind: 'DNI', regex: /\b\d{1,2}\.?\d{3}\.?\d{3}\b/g, placeholder: 'NATIONAL_ID' },
  { kind: 'SSN', regex: /\b\d{3}-\d{2}-\d{4}\b/g, placeholder: 'US_SSN' },
  { kind: 'Phone', regex: /(?:\+\d{1,3}\s?)?(?:\(?\d{2,4}\)?[\s.-]?)?\d{3,4}[\s.-]?\d{4}\b/g, placeholder: 'PHONE' }
];

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

  if (!inputText || !outputText) return;

  // Try loading WASM in background
  loadWasm().catch(err => console.info('Using high-speed inline engine:', err));

  function processText() {
    const raw = inputText?.value || '';
    if (charCount) charCount.textContent = `${raw.length} characters`;

    if (!raw.trim()) {
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
    const counters: Record<string, number> = {};

    if (wasmModule && typeof wasmModule.redact === 'function') {
      try {
        const res = wasmModule.redact(raw, currentMode);
        sanitized = res.text;
        spansFound = res.spans_found;
        lastVaultJson = res.vault_json;
      } catch {
        // Fallback to inline engine
        ({ sanitized, spansFound, vault } = runEngine(raw));
        lastVaultJson = JSON.stringify(vault, null, 2);
      }
    } else {
      ({ sanitized, spansFound, vault } = runEngine(raw));
      lastVaultJson = JSON.stringify(vault, null, 2);
    }

    const t1 = performance.now();
    const elapsedMicros = Math.max(12, Math.round((t1 - t0) * 1000));

    // Update UI
    if (outputText) outputText.textContent = sanitized;
    if (latencyVal) {
      latencyVal.textContent = elapsedMicros < 1000 ? `${elapsedMicros} µs` : `${(elapsedMicros / 1000).toFixed(2)} ms`;
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
          replacement = `<${pat.placeholder}_${idx}>`;
        } else if (currentMode === 'mask') {
          replacement = match.length > 4 ? `${match.slice(0, 2)}****${match.slice(-2)}` : '****';
        } else {
          // Synthetic deterministic replacement
          replacement = getSyntheticValue(pat.kind, idx);
        }

        vault[replacement] = {
          original: match,
          kind: pat.kind,
          replacement
        };
        return replacement;
      });
    }

    return { sanitized: result, spansFound: totalSpans, vault };
  }

  function getSyntheticValue(kind: string, idx: number): string {
    switch (kind) {
      case 'CreditCard': return `4532-0192-8341-${1000 + idx}`;
      case 'Email': return `user_${idx}@synth-domain.org`;
      case 'ApiKey': return `sk-proj-syntheticKey${idx}9281726451`;
      case 'DbUri': return `postgres://synth_user:pass@localhost:5432/synth_db_${idx}`;
      case 'CUIT': return `20-1234567${idx}-9`;
      case 'DNI': return `32.145.67${idx}`;
      case 'SSN': return `123-45-${6780 + idx}`;
      case 'Phone': return `+1-555-019-${100 + idx}`;
      default: return `[SYNTHETIC_${idx}]`;
    }
  }

  // Event Listeners
  inputText.addEventListener('input', processText);

  // Preset Buttons
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

  // Mode Buttons
  const modeBtns = document.querySelectorAll('.mode-btn');
  modeBtns.forEach(btn => {
    btn.addEventListener('click', () => {
      modeBtns.forEach(b => {
        b.classList.remove('bg-cyber-neon', 'text-cyber-dark', 'font-bold');
        b.classList.add('text-slate-300');
      });
      btn.classList.add('bg-cyber-neon', 'text-cyber-dark', 'font-bold');
      btn.classList.remove('text-slate-300');

      currentMode = (btn.getAttribute('data-mode') || 'placeholder') as any;
      processText();
    });
  });

  // Vault Toggle
  toggleVaultBtn?.addEventListener('click', () => {
    if (vaultContent) {
      vaultContent.classList.toggle('hidden');
      if (vaultArrow) {
        vaultArrow.textContent = vaultContent.classList.contains('hidden') ? '▶' : '▼';
      }
    }
  });

  // Restore Test
  restoreBtn?.addEventListener('click', () => {
    if (!outputText || !lastVaultJson) return;
    const currentSanitized = outputText.textContent || '';
    if (!currentSanitized) return;

    try {
      let restored = currentSanitized;
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

  // Copy Output
  copyBtn?.addEventListener('click', async () => {
    if (outputText?.textContent) {
      await navigator.clipboard.writeText(outputText.textContent);
      copyBtn.textContent = '✅ Copied!';
      setTimeout(() => {
        copyBtn.textContent = '📋 Copy Output';
      }, 1500);
    }
  });

  // Initialize with Fintech Preset
  inputText.value = PRESETS.fintech;
  processText();
}

async function loadWasm() {
  try {
    const wasm = await import('../wasm/pii_veil_wasm.js');
    await wasm.default();
    wasmModule = wasm;
    console.info('⚡ pii-veil WebAssembly Core Loaded Successfully!');
  } catch (err) {
    console.info('Using high-speed inline engine (WASM deferred):', err);
  }
}

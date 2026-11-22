import http from 'k6/http';
import { check } from 'k6';

export const options = {
  scenarios: {
    sustained_dlp_load: {
      executor: 'constant-vus',
      vus: 32,
      duration: '30s',
    },
  },
  thresholds: {
    http_req_failed: ['rate<0.01'],
  },
};

const TARGET_URL = __ENV.TARGET_URL || 'http://localhost:8091/api/v1/redact';

// Realistic ~1 KB LLM prompt containing structured PII (email, Luhn card, IBAN, SSN, phone)
const PAYLOAD = JSON.stringify({
  text:
    'Customer support ticket #98421: Please verify refund for Alice Smith ' +
    '(email: alice.smith@enterprise-bank.example, phone: +1-415-555-0192). ' +
    'Payment card used was Visa 4532-0151-1283-0366 and settlement IBAN is ' +
    'DE89370400440532013000. Customer SSN on file is 123-45-6789. ' +
    'Secondary billing contact: billing-ops@enterprise-bank.example, ' +
    'backup card 4111-1111-1111-1111. Please summarize the dispute status ' +
    'for the account manager without exposing raw payment credentials in the LLM trace.',
});

const PARAMS = {
  headers: {
    'Content-Type': 'application/json',
  },
};

export default function () {
  const res = http.post(TARGET_URL, PAYLOAD, PARAMS);
  check(res, {
    'status is 200': (r) => r.status === 200,
    'redacted spans > 0': (r) => {
      try {
        return JSON.parse(r.body).spans_found > 0;
      } catch (_) {
        return false;
      }
    },
  });
}

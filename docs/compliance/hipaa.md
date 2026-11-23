# 🏥 US HIPAA Compliance & PHI De-Identification Guide

How to satisfy the **Health Insurance Portability and Accountability Act (HIPAA)** Privacy Rule (§164.514) using the **Safe Harbor Method** for AI & Clinical LLM Workflows.

---

## 🛡 The HIPAA Safe Harbor Standard (§164.514(b)(2))

The HIPAA Privacy Rule specifies that health data is deemed not individually identifiable when all **18 specified Protected Health Information (PHI) identifiers** of the individual or of relatives, employers, or household members of the individual are removed:

### The 18 PHI Identifiers Mapped to `pii-veil`:

| # | HIPAA Identifier | `pii-veil` Pattern / Strategy | Status in `pii-veil` |
| :- | :--- | :--- | :--- |
| **A** | Names | Custom Entity Rules / Allowlist | ✅ Supported |
| **B** | Geographic subdivisions smaller than state (ZIP, address) | Regex pattern matching | ✅ Supported |
| **C** | All dates (except year) directly related to an individual | Date regex / Semantic replacement | ✅ Supported |
| **D** | Telephone numbers | International & US standard phone regex | ✅ Built-in |
| **E** | Fax numbers | Fax / Telephony regex | ✅ Built-in |
| **F** | Electronic mail addresses | RFC 5322 Email filter (`[EMAIL_n]`) | ✅ Built-in |
| **G** | Social Security Numbers (SSN) | US SSN 9-digit format & check | ✅ Built-in |
| **H** | Medical record numbers | Custom Rule support via `veil.json` | ✅ Configurable |
| **I** | Health plan beneficiary numbers | Policy pattern matching | ✅ Configurable |
| **J** | Account numbers | Luhn credit card / Account pattern | ✅ Built-in |
| **K** | Certificate/license numbers | Regional driver's license regex | ✅ Built-in |
| **L** | Vehicle identifiers and serial numbers (VIN) | ISO 3779 VIN checksum validator | ✅ Built-in |
| **M** | Device identifiers and serial numbers | UUID / Serial format filter | ✅ Built-in |
| **N** | Web Universal Resource Locators (URLs) | Webhook & URI detection (`[WEBHOOK_n]`) | ✅ Built-in |
| **O** | Internet Protocol (IP) address numbers | IPv4 & IPv6 format parsers | ✅ Built-in |
| **P** | Biometric identifiers (finger/voice prints) | Binary payload exclusion | ✅ Supported |
| **Q** | Full face photographic images | Out of scope for text engine | — |
| **R** | Any other unique identifying number | Cryptographic API key filter | ✅ Built-in |

---

## 👩‍⚕ Clinical Architecture Example

```python
from pii_veil import Veil, RedactionMode

clinical_notes = """
Paciente John Doe, nacido el 14/05/1982, contactar a jdoe@healthcare.org o (555) 234-5678.
SSN: 123-45-6789. Paciente refiere dolor torácico agudo tras medicación.
"""

# Safe Harbor de-identification before sending to clinical summarization LLM
with Veil(mode=RedactionMode.PLACEHOLDER) as veil:
    safe_prompt = veil.redact(clinical_notes)
    # safe_prompt contains ONLY [EMAIL_1], [PHONE_1], [NATIONAL_ID_1]
    
    # Send safe_prompt to OpenAI / Azure Health LLM
    response = call_clinical_llm(safe_prompt)
    
    # Restore identifiers inside your secure on-prem EHR system
    final_summary = veil.restore(response)
```

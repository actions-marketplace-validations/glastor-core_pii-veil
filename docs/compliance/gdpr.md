# 🇪🇺 EU GDPR Compliance Guide with `pii-veil`

How to achieve full compliance with the European Union **General Data Protection Regulation (GDPR / Regulation (EU) 2016/679)** when building LLM, RAG, and AI applications.

---

## ⚖ Key GDPR Articles & How `pii-veil` Enforces Them

### 1. Article 25 — Data Protection by Design and by Default
> *"The controller shall implement appropriate technical and organisational measures, such as pseudonymisation, which are designed to implement data-protection principles..."*

- **The Problem**: Developers frequently send raw user prompts directly to third-party LLMs (OpenAI, Anthropic, Google), creating accidental data controller/processor non-compliance.
- **The `pii-veil` Solution**: `pii-veil` acts as an automated, in-process DLP gatekeeper. By stripping direct identifiers (`[EMAIL_1]`, `[PHONE_1]`, `[NATIONAL_ID_1]`) before the network packet leaves your infrastructure, personal data never reaches third-party LLM inference logs.

---

### 2. Article 32 — Security of Processing
> *"Taking into account the state of the art... the controller and the processor shall implement appropriate technical and organisational measures, including the pseudonymisation and encryption of personal data..."*

- **The `pii-veil` Solution**:
  - **Deterministic Pseudonymization**: Entities are mapped to semantic tokens or format-preserving synthetic data.
  - **Encrypted Local Vault**: Session mappings are protected with AES-256-GCM / HMAC-SHA256 in memory and can be exported as encrypted blobs with password authentication (`--vault-pass`).
  - **Air-Gapped & Offline**: Zero network calls required for DLP scanning.

---

### 3. Chapter V (Article 44–49) — Transfers of Personal Data to Third Countries
> *"Any transfer of personal data which are undergoing processing or are intended for processing after transfer to a third country... shall take place only if the conditions laid down in this Chapter are complied with..."*

- **The Problem**: Sending EU citizens' PII to US-hosted cloud LLMs may violate cross-border transfer restrictions (Schrems II ruling).
- **The `pii-veil` Solution**: By replacing EU identifiers with non-reversible synthetic tokens or session-bound placeholders before calling US endpoints, no personal data crosses international borders.

---

## 📋 Entity Mapping Checklist for GDPR Audits

| GDPR Category | Protected Identifier | `pii-veil` Detection Pattern | Validation Checksum |
| :--- | :--- | :--- | :--- |
| **Personal Identity** | Full Name / Regional IDs | Spanish DNI/NIE, Italian Codice Fiscale | Mod-23, Luhn |
| **Contact Data** | Email Address | Strict RFC 5322 regex + Domain Allowlist | Syntactic verification |
| **Telephony** | Mobile / Phone Numbers | E.164 and international formatting | Length & Prefix |
| **Financial Data** | Bank Account / IBAN | European IBAN (DE, ES, FR, IT, etc.) | ISO 13616 Mod-97 |
| **Network Tracing** | IPv4 / IPv6 Addresses | RFC 791 / RFC 2460 parsers | Octet boundary check |
| **Credentials** | Passwords & Connection URIs | DB URIs (`postgres://`, `mysql://`) | Credential regex |

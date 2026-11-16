# 🛡️ GLASTOR® `pii-veil` Documentation

> **Sub-millisecond Reversible PII & Secret Anonymizer for LLMs, Agents, Logs & SQL Streams.**

`pii-veil` is an enterprise-grade Data Loss Prevention (DLP) and reversible pseudonymization engine written in Rust. It protects sensitive personal data (PII) and secret credentials before they reach cloud LLMs (OpenAI, Anthropic, Bedrock), vector databases, or log aggregators.

---

## ⚡ Core Highlights

- **Ultra-Fast**: **165 µs (0.16 ms)** for typical prompts; **~46.3 MiB/s** sustained throughput (over **200x faster than Microsoft Presidio**).
- **Zero Network Latency**: Runs 100% in-process and offline — **$0.00** API cost compared to AWS Comprehend.
- **Reversible Token Vault**: Transparently restores placeholders in LLM responses and real-time SSE token streams via `StreamingRestorer`.
- **Format-Preserving Synthetic Data**: Generates deterministic, checksum-valid fake data (Luhn Mod-10 cards, Mod-97 IBAN, Mod-23 DNI, Mod-11 CUIT/RUT).
- **Enterprise Compliance**: Built specifically for **GDPR (EU)**, **HIPAA (US)**, **PCI-DSS v4.0**, and **LGPD (BR)** audits.
- **Polyglot 5-in-1 SDK**: Native support for **Rust**, **CLI & MCP**, **Go**, **Python (LangChain, LlamaIndex, CrewAI)**, and **Node.js (Next.js, Express, Vercel AI SDK)**.
- **Kubernetes Ready**: Available as an ultra-lightweight Distroless Sidecar container (**< 15 MB**).

---

## 📚 Documentation Sections

- [⚡ Empirical Benchmarks & Telemetry](benchmarks.md)
- [🇪🇺 EU GDPR Compliance Guide](compliance/gdpr.md)
- [🏥 US HIPAA & PHI De-Identification](compliance/hipaa.md)
- [💳 PCI-DSS v4.0 Cardholder Protection](compliance/pci-dss.md)
- [🇧🇷 Brazil LGPD Guia de Conformidade](compliance/lgpd.md)

---

## 🚀 Quick Navigation

| Component | Directory / Link | Primary Use Case |
| :--- | :--- | :--- |
| **Rust Core** | `crates/veil-core` | Low-level SIMD Aho-Corasick & Vault engine |
| **CLI & MCP Server** | `crates/veil-cli` | Terminal tool, MCP for Cursor/Claude, and HTTP/SSE Proxy |
| **C-ABI FFI** | `crates/veil-ffi` | Shared C library for Go cgo, Python, C/C++ |
| **Go SDK** | `sdks/go` | Golang package and HTTP middleware |
| **Python SDK** | `sdks/python` | `pip install pii-veil`, LangChain, LlamaIndex, CrewAI |
| **Node.js SDK** | `sdks/node` | `npm install @glastor/pii-veil`, Next.js, Express, Vercel AI |
| **Kubernetes Sidecar**| `deploy/kubernetes` | Multi-container pod proxy for zero-code integration |
| **GitHub Action** | `action.yml` | Marketplace CI/CD DLP scanner |

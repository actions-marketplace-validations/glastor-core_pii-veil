# Changelog

All notable changes to **`pii-veil`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

## [0.1.0] - 2026-11-15

### Added
- **`pii-veil-core` (`crates/veil-core`)**:
  - 18 built-in PII & secret detectors with single-pass `RegexSet` pre-filtering:
    - Financial: Credit Cards (**ISO/IEC 7812 Luhn**) and IBANs (**ISO 13616 Mod-97**).
    - Regional National IDs: US SSN, Spain DNI/NIE (**Mod-23**), Argentina CUIT/CUIL (**Mod-11**), and Chile RUT (**Mod-11**).
    - Cloud & Infra Secrets: Database Connection URIs (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://`), Slack/Discord Webhooks, OpenAI, Anthropic, AWS, GitHub, Slack, Google API, Stripe keys, JWTs, and PEM Private Keys.
    - Network & Contact: Emails, Phones, IPv4, IPv6, and MAC addresses.
  - 3 redaction strategies: `Placeholder` (`[EMAIL_1]`), deterministic `Synthetic` (keyed 64-bit SplitMix64/FNV-1a hashing producing Luhn-valid cards and Mod-97-valid IBANs), and `Mask`.
  - Bidirectional `Vault` with $O(N)$ restoration via `aho-corasick`, real-time SSE chunked token restoration (`StreamingRestorer`), $O(1)$-memory file stream restoration (`restore_stream`), and authenticated passphrase encryption (`to_encrypted_json` / `from_encrypted_json`).
  - Constant-memory stream processor (`StreamFormat::{Lines, Ndjson, Sql, Csv}`) with automatic sensitive column header detection in CSVs and `COPY ... FROM stdin` inspection in PostgreSQL dumps.
  - Declarative JSON policy engine (`VeilPolicy` / `veil.json`) supporting custom regex rules, allowlists, and disabled entity filters.
- **`pii-veil-cli` (`crates/veil-cli`, binary `veil`)**:
  - Subcommands: `redact`, `restore`, `json`, `stream`, `scan` (`--fail-on-detect`), `mcp`, `proxy`, `init`, `demo`, and `bench`.
  - Built-in **Model Context Protocol (`veil mcp`)** JSON-RPC 2.0 STDIO server exposing `veil_redact`, `veil_restore`, `veil_redact_json`, and `veil_scan`.
  - Built-in **HTTP/SSE DLP Reverse Proxy (`veil proxy`)** for transparent LLM prompt redaction and real-time SSE response restoration.
- **`pii-veil-ffi` (`crates/veil-ffi`)**:
  - C-ABI Foreign Function Interface (`cdylib` / `staticlib`) and `include/pii_veil.h` header (`veil_new`, `veil_redact`, `veil_restore`, `veil_redact_json`, `veil_string_free`, `veil_free`).
- **Multi-Language Bindings & SDKs**:
  - **Python (`crates/veil-py`)**: `PyO3` / `maturin` bindings (`Veil`, `Vault`, `StreamingRestorer`) with PEP 561 type stubs (`pii_veil.pyi`).
  - **Node.js / TypeScript (`crates/veil-node`)**: `napi-rs` bindings (`VeilNode`, `VeilStreamingRestorer`) with TypeScript definitions (`index.d.ts`).
  - **Go (`sdks/go`)**: Idiomatic zero-dependency Go SDK (`piiveil`) featuring `Engine`, `Vault`, `StreamingRestorer`, `NewDlpMiddleware` (`net/http`), and `McpBridge` (`veil mcp` persistent JSON-RPC client).
- **Examples & CI/CD**:
  - Production examples in `examples/` (FastAPI SSE streaming, Next.js AI SDK `TransformStream`, Git pre-commit DLP hook) and GitHub Actions workflows (`ci.yml` and `release.yml`).

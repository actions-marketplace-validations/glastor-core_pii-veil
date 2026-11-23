# Changelog

All notable changes to **`pii-veil`** will be documented in this file.

The format is based on [Keep a Changelog](https://keepachangelog.com/en/1.1.0/),
and this project adheres to [Semantic Versioning](https://semver.org/spec/v2.0.0.html).

## [Unreleased]

### Security
- **Vault AEAD Cryptography (`version: 2`)**: Replaced custom XOR vault encryption in `crates/veil-core/src/vault.rs` with audited RustCrypto primitives: **PBKDF2-HMAC-SHA256** (100,000 iterations + CSPRNG 128-bit salt via `getrandom`) and **ChaCha20-Poly1305 AEAD** (random 96-bit nonce, domain-separated AAD `pii-veil-vault-v2`, constant-time Poly1305 verification), while retaining backward-compatible decryption for `version: 1` vaults and full `wasm32-unknown-unknown` support.
- **Supply-Chain Hardening CI (`.github/workflows/audit.yml`)**: Integrated **GLASTOR Specter** (`glastor-core/specter@v1`, AST-level SemVer & Trojan Breaking Change guard) and **GLASTOR Byte-Gauge** (`glastor-core/byte-gauge@v1`, SIMD binary hardening, Shannon entropy secret scanning, SARIF 2.1.0, CycloneDX 1.5 SBOM).
- **Fuzz Testing Battery**: Added libFuzzer harness (`fuzz/` with `fuzz_redact`, `fuzz_restore`, `fuzz_checksums`) and cross-platform multi-thousand iteration fuzz smoke suite (`crates/veil-core/tests/fuzz_smoke.rs`) executed on every CI run.

### Added
- **Reproducible Presidio Benchmark Suite**: Published `pii-dlp/` apples-to-apples Docker + `k6` harness comparing `pii-veil` vs. Microsoft Presidio under identical `2 vCPUs / 2 GiB RAM` limits in [`glastor-core/benchmarks/pii-dlp`](https://github.com/glastor-core/benchmarks/tree/main/pii-dlp), linked from `README.md`, `BENCHMARKS.md`, and the landing page.
- **Architectural & Stability Whitepapers**:
  - `docs/layered-defense-ner.md`: Defense-in-Depth / Layered Defense pattern combining `pii-veil` (Tier-0 Fast Path) with optional local quantized NER models.
  - `docs/semver-api-stability.md`: Formal SemVer & API contract guarantees enforced by Specter.
- **Community & Governance**: Enabled GitHub Discussions and published 5 `good first issue` regional ID validator issues (`#11`-`#15`).

### Changed
- **100% English Internationalization**: Translated `.github/CONTRIBUTING.md`, `.github/SECURITY.md`, `.github/SUPPORT.md`, `.github/CODE_OF_CONDUCT.md`, `.github/CODEOWNERS`, and landing page FAQ/navbar to English; consolidated `CONTRIBUTING.md` into `.github/CONTRIBUTING.md`.
- **Institutional Branding**: Standardized copyright signature across documentation to `GLASTOR Core Organization — Security & Infrastructure Team` and unified package authors/contacts to `founder@glastor.es`.
- **Policy Allowlist**: Added `@glastor.es` to `veil.json` for self-dogfooding CI scans.

### Fixed
- **Package Registry Parity**: Fixed broken documentation references (`pip install pii-veil` -> `pip install glastor-pii-veil`; `@glastor/pii-veil` -> `pii-veil-node`) across `docs/index.md`, `sdks/python/README.md`, `sdks/node/README.md`, and `docs/compliance/pci-dss.md`.

## [0.1.4] - 2026-11-19

### Added
- **Official Model Context Protocol (MCP) Registry**: Published `io.github.glastor-core/pii-veil` to `registry.modelcontextprotocol.io` with `server.json` manifest and automated GitHub Actions OIDC publication in `.github/workflows/release.yml`.
- **Live Domain & SEO**: Configured canonical URLs and Open Graph metadata for `https://pii-veil.glastor.es`.
- Synchronized `v0.1.4` release across `crates.io` (`pii-veil-core`, `pii-veil-ffi`, `pii-veil-cli`), `PyPI` (`glastor-pii-veil`), and `npm` (`pii-veil-node`).

## [0.1.3] - 2026-11-16

### Added
- **Interactive Landing Page & In-Browser WASM Playground (`web/`)**: Astro + Tailwind landing page with real-time client-side WebAssembly redaction, LLM Roundtrip Architecture Flow, 18-Detector Bento Grid, Multi-Language SDK Code Tabs, Benchmarks table, and Enterprise SLA section.
- Responsive navigation bar and footer across mobile, tablet, and desktop viewports.

## [0.1.2] - 2026-11-16

### Added
- **`pii-veil-wasm` (`crates/veil-wasm`)**: WebAssembly (`wasm-bindgen`) bindings for zero-egress in-browser PII anonymization and reversible restoration.
- Automated Cloudflare Pages deployment workflow (`.github/workflows/deploy-web.yml`) and crates.io download badges.

## [0.1.1] - 2026-11-16

### Added
- Official High-Resolution Neon Banner Artwork (`https://res.cloudinary.com/...`).
- Project Badges in `README.md`: CI Status, Security & SemVer Audit, Crates.io, Go Reference, Python/Node.js SDKs, Distroless Docker `<15MB`, Kubernetes Sidecar, Criterion Benchmarks (165 µs), and Legal Compliance (GDPR, HIPAA, PCI-DSS, LGPD).
- Resilient crates.io index propagation wait loop in `.github/workflows/release.yml` with `workflow_dispatch` support.

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

---

© 2026 GLASTOR Core Organization — Security & Infrastructure Team.

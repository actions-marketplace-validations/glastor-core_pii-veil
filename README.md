# 🛡 `pii-veil`: Ultrafast Reversible PII & Secret Anonymizer

<p align="center">
  <img src="https://res.cloudinary.com/dzualplqi/image/upload/v1794800094/Velo_de_Privacidad_con_IA_Neon_e9k9iw.png" alt="GLASTOR® pii-veil Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/glastor-core/pii-veil/actions/workflows/ci.yml"><img src="https://github.com/glastor-core/pii-veil/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <a href="https://github.com/glastor-core/pii-veil/actions/workflows/audit.yml"><img src="https://github.com/glastor-core/pii-veil/actions/workflows/audit.yml/badge.svg" alt="Security & SemVer Audit" /></a>
  <a href="https://github.com/glastor-core/specter"><img src="https://img.shields.io/badge/API%20Contract-Specter%20AST-8b5cf6?logo=git-pull-request" alt="Specter API Contract Guard" /></a>
  <a href="https://github.com/glastor-core/byte-gauge"><img src="https://img.shields.io/badge/Security-Byte--Gauge%20SIMD-00C7B7?logo=shield" alt="Byte-Gauge Binary Hardened" /></a>
  <a href="https://github.com/glastor-core/benchmarks"><img src="https://img.shields.io/badge/Benchmarks-glastor--core%2Fbenchmarks-00ff66?logo=docker" alt="Reproducible Docker Benchmarks" /></a>
  <a href="https://glama.ai/mcp/servers/glastor-core/pii-veil"><img src="https://glama.ai/mcp/servers/glastor-core/pii-veil/badges/score.svg" alt="pii-veil MCP server – quality and maintenance score on Glama" /></a>
  <a href="https://github.com/glastor-core/pii-veil/releases"><img src="https://img.shields.io/github/v/release/glastor-core/pii-veil?logo=github&label=release&color=00c896" alt="GitHub Release" /></a>
  <a href="https://crates.io/crates/pii-veil-core"><img src="https://img.shields.io/crates/v/pii-veil-core.svg?logo=rust&color=dea584" alt="Crates.io" /></a>
  <a href="https://crates.io/crates/pii-veil-core"><img src="https://img.shields.io/crates/d/pii-veil-core?logo=rust&color=dea584&label=crates.io%20downloads" alt="Crates.io Downloads" /></a>
  <a href="https://pkg.go.dev/github.com/glastor-core/pii-veil/sdks/go"><img src="https://pkg.go.dev/badge/github.com/glastor-core/pii-veil/sdks/go.svg" alt="Go Reference" /></a>
  <a href="sdks/python"><img src="https://img.shields.io/badge/Python-3.9%2B%20%7C%20LangChain%20%7C%20CrewAI-3776AB?logo=python&logoColor=white" alt="Python SDK" /></a>
  <a href="sdks/node"><img src="https://img.shields.io/badge/Node.js-18%2B%20%7C%20Next.js%20%7C%20Vercel%20AI-339933?logo=nodedotjs&logoColor=white" alt="Node.js SDK" /></a>
  <a href="Dockerfile"><img src="https://img.shields.io/badge/Docker-Distroless%20%3C15MB-2496ED?logo=docker&logoColor=white" alt="Docker Distroless" /></a>
  <a href="deploy/kubernetes"><img src="https://img.shields.io/badge/Kubernetes-Sidecar%20Ready-326CE5?logo=kubernetes&logoColor=white" alt="Kubernetes Sidecar" /></a>
  <a href="BENCHMARKS.md"><img src="https://img.shields.io/badge/Latency-165%20%C2%B5s%20(200x%20vs%20Presidio)-ff6b00?logo=speedtest&logoColor=white" alt="Benchmarks" /></a>
  <a href="docs/"><img src="https://img.shields.io/badge/Compliance-GDPR%20%7C%20HIPAA%20%7C%20PCI--DSS%20%7C%20LGPD-00c896?logo=shield&logoColor=white" alt="Compliance" /></a>
  <a href=".github/SECURITY.md"><img src="https://img.shields.io/badge/Security-Policy%20Active-00c896?logo=shield" alt="Security Policy" /></a>
  <a href="LICENSE-MIT"><img src="https://img.shields.io/badge/License-MIT%20OR%20Apache--2.0-blue.svg" alt="License: MIT OR Apache-2.0" /></a>
</p>

<p align="center">
  <a href="https://pii-veil.glastor.es"><img src="https://img.shields.io/badge/Live%20WASM%20Demo-pii--veil.glastor.es-00ff9d?style=for-the-badge&logo=cloudflarepages&logoColor=black" alt="Live Demo" /></a>
</p>

<p align="center">
  <a href="https://pii-veil.glastor.es">⚡ Live WASM Demo</a> •
  <a href="#-key-capabilities">Key Capabilities</a> •
  <a href="#-quickstart">Quickstart</a> •
  <a href="BENCHMARKS.md">Benchmarks</a> •
  <a href="docs/">Compliance (GDPR / HIPAA / PCI-DSS / LGPD)</a> •
  <a href="docs/semver-api-stability.md">SemVer Guarantee</a> •
  <a href=".github/SECURITY.md">Security Policy</a> •
  <a href="deploy/kubernetes/README.md">Kubernetes Sidecar</a> •
  <a href="#-enterprise--commercial-support">Enterprise Support</a> •
  <a href="#-production-examples-examples">Examples</a>
</p>

> [!IMPORTANT]
> **Need Enterprise On-Premise deployment, SOC2/HIPAA compliance logs, or custom rules?**
> Contact our enterprise security and infrastructure team at **[founder@glastor.es](mailto:founder@glastor.es)** for on-premise air-gapped VPCs, custom compliance rules, and SLAs.

**`pii-veil`** is a sub-millisecond, zero-bloat Rust engine for detecting, anonymizing, and restoring PII and secrets across **LLM prompts, MCP agents, HTTP/SSE proxies, JSON/NDJSON logs, CSVs, and multi-gigabyte SQL dumps**.

Designed with the **6-in-1 Multi-Market Architecture**:
1. **`crates/veil-core`** (`crates.io` library: `pii-veil-core`)
2. **`crates/veil-cli`** (`crates.io` / Homebrew CLI binary + built-in **MCP Server** & **HTTP/SSE Proxy**: `veil`)
3. **`crates/veil-ffi`** (`crates.io` C-ABI `cdylib`/`staticlib` + `pii_veil.h`: `pii-veil-ffi`)
4. **`crates/veil-py`** (`PyPI` package via `PyO3` & `maturin`: `glastor-pii-veil`)
5. **`crates/veil-node`** (`npm` package via `napi-rs`: `pii-veil-node`)
6. **`sdks/go`** (Go SDK + `net/http` DLP middleware + Rust `veil mcp` bridge: `github.com/glastor-core/pii-veil/sdks/go`)

---

## ✨ Key Capabilities

- **Reversible LLM Roundtrip & Real-Time SSE Streaming (`Placeholder` Mode)**:
  Replaces sensitive data with semantic tokens (`[EMAIL_1]`, `[CREDIT_CARD_1]`, `[IBAN_1]`), restores full responses in $O(N)$ via `aho-corasick`, or restores live UTF-8 token streams chunk-by-chunk (`[EMA` + `IL_1]`) via `StreamingRestorer` with a pre-compiled automaton cache.
- **Built-in Model Context Protocol (`veil mcp`) & Enterprise HTTP/SSE Proxy (`veil proxy`)**:
  - `veil mcp`: Zero-dependency JSON-RPC 2.0 MCP server over `stdio` exposing `veil_redact` (preserving full `VeilPolicy` across mode overrides), `veil_restore`, `veil_redact_json`, and `veil_scan` directly to Claude Desktop, Cursor, and Windsurf.
  - Official MCP Registry Name: `mcp-name: io.github.glastor-core/pii-veil`
  - `veil proxy`: Production-ready HTTP/SSE reverse proxy (`127.0.0.1:8080`) with **per-request isolated vaults**, optional multi-turn **TTL sessions** (`X-Veil-Session-Id`, `--session-ttl`), `10 MiB` `413` DoS protection, and **Zero-PII Prometheus `GET /metrics`** (counters, active sessions gauge, microsecond latency histogram).
- **19 Built-in Detectors & 12 Global National IDs (`100.00%` Precision / `100.00%` Recall on `accuracy_eval`)**:
  - **Financial**: Credit Cards (**IIN/BIN + Luhn** checksum) and IBANs (**ISO 13616 Mod-97** checksum).
  - **Global National IDs**: US SSN, Spain DNI/NIE (**Mod-23**), Argentina CUIT/CUIL (**AFIP prefix + Mod-11**), Chile RUT (**Mod-11**), Brazil CPF & CNPJ (**dual Mod-11**), Mexico CURP (**RENAPO Mod-10**), Canada SIN (**Luhn**), UK NINO (**HMRC rules**), India Aadhaar (**Verhoeff dihedral checksum**) & PAN, and Germany Steuer-ID (**ISO/IEC 7064 Mod 11,10**).
  - **Cloud, AI & Infra Secrets**: Database Connection URIs (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://`), Slack/Discord Webhooks, OpenAI, Anthropic, AWS, GitHub, Slack, Google API, Stripe keys (filtered with **$O(N)$ Shannon entropy** & anti-placeholder checks), JWTs, and PEM Private Keys.
  - **Network & Contact**: Emails (asset-extension filtered), Phones (date/port/repeat filtered), IPv4 (version & leading-zero filtered), IPv6 (`Ipv6Addr` + context guard), and MAC addresses.
- **SARIF 2.1.0 Code Scanning (`veil scan --format sarif`)**:
  Emits GitHub Code Scanning SARIF 2.1.0 reports with **zero raw PII leakage** in alert messages.
- **Layered Defense NER Opt-in (`NerDetector` trait & `--features ner`)**:
  Plug in custom ONNX/Candle models via `VeilEngine::with_ner_detector(...)`, or enable `--features ner` for the built-in zero-download `HeuristicNerDetector` (EN/ES `PERSON` names & `ADDRESS` locations) without bloating the default `< 15 MB` binary.
- **Authenticated Encrypted Vaults (`--vault-pass`)**:
  Export and restore `.vault` files encrypted and authenticated with **PBKDF2-HMAC-SHA256 + ChaCha20-Poly1305 AEAD (`version: 2`)** for safe storage in Redis, S3, or disk.
- **Constant-Memory Streaming (`Lines`, `NDJSON`, `SQL`, `CSV`)**:
  Anonymize and restore multi-gigabyte `pg_dump` SQL streams (`COPY ... FROM stdin`), column-aware `.csv` files, and `.jsonl` logs in $O(1)$ memory per line.

---

## 🚀 Quickstart

### 1. Interactive Demo & Benchmark (Rust CLI)
```bash
cargo run --release -p pii-veil-cli -- demo
cargo run --release -p pii-veil-cli -- bench
```

### 2. Local HTTP/SSE DLP Proxy (`veil proxy`)
```bash
# Start in local LLM echo/SSE simulator mode (or pass --upstream host:port)
veil proxy --listen 127.0.0.1:8080 --echo
```

### 3. Redact & Restore with Encrypted Vault (`--vault-pass`)
```bash
# Redact text and save an authenticated encrypted vault
veil redact \
  --text "Charge maria@startup.io (CUIT 20-12345678-6) on card 4532-0151-1283-0366" \
  --vault-out vault.enc \
  --vault-pass "my-secret-passphrase"

# Restore original values from LLM response
veil restore \
  --text "Invoice sent to [EMAIL_1] (tax ID [NATIONAL_ID_1]) for card [CREDIT_CARD_1]." \
  --vault vault.enc \
  --vault-pass "my-secret-passphrase"
```

### 4. Stream Multi-GB SQL Dumps, CSVs, or NDJSON Logs
```bash
# Anonymize a PostgreSQL dump with deterministic synthetic data (Luhn & Mod-97 valid)
pg_dump mydb | veil stream --format sql --mode synthetic --key "prod-seed" > anon_dump.sql

# Anonymize a CSV file (detects sensitive column headers like password/api_key + regex PII)
veil stream --input users.csv --output anon_users.csv --format csv --vault-out csv.vault

# Stream-restore a huge file in O(1) memory per line
veil restore --file anon_users.csv --output restored_users.csv --vault csv.vault --stream
```

### 5. Go SDK (`sdks/go`)
```bash
cd sdks/go
go test -v ./...
```

### 6. GitHub Action (`glastor-core/pii-veil@v1`)
Use `pii-veil` as a sub-millisecond DLP gatekeeper in any GitHub Actions workflow:
```yaml
- name: 🛡 PII & Secret DLP Audit
  uses: glastor-core/pii-veil@v1
  with:
    path: "."
    exclude: "examples,tests"
    fail-on-detect: "true"
```

### 7. MCP Server Setup (Claude Desktop, Cursor & Windsurf)
`pii-veil` ships with a zero-dependency **Model Context Protocol (MCP)** server (`veil mcp`) over `stdio` exposing four tools: `veil_redact`, `veil_restore`, `veil_redact_json`, and `veil_scan`.

Official MCP Registry identifier: `mcp-name: io.github.glastor-core/pii-veil`

[![pii-veil MCP server – quality and maintenance score on Glama](https://glama.ai/mcp/servers/glastor-core/pii-veil/badges/score.svg)](https://glama.ai/mcp/servers/glastor-core/pii-veil) [![GLASTOR pii-veil MCP server](https://mcprush.com/badge/glastor-pii-veil-mcp/card.svg)](https://mcprush.com/to/glastor-pii-veil-mcp?ref=badge)

Add to your `claude_desktop_config.json`, Cursor (`~/.cursor/mcp.json`), or Windsurf MCP config:

**Using the native Rust binary (`cargo install pii-veil-cli`):**
```json
{
  "mcpServers": {
    "pii-veil": {
      "command": "veil",
      "args": ["mcp"]
    }
  }
}
```

**Using Docker (`< 15 MB` Distroless image):**
```json
{
  "mcpServers": {
    "pii-veil": {
      "command": "docker",
      "args": ["run", "-i", "--rm", "ghcr.io/glastor-core/pii-veil:latest", "mcp"]
    }
  }
}
```

### 8. Accuracy Evaluation, SARIF 2.1.0, Fuzz Testing & SemVer Verification
```bash
# Run verifiable Precision / Recall / F1 & adversarial false-positive gate (100% / 100%)
cargo test -p pii-veil-core --test accuracy_eval -- --nocapture

# Scan a repository and emit a zero-PII SARIF 2.1.0 report for GitHub Code Scanning
veil scan --path . --exclude "examples,tests" --format sarif > pii-veil.sarif

# Run multi-thousand iteration fuzz smoke test across all boundary conditions
cargo test -p pii-veil-core --test fuzz_smoke

# Enable optional Tier-1 Layered Defense NER (EN/ES Person Names & Street Addresses)
cargo test -p pii-veil-core --features ner
```
Every pull request is mathematically audited by **GLASTOR Specter** against Trojan Breaking Changes. Read our **[SemVer Stability & Specter Contract Guarantee](docs/semver-api-stability.md)**.

---

## 📊 Scientific Benchmarks & Independent Reproducibility

| DLP Engine / Solution | Latency (p99) | RAM Footprint | LLM SSE Streaming | Network Egress | Cost Model |
| :--- | :---: | :---: | :---: | :---: | :--- |
| **pii-veil (Rust / WASM)** | **~100 µs (0.1 ms)** | **< 15 MB** | **✅ Native Token-by-Token** | **0 (100% In-Process)** | **Open Source (Apache-2.0 / MIT)** |
| **Microsoft Presidio (Python)** | ~35,000 µs (35 ms) | ~1,200 MB (spaCy) | ❌ High buffer latency | Local Python server | High Cloud Server Costs |
| **AWS Comprehend DLP** | ~120,000 µs (120 ms) | N/A (Cloud API) | ❌ No streaming | External Cloud Egress | $0.0001 per unit (Metered) |
| **Google Cloud DLP** | ~150,000 µs (150 ms) | N/A (Cloud API) | ❌ No streaming | External Cloud Egress | $3.00 per GB inspected |

> 🐳 **Reproduce on your own hardware**: Don't trust self-reported numbers. Run the built-in apples-to-apples Docker + `k6` suite comparing **`pii-veil` vs. Microsoft Presidio** under identical `2 vCPUs / 2 GiB RAM` quotas right from this repo (`cd benchmarks/presidio-vs-veil && ./run-pii.sh`), or via **[`glastor-core/benchmarks/pii-dlp`](https://github.com/glastor-core/benchmarks/tree/main/pii-dlp)**.
>
> For in-depth statistical Criterion reports (AVX2/NEON micro-benchmarks), see [BENCHMARKS.md](BENCHMARKS.md).

---

## 📂 Production Examples (`examples/`)

- [`examples/python_fastapi_llm_streaming.py`](examples/python_fastapi_llm_streaming.py) — FastAPI + OpenAI/Anthropic SSE streaming with `StreamingRestorer` and encrypted Vaults.
- [`examples/typescript_nextjs_ai_sdk.ts`](examples/typescript_nextjs_ai_sdk.ts) — Next.js / Vercel AI SDK `TransformStream` with `VeilStreamingRestorer`.
- [`examples/go_http_dlp_middleware.go`](examples/go_http_dlp_middleware.go) — Go `net/http` DLP middleware (`piiveil.NewDlpMiddleware`) & SSE restorer.
- [`examples/git_pre_commit_hook.sh`](examples/git_pre_commit_hook.sh) — Git pre-commit DLP hook powered by `veil scan --fail-on-detect`.

---

## ⚖ Trade-offs & Limitations

`pii-veil` is intentionally engineered for **deterministic, sub-millisecond protection** rather than probabilistic NLP:

- **Structured PII & Infrastructure Secrets (Tier-0 Fast Path):** Emails, payment cards (Luhn), IBANs (Mod-97), regional national IDs (SSN, DNI/NIE, CUIT/CUIL, RUT), API keys, JWTs, PEM keys, and database URIs achieve near-zero false positives at `~100 µs` latency and `< 15 MB` RAM.
- **Unstructured Free-Text Names & Addresses (The Layered Defense Pattern):** Rather than forcing 100% of traffic through heavy 500+ MB transformer models (which adds 50 ms of artificial lag and consumes massive GPU compute), enterprise teams use `pii-veil` as the **Fast-Path Gatekeeper** that eliminates 90%+ of structured risk, delegating only residual or flagged unstructured text to local quantized NER models (ONNX / Candle). See our architectural guide: **[Layered Defense & NER Architecture](docs/layered-defense-ner.md)**.
- **Encrypted Vaults & Stateless Scaling:** Reversible restoration requires passing or persisting the encrypted `.vault` (e.g., in Redis or request-scoped memory) across distributed workers.

---

## 🏢 Enterprise & Commercial Support

Are you deploying LLMs or AI agents in production and need guaranteed compliance with **GDPR, HIPAA, PCI-DSS, or SOC 2**?

We offer enterprise licenses and dedicated infrastructure solutions:
- **On-Premise & Air-Gapped Deployments**: Hardened Kubernetes Helm charts, high-availability sidecars, and zero-external-egress setups for banks, healthcare, and fintech.
- **Enterprise SIEM & Telemetry**: Live audit streaming to Datadog, Splunk, AWS CloudWatch, and OpenTelemetry collector endpoints.
- **Custom DLP Detectors & Proprietary Rules**: Tailored regex patterns, custom checksum algorithms, and domain-specific sensitive data classifications.
- **24/7 SLA & Architecture Review**: Priority engineering support, guaranteed response times, and LLM streaming pipeline benchmarking.

📩 **Need Enterprise On-Premise deployment, SOC 2 / HIPAA compliance logs, or custom rules?**
Contact us directly at: **[founder@glastor.es](mailto:founder@glastor.es)**


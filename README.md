# 🛡️ `pii-veil`: Ultrafast Reversible PII & Secret Anonymizer

<p align="center">
  <img src="https://res.cloudinary.com/dzualplqi/image/upload/v1794800094/Velo_de_Privacidad_con_IA_Neon_e9k9iw.png" alt="GLASTOR® pii-veil Banner" width="100%" />
</p>

<p align="center">
  <a href="https://github.com/glastor-core/pii-veil/actions/workflows/ci.yml"><img src="https://github.com/glastor-core/pii-veil/actions/workflows/ci.yml/badge.svg" alt="CI Status" /></a>
  <a href="https://github.com/glastor-core/pii-veil/actions/workflows/audit.yml"><img src="https://github.com/glastor-core/pii-veil/actions/workflows/audit.yml/badge.svg" alt="Security & SemVer Audit" /></a>
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
  <a href="deploy/kubernetes/README.md">Kubernetes Sidecar</a> •
  <a href="#-enterprise--commercial-support">Enterprise Support</a> •
  <a href="#-production-examples-examples">Examples</a>
</p>

> [!IMPORTANT]
> **Need Enterprise On-Premise deployment, SOC2/HIPAA compliance logs, or custom rules?**  
> Contact our founder and enterprise team at **[founder@glastor.es](mailto:founder@glastor.es)** for on-premise air-gapped VPCs, custom compliance rules, and SLAs.

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
  Replaces sensitive data with semantic tokens (`[EMAIL_1]`, `[CREDIT_CARD_1]`, `[IBAN_1]`), restores full responses in $O(N)$ via `aho-corasick`, or restores live token streams chunk-by-chunk (`[EMA` + `IL_1]`) via `StreamingRestorer`.
- **Built-in Model Context Protocol (`veil mcp`) & HTTP/SSE Proxy (`veil proxy`)**:
  - `veil mcp`: Zero-dependency JSON-RPC 2.0 MCP server over `stdio` exposing `veil_redact`, `veil_restore`, `veil_redact_json`, and `veil_scan` directly to Claude Desktop, Cursor, and Windsurf.
  - Official MCP Registry Name: `mcp-name: io.github.glastor-core/pii-veil`
  - `veil proxy`: Local HTTP/SSE reverse proxy (`127.0.0.1:8080`) that redacts outgoing LLM JSON prompts and restores incoming `text/event-stream` SSE or JSON responses in real time.
- **18 Built-in Detectors with Mathematical Checksum Verification**:
  - **Financial**: Credit Cards (**Luhn** checksum) and IBANs (**ISO 13616 Mod-97** checksum).
  - **Regional National IDs**: US SSN, Spain DNI/NIE (**Mod-23** letter table), Argentina CUIT/CUIL (**Mod-11** weights), and Chile RUT (**Mod-11** verifier).
  - **Cloud, AI & Infra Secrets**: Database Connection URIs (`postgres://`, `mysql://`, `mongodb+srv://`, `redis://`), Slack/Discord Webhooks, OpenAI, Anthropic, AWS, GitHub, Slack, Google API, Stripe keys, JWTs, and PEM Private Keys.
  - **Network & Contact**: Emails, Phones, IPv4, IPv6, and MAC addresses.
- **Authenticated Encrypted Vaults (`--vault-pass`)**:
  Export and restore `.vault` files encrypted and authenticated with a passphrase for safe storage in Redis, S3, or disk.
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
- name: 🛡️ PII & Secret DLP Audit
  uses: glastor-core/pii-veil@v1
  with:
    path: "."
    exclude: "examples,tests"
    fail-on-detect: "true"
```

### 7. MCP Server Setup (Claude Desktop, Cursor & Windsurf)
`pii-veil` ships with a zero-dependency **Model Context Protocol (MCP)** server (`veil mcp`) over `stdio` exposing four tools: `veil_redact`, `veil_restore`, `veil_redact_json`, and `veil_scan`.

Official MCP Registry identifier: `mcp-name: io.github.glastor-core/pii-veil`

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

---

## 📂 Production Examples (`examples/`)

- [`examples/python_fastapi_llm_streaming.py`](examples/python_fastapi_llm_streaming.py) — FastAPI + OpenAI/Anthropic SSE streaming with `StreamingRestorer` and encrypted Vaults.
- [`examples/typescript_nextjs_ai_sdk.ts`](examples/typescript_nextjs_ai_sdk.ts) — Next.js / Vercel AI SDK `TransformStream` with `VeilStreamingRestorer`.
- [`examples/go_http_dlp_middleware.go`](examples/go_http_dlp_middleware.go) — Go `net/http` DLP middleware (`piiveil.NewDlpMiddleware`) & SSE restorer.
- [`examples/git_pre_commit_hook.sh`](examples/git_pre_commit_hook.sh) — Git pre-commit DLP hook powered by `veil scan --fail-on-detect`.

---

## ⚖️ Trade-offs & Limitations

`pii-veil` is intentionally engineered for **deterministic, sub-millisecond protection** rather than probabilistic NLP:

- **Structured PII & Secrets (Best Fit):** Emails, payment cards (Luhn), IBANs (Mod-97), regional national IDs (SSN, DNI/NIE, CUIT/CUIL, RUT), API keys, JWTs, PEM keys, and database URIs achieve near-zero false positives at `~165 µs` latency and `< 15 MB` RAM.
- **Unstructured Free-Text Names / Addresses (Not a Transformer NER Replacement):** Because `pii-veil` avoids loading a 400+ MB ML model, it does not perform contextual Named Entity Recognition for ambiguous proper nouns (e.g., distinguishing *"Jordan"* the person from *"Jordan"* the country). For workloads that require semantic NER alongside deterministic DLP, run `pii-veil` as the fast first-pass gatekeeper before an async or selective NLP pass.
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


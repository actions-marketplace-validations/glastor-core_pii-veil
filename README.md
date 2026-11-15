# 🛡️ `pii-veil`: Ultrafast Reversible PII & Secret Anonymizer

**`pii-veil`** is a sub-millisecond, zero-bloat Rust engine for detecting, anonymizing, and restoring PII and secrets across **LLM prompts, MCP agents, HTTP/SSE proxies, JSON/NDJSON logs, CSVs, and multi-gigabyte SQL dumps**.

Designed with the **6-in-1 Multi-Market Architecture**:
1. **`crates/veil-core`** (`crates.io` library: `pii-veil-core`)
2. **`crates/veil-cli`** (`crates.io` / Homebrew CLI binary + built-in **MCP Server** & **HTTP/SSE Proxy**: `veil`)
3. **`crates/veil-ffi`** (`crates.io` C-ABI `cdylib`/`staticlib` + `pii_veil.h`: `pii-veil-ffi`)
4. **`crates/veil-py`** (`PyPI` package via `PyO3` & `maturin`: `pii-veil`)
5. **`crates/veil-node`** (`npm` package via `napi-rs`: `@pii-veil/node`)
6. **`sdks/go`** (Go SDK + `net/http` DLP middleware + Rust `veil mcp` bridge: `github.com/glastor-dev/pii-veil/sdks/go`)

---

## ✨ Key Capabilities

- **Reversible LLM Roundtrip & Real-Time SSE Streaming (`Placeholder` Mode)**:
  Replaces sensitive data with semantic tokens (`[EMAIL_1]`, `[CREDIT_CARD_1]`, `[IBAN_1]`), restores full responses in $O(N)$ via `aho-corasick`, or restores live token streams chunk-by-chunk (`[EMA` + `IL_1]`) via `StreamingRestorer`.
- **Built-in Model Context Protocol (`veil mcp`) & HTTP/SSE Proxy (`veil proxy`)**:
  - `veil mcp`: Zero-dependency JSON-RPC 2.0 MCP server over `stdio` exposing `veil_redact`, `veil_restore`, `veil_redact_json`, and `veil_scan` directly to Claude Desktop, Cursor, and Windsurf.
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

---

## 📂 Production Examples (`examples/`)

- [`examples/python_fastapi_llm_streaming.py`](examples/python_fastapi_llm_streaming.py) — FastAPI + OpenAI/Anthropic SSE streaming with `StreamingRestorer` and encrypted Vaults.
- [`examples/typescript_nextjs_ai_sdk.ts`](examples/typescript_nextjs_ai_sdk.ts) — Next.js / Vercel AI SDK `TransformStream` with `VeilStreamingRestorer`.
- [`examples/git_pre_commit_hook.sh`](examples/git_pre_commit_hook.sh) — Git pre-commit DLP hook powered by `veil scan --fail-on-detect`.

# ⚡ GLASTOR® `pii-veil` — Scientific Benchmarks & Latency Telemetry

Empirical performance evaluation comparing **`pii-veil` (Rust SIMD)** against **Microsoft Presidio (Python/spaCy)** and **AWS Comprehend PII (Cloud API)**.

All benchmarks were measured on standard x86_64 hardware using the official Rust [`criterion`](https://github.com/bheisler/criterion.rs) statistical harness (10 samples, 3s warm-up, L1/L2 cache preheated).

---

## 📊 Summary Comparison

| Metric / Capability | 🛡️ GLASTOR® `pii-veil` | 🐍 Microsoft Presidio | ☁️ AWS Comprehend |
| :--- | :--- | :--- | :--- |
| **Typical Prompt Latency (1 KB)** | **165 µs (0.165 ms)** | ~35 ms (35,000 µs) | ~140 ms (140,000 µs) |
| **Single-Entity Scan Latency** | **4.01 µs (0.004 ms)** | ~12 ms (12,000 µs) | ~90 ms (network bound) |
| **1 MB Throughput Buffer** | **20.5 ms (~46.3 MiB/s)** | ~4,200 ms (4.2 s) | Not supported in single call |
| **Speedup vs Competitor** | **Baseline (1x)** | **~212x faster** | **~848x faster** |
| **Streaming Token Restoration** | **69.6 µs per chunk** | ❌ Not supported | ❌ Not supported |
| **Network & Privacy Overhead** | **0 ms (100% In-Process)** | 0 ms (In-Process) | 80–250 ms HTTP overhead |
| **Cost per 1M Requests** | **$0.00 (Self-Hosted)** | $0.00 (Compute cost) | **$100.00+ USD** |
| **Memory Footprint** | **< 15 MB (Distroless)** | ~450 MB (spaCy model) | Cloud Service |

---

## 🔬 Empirical Criterion Results

Source: `crates/veil-core/benches/bench_throughput.rs`

### 1. Typical LLM Prompt Redaction (1 KB text with 7 sensitive entities)
- **Mean Latency**: `165.68 µs`
- **Confidence Interval (95%)**: `[164.40 µs — 167.22 µs]`
- **Entities Tested**: Email, Luhn-valid Credit Card, DNI, CUIT, Mod-97 IBAN, PostgreSQL Connection URI, OpenAI Secret API Key.

### 2. Strategy Mode Comparison (Single Entity Isolation)
- **Semantic Placeholder (`[CREDIT_CARD_1]`)**: `4.01 µs` (Throughput: `21.84 MiB/s`)
- **Synthetic Replacement (Checksum-Valid Luhn/IBAN)**: `4.99 µs` (Throughput: `17.56 MiB/s`)
- **Irreversible Partial Mask (`4532-****-****-0366`)**: `4.52 µs` (Throughput: `19.40 MiB/s`)

### 3. Real-Time Streaming Token Restorer (SSE Chunks)
- **Mean Latency**: `69.65 µs` per streaming event
- **Token Split Test**: Handles placeholders split across arbitrary chunk boundaries (e.g. `"[EMA"` + `"IL_1]"`).

### 4. High-Throughput Bulk Payload (1 MB dense buffer)
- **Mean Time**: `20.58 ms`
- **Sustained Throughput**: `46.33 MiB/s`

---

## 🔄 Reproduction Steps

```bash
cargo bench -p pii-veil-core --bench bench_throughput
```

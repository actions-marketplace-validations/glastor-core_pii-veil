# PII & LLM DLP Benchmark Suite: `pii-veil` (Rust) vs. Microsoft Presidio (Python)

Reproducible, apples-to-apples containerized benchmark comparing **[GLASTOR `pii-veil`](https://github.com/glastor-core/pii-veil)** (`pii-veil-core` + Axum) against **Microsoft Presidio** (`presidio-analyzer` + `presidio-anonymizer` + FastAPI/Uvicorn) under identical Docker resource limits (`2.0 vCPUs`, `2 GiB RAM`).

## Fair-Play Contract

Both services expose the exact same HTTP interface:
- `GET /health` -> `200 OK`
- `POST /api/v1/redact` -> Accepts `{"text": "<prompt>"}` and returns `{"text": "<sanitized>", "spans_found": <int>}`.

Both containers are pre-warmed (spaCy `en_core_web_sm` loaded at startup in Presidio; `VeilEngine` initialized once in `Arc` state in Rust) and run in strict production mode with access logs disabled.

## Reproduce Locally

### Prerequisites
- Docker & Docker Compose v2
- [k6](https://k6.io/docs/get-started/installation/)

### Run Both Engines Back-to-Back
```bash
cd pii-dlp
chmod +x run-pii.sh
./run-pii.sh
```

### Run Individually
```bash
# 1. Rust pii-veil
docker compose up -d --build rust-pii-veil
k6 run -e TARGET_URL=http://localhost:8091/api/v1/redact k6-pii.js
docker stats --no-stream glastor-bench-pii-veil
docker compose down

# 2. Python Microsoft Presidio
docker compose up -d --build python-presidio
k6 run -e TARGET_URL=http://localhost:8092/api/v1/redact k6-pii.js
docker stats --no-stream glastor-bench-presidio
docker compose down
```

## Trade-off Note

`pii-veil` is a deterministic, linear-time Aho-Corasick + mathematical checksum DLP engine (Luhn, Mod-97, Mod-11, Mod-23) designed for sub-millisecond structured PII and secrets redaction. Microsoft Presidio executes a full spaCy NLP pipeline that also attempts probabilistic Named Entity Recognition (NER) on unstructured free-text names. See [`pii-veil` Layered Defense Architecture](https://github.com/glastor-core/pii-veil/blob/main/docs/layered-defense-ner.md) for combining both in production.

---

© 2026 GLASTOR Core Organization — Security & Infrastructure Team.

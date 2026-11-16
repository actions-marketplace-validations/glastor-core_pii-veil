use criterion::{black_box, criterion_group, criterion_main, BenchmarkId, Criterion, Throughput};
use pii_veil_core::{RedactionMode, Vault, VeilEngine};

fn bench_short_prompt_redaction(c: &mut Criterion) {
    let engine = VeilEngine::new(RedactionMode::Placeholder);
    let prompt = "Hola soporte, soy María (maria.gonzalez@fintech.io, DNI 00000000T, CUIT 20-12345678-6). \
                  Mi tarjeta es 4532-0151-1283-0366 y mi IBAN es DE89 3704 0044 0532 0130 00. \
                  Mi servidor de pruebas corre en postgres://admin:SecretPass99@db.fintech.io:5432/prod \
                  y mi API key es sk-proj-99a8b7c6d5e4f3g2h1i0jklmnopqrst.";

    let mut group = c.benchmark_group("llm_prompt_redaction");
    group.throughput(Throughput::Bytes(prompt.len() as u64));

    group.bench_function("short_prompt_1kb_redact", |b| {
        let mut vault = Vault::new();
        b.iter(|| {
            vault.clear();
            let redacted = engine.redact_with_vault(black_box(prompt), &mut vault);
            black_box(redacted);
        });
    });

    group.finish();
}

fn bench_throughput_large_payload(c: &mut Criterion) {
    let engine = VeilEngine::new(RedactionMode::Placeholder);

    // Build 1 MB payload with dense PII entities
    let unit = "Registro: user.id=1024, email=cliente.vip@fintech.com, card=4532-0151-1283-0366, \
                ip=192.168.1.105, iban=DE89370400440532013000, key=sk-proj-1234567890abcdef1234567890abcdef.\n";
    let count = 1_000_000 / unit.len() + 1;
    let payload = unit.repeat(count);
    let payload_bytes = payload.len() as u64;

    let mut group = c.benchmark_group("large_payload_throughput");
    group.throughput(Throughput::Bytes(payload_bytes));

    group.bench_function(BenchmarkId::new("redact_1mb_buffer", "dense_pii"), |b| {
        let mut vault = Vault::new();
        b.iter(|| {
            vault.clear();
            let redacted = engine.redact_with_vault(black_box(&payload), &mut vault);
            black_box(redacted);
        });
    });

    group.finish();
}

fn bench_streaming_restorer(c: &mut Criterion) {
    let engine = VeilEngine::new(RedactionMode::Placeholder);
    let mut vault = Vault::new();
    let prompt = "Usuario martin@empresa.com con tarjeta 4532-0151-1283-0366 y token sk-proj-1234567890abcdef";
    let _ = engine.redact_with_vault(prompt, &mut vault);

    let chunks = vec![
        "Confirmación de operación para [EMA".to_string(),
        "IL_1] realizada con éxito con [CRED".to_string(),
        "IT_CARD_1]. Token registrado: [OPENAI_".to_string(),
        "KEY_1]. Gracias.".to_string(),
    ];

    let mut group = c.benchmark_group("streaming_restorer");

    group.bench_function("sse_chunk_split_restoration", |b| {
        b.iter(|| {
            let mut restorer = vault.streaming_restorer();
            let mut output = String::with_capacity(256);
            for chunk in black_box(&chunks) {
                output.push_str(&restorer.push_chunk(chunk));
            }
            output.push_str(&restorer.finish());
            black_box(output);
        });
    });

    group.finish();
}

fn bench_synthetic_vs_placeholder_vs_mask(c: &mut Criterion) {
    let placeholder_engine = VeilEngine::new(RedactionMode::Placeholder);
    let synthetic_engine =
        VeilEngine::new(RedactionMode::Synthetic).with_secret_key(b"benchmark-seed-key");
    let mask_engine = VeilEngine::new(RedactionMode::Mask);

    let sample = "Pago de carlos@acme.org con tarjeta 4532-0151-1283-0366 e IBAN ES91 2100 0418 4502 0005 1332";

    let mut group = c.benchmark_group("strategy_comparison");
    group.throughput(Throughput::Bytes(sample.len() as u64));

    group.bench_function("mode_placeholder", |b| {
        let mut vault = Vault::new();
        b.iter(|| {
            vault.clear();
            black_box(placeholder_engine.redact_with_vault(black_box(sample), &mut vault));
        });
    });

    group.bench_function("mode_synthetic_checksummed", |b| {
        b.iter(|| {
            black_box(synthetic_engine.redact(black_box(sample)));
        });
    });

    group.bench_function("mode_mask", |b| {
        b.iter(|| {
            black_box(mask_engine.redact(black_box(sample)));
        });
    });

    group.finish();
}

criterion_group!(
    benches,
    bench_short_prompt_redaction,
    bench_throughput_large_payload,
    bench_streaming_restorer,
    bench_synthetic_vs_placeholder_vs_mask
);
criterion_main!(benches);

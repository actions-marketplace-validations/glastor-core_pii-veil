//! Multi-thousand iteration fuzzing smoke test for `pii-veil-core`.
//!
//! Validates invariants under pseudo-random permutations, chaotic token splits,
//! malformed UTF-8 slicing attempts, and boundary conditions without panics.

use pii_veil_core::{
    is_valid_arg_cuit, is_valid_chilean_rut, is_valid_iban, is_valid_ipv4, is_valid_luhn,
    is_valid_national_id, is_valid_spanish_dni_nie, EntityKind, RedactionMode, StreamingRestorer,
    Vault, VeilEngine,
};

/// Simple deterministic linear congruential generator for reproducible pseudo-random fuzzing.
struct FuzzRng {
    state: u64,
}

impl FuzzRng {
    fn new(seed: u64) -> Self {
        Self { state: seed }
    }

    fn next_u32(&mut self) -> u32 {
        self.state = self.state.wrapping_mul(6364136223846793005).wrapping_add(1);
        (self.state >> 32) as u32
    }

    fn next_usize(&mut self, max: usize) -> usize {
        if max == 0 {
            0
        } else {
            (self.next_u32() as usize) % max
        }
    }

    fn random_string(&mut self, max_len: usize) -> String {
        let len = self.next_usize(max_len);
        let chars = [
            'a', 'b', '1', '2', '@', '.', '-', '_', ' ', '\n', '\t', '\0',
            'é', 'ñ', '中', '🦀', '<', '>', '/', '\\', ':', ';', '"', '\'',
        ];
        let mut s = String::with_capacity(len);
        for _ in 0..len {
            let idx = self.next_usize(chars.len());
            s.push(chars[idx]);
        }
        s
    }
}

#[test]
fn test_fuzz_redaction_engine_no_panics() {
    let mut rng = FuzzRng::new(0xDEAD_BEEF_CAFE_BABE);
    let modes = [
        RedactionMode::Placeholder,
        RedactionMode::Synthetic,
        RedactionMode::Mask,
    ];

    for i in 0..2_000 {
        let input = rng.random_string(256);
        let mode = modes[i % modes.len()];
        let engine = VeilEngine::new(mode);

        // Invariant 1: Engine never panics on arbitrary string data
        let res = engine.redact(&input);
        assert!(res.spans_found <= input.len());

        // Invariant 2: Restore never panics on engine output
        if mode == RedactionMode::Placeholder {
            let restored = res.vault.restore(&res.text);
            let _ = restored.len();
        }
    }
}

#[test]
fn test_fuzz_checksum_validators_no_panics() {
    let mut rng = FuzzRng::new(0x1337_F00D_2026);

    for _ in 0..3_000 {
        let s = rng.random_string(64);
        let _ = is_valid_luhn(&s);
        let _ = is_valid_iban(&s);
        let _ = is_valid_national_id(&s);
        let _ = is_valid_spanish_dni_nie(&s);
        let _ = is_valid_arg_cuit(&s);
        let _ = is_valid_chilean_rut(&s);
        let _ = is_valid_ipv4(&s);
    }
}

#[test]
fn test_fuzz_streaming_restorer_arbitrary_chunk_boundaries() {
    let mut rng = FuzzRng::new(0x8888_9999_AAAA_BBBB);

    let mut vault = Vault::new();
    let _ = vault.get_or_insert(EntityKind::Email, "security-auditor@glastor.es", |i| {
        format!("[EMAIL_{i}]")
    });
    let _ = vault.get_or_insert(EntityKind::CreditCard, "4532-0151-1283-0366", |i| {
        format!("[CREDIT_CARD_{i}]")
    });

    let target_template = "Invoice for [EMAIL_1] charging card [CREDIT_CARD_1] approved.";

    for _ in 0..500 {
        // Randomly split the target template into 1 to 10 arbitrary chunks
        let mut chunks = Vec::new();
        let mut cursor = 0;
        let bytes = target_template.as_bytes();

        while cursor < bytes.len() {
            let remaining = bytes.len() - cursor;
            let slice_len = (rng.next_usize(remaining) + 1).min(remaining);
            let chunk_str = String::from_utf8_lossy(&bytes[cursor..cursor + slice_len]).to_string();
            chunks.push(chunk_str);
            cursor += slice_len;
        }

        // Feed chunks into StreamingRestorer
        let mut restorer = StreamingRestorer::new(vault.clone());
        let mut reassembled = String::new();

        for chunk in &chunks {
            reassembled.push_str(&restorer.push_chunk(chunk));
        }
        reassembled.push_str(&restorer.finish());

        // Invariant: Must deterministically restore the exact original plaintext
        assert_eq!(
            reassembled,
            "Invoice for security-auditor@glastor.es charging card 4532-0151-1283-0366 approved."
        );
    }
}

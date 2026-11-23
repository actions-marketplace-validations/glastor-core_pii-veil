#![no_main]
use libfuzzer_sys::fuzz_target;
use pii_veil_core::{EntityKind, StreamingRestorer, Vault};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let mut vault = Vault::new();
        let _ = vault.get_or_insert(EntityKind::Email, "alice@example.com", |i| format!("[EMAIL_{i}]"));
        let _ = vault.get_or_insert(EntityKind::CreditCard, "4532-0151-1283-0366", |i| format!("[CREDIT_CARD_{i}]"));

        let _ = vault.restore(text);

        let mut restorer = StreamingRestorer::new(vault);
        let mut output = String::new();
        for chunk in text.split_whitespace() {
            output.push_str(&restorer.push_chunk(chunk));
        }
        output.push_str(&restorer.finish());
    }
});

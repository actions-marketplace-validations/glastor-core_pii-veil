#![no_main]
use libfuzzer_sys::fuzz_target;
use pii_veil_core::{RedactionMode, VeilEngine};

fuzz_target!(|data: &[u8]| {
    if let Ok(text) = std::str::from_utf8(data) {
        let modes = [
            RedactionMode::Placeholder,
            RedactionMode::Synthetic,
            RedactionMode::Mask,
        ];
        for mode in modes {
            let engine = VeilEngine::new(mode);
            let result = engine.redact(text);
            assert!(result.spans_found <= text.len());
            if mode == RedactionMode::Placeholder {
                let restored = result.vault.restore(&result.text);
                let _ = restored.len();
            }
        }
    }
});

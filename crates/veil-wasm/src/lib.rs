//! # `pii-veil-wasm`
//!
//! High-performance WebAssembly bindings for `pii-veil-core`.
//! Runs 100% in-browser on client CPU with zero network calls and sub-millisecond execution.

use pii_veil_core::{
    DetectedSpan, RedactionMode, Vault, VaultEntry, VeilEngine,
};
use serde::{Deserialize, Serialize};
use wasm_bindgen::prelude::*;

#[derive(Serialize, Deserialize)]
pub struct WasmRedactionOutput {
    pub text: String,
    pub spans_found: usize,
    pub vault_json: String,
    pub entries: Vec<VaultEntry>,
}

fn parse_mode(mode_str: Option<&str>) -> RedactionMode {
    match mode_str.map(|s| s.trim().to_ascii_lowercase()).as_deref() {
        Some("synthetic") => RedactionMode::Synthetic,
        Some("mask") => RedactionMode::Mask,
        _ => RedactionMode::Placeholder,
    }
}

/// Redacts sensitive PII and secrets in `text`.
///
/// Returns an object: `{ text: string, spans_found: number, vault_json: string, entries: Array<VaultEntry> }`.
#[wasm_bindgen]
pub fn redact(text: &str, mode: Option<String>) -> Result<JsValue, JsValue> {
    let selected_mode = parse_mode(mode.as_deref());
    let engine = VeilEngine::new(selected_mode);
    let mut vault = Vault::new();

    let (sanitized_text, spans_count) = engine.redact_with_vault_counted(text, &mut vault);

    let vault_json = serde_json::to_string_pretty(&vault)
        .map_err(|e| JsValue::from_str(&format!("Vault serialization error: {e}")))?;

    // Extract entries list from the serialized vault
    let entries: Vec<VaultEntry> = serde_json::from_str(&vault_json).unwrap_or_default();

    let output = WasmRedactionOutput {
        text: sanitized_text,
        spans_found: spans_count,
        vault_json,
        entries,
    };

    serde_wasm_bindgen::to_value(&output)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize result: {e}")))
}

/// Restores sanitized text back to original values using the serialized JSON vault.
#[wasm_bindgen]
pub fn restore(sanitized_text: &str, vault_json: &str) -> Result<String, JsValue> {
    let vault: Vault = serde_json::from_str(vault_json)
        .map_err(|e| JsValue::from_str(&format!("Invalid vault JSON: {e}")))?;

    Ok(vault.restore(sanitized_text))
}

/// Scans text for PII/secrets without modifying it.
/// Returns an array of detected spans.
#[wasm_bindgen]
pub fn scan(text: &str) -> Result<JsValue, JsValue> {
    let engine = VeilEngine::new(RedactionMode::Placeholder);
    let spans: Vec<DetectedSpan> = engine.scan(text);

    serde_wasm_bindgen::to_value(&spans)
        .map_err(|e| JsValue::from_str(&format!("Failed to serialize spans: {e}")))
}

/// Stateful engine holding a persistent vault for multi-turn chats or streaming chunks.
#[wasm_bindgen]
pub struct WasmVeil {
    engine: VeilEngine,
    vault: Vault,
}

#[wasm_bindgen]
impl WasmVeil {
    #[wasm_bindgen(constructor)]
    pub fn new(mode: Option<String>) -> Self {
        let selected_mode = parse_mode(mode.as_deref());
        Self {
            engine: VeilEngine::new(selected_mode),
            vault: Vault::new(),
        }
    }

    /// Redacts text using the persistent vault.
    pub fn redact(&mut self, text: &str) -> String {
        self.engine.redact_with_vault(text, &mut self.vault)
    }

    /// Restores text back using the current persistent vault.
    pub fn restore(&self, text: &str) -> String {
        self.vault.restore(text)
    }

    /// Exports the current vault as a JSON string.
    pub fn export_vault_json(&self) -> Result<String, JsValue> {
        serde_json::to_string_pretty(&self.vault)
            .map_err(|e| JsValue::from_str(&format!("Serialization error: {e}")))
    }

    /// Resets the persistent vault.
    pub fn reset_vault(&mut self) {
        self.vault.clear();
    }
}

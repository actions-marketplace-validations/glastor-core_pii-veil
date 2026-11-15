//! # `pii-veil-core`
//!
//! Ultrafast, deterministic, and reversible PII & secret anonymization engine for LLMs,
//! observability logs, and SQL/CSV/NDJSON streams.
//!
//! ## Core Features
//! - **Sub-millisecond PII & Secret Detection (18 Built-in Detectors)**:
//!   Emails, Credit Cards (Luhn), IBANs (ISO 13616 Mod-97), Regional IDs (US SSN, Spain DNI/NIE Mod-23,
//!   Argentina CUIT/CUIL Mod-11, Chile RUT Mod-11), Database Connection URIs (`postgres://`, `mongodb+srv://`, `redis://`),
//!   Slack/Discord Webhooks, OpenAI/Anthropic/AWS/GitHub/Slack/Google/Stripe keys, JWTs, PEM Private Keys,
//!   IPv4, IPv6, MAC addresses, and Phone numbers.
//! - **3 Redaction Modes**:
//!   - [`RedactionMode::Placeholder`]: `[EMAIL_1]`, `[CREDIT_CARD_1]` (ideal for LLM prompts & MCP agents).
//!   - [`RedactionMode::Synthetic`]: Deterministic realistic fake data via keyed hashing (ideal for SQL dumps & E2E tests).
//!   - [`RedactionMode::Mask`]: Partial masking (`j***@empresa.com`) for safe logging.
//! - **Single-Pass & Streaming Reversible Vault**:
//!   - Restore full responses in $O(N)$ time via `aho-corasick`.
//!   - Restore real-time LLM SSE token streams (`[EMA` + `IL_1]`) via [`StreamingRestorer`].
//!   - Persist vaults securely with authenticated encryption via [`Vault::to_encrypted_json`].

pub mod detector;
pub mod policy;
pub mod strategy;
pub mod stream;
pub mod vault;

pub use detector::{
    is_valid_arg_cuit, is_valid_chilean_rut, is_valid_iban, is_valid_ipv4, is_valid_luhn,
    is_valid_national_id, is_valid_spanish_dni_nie, DetectedSpan, DetectorPipeline, EntityKind,
};
pub use policy::{CustomRuleConfig, VeilPolicy};
pub use strategy::{generate_replacement, keyed_hash64, RedactionMode};
pub use stream::{StreamFormat, StreamStats};
pub use vault::{EncryptedVaultEnvelope, StreamingRestorer, Vault, VaultEntry};

use serde::{Deserialize, Serialize};
use serde_json::Value;
use thiserror::Error;

#[derive(Debug, Error)]
pub enum VeilError {
    #[error("invalid custom regex pattern: {0}")]
    InvalidRegex(#[from] regex::Error),
    #[error("JSON serialization/parsing error: {0}")]
    JsonError(#[from] serde_json::Error),
}

/// Result of a redaction operation when using a single-call helper.
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct RedactionResult {
    pub text: String,
    pub spans_found: usize,
    pub vault: Vault,
}

/// Sensitive JSON/CSV field names whose scalar string values are automatically redacted
/// even if they don't match standard regex patterns.
const SENSITIVE_FIELD_KEYS: &[&str] = &[
    "password",
    "passwd",
    "secret",
    "client_secret",
    "api_key",
    "apikey",
    "access_token",
    "refresh_token",
    "private_key",
    "cvv",
    "cvc",
    "pin",
];

/// Primary engine for detecting, anonymizing, and restoring PII and secrets.
#[derive(Debug, Clone)]
pub struct VeilEngine {
    pipeline: DetectorPipeline,
    mode: RedactionMode,
    secret_key: Vec<u8>,
    extra_sensitive_keys: Vec<String>,
}

impl Default for VeilEngine {
    fn default() -> Self {
        Self::new(RedactionMode::Placeholder)
    }
}

impl VeilEngine {
    /// Creates a new `VeilEngine` with the specified [`RedactionMode`].
    pub fn new(mode: RedactionMode) -> Self {
        Self {
            pipeline: DetectorPipeline::new(),
            mode,
            secret_key: b"pii-veil-default-seed-key-2026".to_vec(),
            extra_sensitive_keys: Vec::new(),
        }
    }

    /// Constructs a [`VeilEngine`] from a declarative [`VeilPolicy`].
    pub fn from_policy(policy: VeilPolicy) -> Result<Self, VeilError> {
        let mut engine = Self::new(policy.mode).with_secret_key(policy.secret_key.as_bytes());
        for kind in policy.disabled_entities {
            engine.disable_entity(kind);
        }
        for allow in policy.allowlist {
            engine.add_allowlist(allow);
        }
        for key in policy.extra_sensitive_keys {
            engine.add_sensitive_json_key(key);
        }
        for rule in policy.custom_rules {
            engine.add_custom_rule(rule.name, &rule.pattern)?;
        }
        Ok(engine)
    }

    /// Sets the secret key used for deterministic synthetic data generation.
    pub fn with_secret_key(mut self, key: impl AsRef<[u8]>) -> Self {
        self.secret_key = key.as_ref().to_vec();
        self
    }

    /// Returns the configured [`RedactionMode`].
    pub fn mode(&self) -> RedactionMode {
        self.mode
    }

    /// Returns the configured secret key slice.
    pub fn secret_key(&self) -> &[u8] {
        &self.secret_key
    }

    /// Adds a custom regex detector rule (e.g. `"EMPLOYEE_ID"`, `r"\bEMP-\d{6}\b"`).
    pub fn add_custom_rule(
        &mut self,
        name: impl Into<String>,
        pattern: &str,
    ) -> Result<(), VeilError> {
        self.pipeline.add_custom_rule(name, pattern)?;
        Ok(())
    }

    /// Adds an allowlist entry (exact string like `"127.0.0.1"` or domain suffix like `"@example.com"`).
    pub fn add_allowlist(&mut self, entry: impl Into<String>) {
        self.pipeline.add_allowlist(entry);
    }

    /// Disables detection of a specific built-in [`EntityKind`].
    pub fn disable_entity(&mut self, kind: EntityKind) {
        self.pipeline.disable_entity(kind);
    }

    /// Registers an additional JSON/CSV column key name whose string values should always be redacted.
    pub fn add_sensitive_json_key(&mut self, key: impl Into<String>) {
        let k = key.into().trim().to_ascii_lowercase();
        if !k.is_empty() {
            self.extra_sensitive_keys.push(k);
        }
    }

    /// Checks whether a JSON key or CSV column header is considered sensitive by default or policy.
    pub fn is_sensitive_key_name(&self, key: &str) -> bool {
        let key_lower = key.trim().to_ascii_lowercase();
        SENSITIVE_FIELD_KEYS
            .iter()
            .any(|&sk| key_lower == sk || key_lower.ends_with(&format!("_{}", sk)))
            || self
                .extra_sensitive_keys
                .iter()
                .any(|sk| &key_lower == sk || key_lower.ends_with(&format!("_{}", sk)))
    }

    /// Returns a reference to the underlying detector pipeline.
    pub fn detector(&self) -> &DetectorPipeline {
        &self.pipeline
    }

    /// Scans `text` without modifying it and returns all detected sensitive spans.
    pub fn scan(&self, text: &str) -> Vec<DetectedSpan> {
        self.pipeline.detect(text)
    }

    /// Scans `text` without modifying it and returns all detected spans serialized as a JSON string.
    pub fn scan_json(&self, text: &str) -> Result<String, VeilError> {
        let spans = self.pipeline.detect(text);
        Ok(serde_json::to_string(&spans)?)
    }

    /// Redacts sensitive entities in `text`, recording reversible mappings into `vault`.
    pub fn redact_with_vault(&self, text: &str, vault: &mut Vault) -> String {
        self.redact_with_vault_counted(text, vault).0
    }

    /// Redacts sensitive entities in `text`, returning `(redacted_text, spans_count)`.
    pub fn redact_with_vault_counted(&self, text: &str, vault: &mut Vault) -> (String, usize) {
        let spans = self.pipeline.detect(text);
        let spans_count = spans.len();
        if spans.is_empty() {
            return (text.to_string(), 0);
        }

        let mut output = String::with_capacity(text.len());
        let mut cursor = 0;

        for span in spans {
            if span.start > cursor {
                output.push_str(&text[cursor..span.start]);
            }

            let mode = self.mode;
            let secret = &self.secret_key;
            let kind_clone = span.kind.clone();
            let orig_ref = &span.original;

            let replacement = vault.get_or_insert(span.kind, orig_ref, |idx| {
                generate_replacement(mode, &kind_clone, orig_ref, idx, secret)
            });

            output.push_str(&replacement);
            cursor = span.end;
        }

        if cursor < text.len() {
            output.push_str(&text[cursor..]);
        }

        (output, spans_count)
    }

    /// Convenience method that creates a fresh [`Vault`], redacts `text`, and returns [`RedactionResult`].
    pub fn redact(&self, text: &str) -> RedactionResult {
        let mut vault = Vault::new();
        let (redacted, spans_found) = self.redact_with_vault_counted(text, &mut vault);
        RedactionResult {
            text: redacted,
            spans_found,
            vault,
        }
    }

    /// Recursively sanitizes a JSON string while preserving its structural validity,
    /// redacting both detected PII patterns inside strings and values under sensitive key names.
    pub fn redact_json_str(
        &self,
        json_input: &str,
        vault: &mut Vault,
    ) -> Result<String, VeilError> {
        let mut val: Value = serde_json::from_str(json_input)?;
        self.redact_json_value(&mut val, vault);
        Ok(serde_json::to_string_pretty(&val)?)
    }

    /// Recursively sanitizes a mutable [`serde_json::Value`] in-place.
    pub fn redact_json_value(&self, value: &mut Value, vault: &mut Vault) {
        let _ = self.redact_json_value_counted(value, vault);
    }

    /// Recursively sanitizes a mutable [`serde_json::Value`] in-place and returns the number of redacted spans.
    pub fn redact_json_value_counted(&self, value: &mut Value, vault: &mut Vault) -> usize {
        match value {
            Value::String(s) => {
                let (redacted, count) = self.redact_with_vault_counted(s, vault);
                *s = redacted;
                count
            }
            Value::Array(arr) => arr
                .iter_mut()
                .map(|item| self.redact_json_value_counted(item, vault))
                .sum(),
            Value::Object(map) => {
                let mut total = 0;
                for (k, v) in map.iter_mut() {
                    if self.is_sensitive_key_name(k) {
                        if let Value::String(secret_val) = v {
                            if !secret_val.is_empty() {
                                let mode = self.mode;
                                let secret = &self.secret_key;
                                let kind = EntityKind::Custom("SECRET_FIELD".to_string());
                                let rep = vault.get_or_insert(kind.clone(), secret_val, |idx| {
                                    generate_replacement(mode, &kind, secret_val, idx, secret)
                                });
                                *secret_val = rep;
                                total += 1;
                                continue;
                            }
                        }
                    }
                    total += self.redact_json_value_counted(v, vault);
                }
                total
            }
            _ => 0,
        }
    }
}

#[cfg(test)]
mod tests {
    use super::*;
    use std::io::Cursor;

    #[test]
    fn test_placeholder_roundtrip_for_llm() {
        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let prompt = "Hola, soy Juan (juan.perez@empresa.com) y mi otro correo es ventas@empresa.com. \
                      Si necesitas facturar a juan.perez@empresa.com usa la tarjeta 4532 0151 1283 0366.";

        let result = engine.redact(prompt);

        assert!(result.text.contains("[EMAIL_1]"));
        assert!(result.text.contains("[EMAIL_2]"));
        assert!(result.text.contains("[CREDIT_CARD_1]"));
        assert!(!result.text.contains("juan.perez@empresa.com"));
        assert!(!result.text.contains("4532 0151 1283 0366"));

        let llm_response = "Perfecto, envié la factura a [EMAIL_1] con copia a [EMAIL_2] tras cobrar en [CREDIT_CARD_1].";
        let restored = result.vault.restore(llm_response);

        assert_eq!(
            restored,
            "Perfecto, envié la factura a juan.perez@empresa.com con copia a ventas@empresa.com tras cobrar en 4532 0151 1283 0366."
        );
    }

    #[test]
    fn test_synthetic_mode_determinism_luhn_and_iban() {
        let engine1 = VeilEngine::new(RedactionMode::Synthetic).with_secret_key("my-prod-seed");
        let engine2 = VeilEngine::new(RedactionMode::Synthetic).with_secret_key("my-prod-seed");

        let input = "User email: maria@startup.io, Card: 4532-0151-1283-0366, IBAN: DE89 3704 0044 0532 0130 00, IP: 192.168.1.45";
        let res1 = engine1.redact(input);
        let res2 = engine2.redact(input);

        assert_eq!(res1.text, res2.text);
        assert!(!res1.text.contains("maria@startup.io"));
        assert!(!res1.text.contains("DE89 3704 0044 0532 0130 00"));

        for entry in res1.vault.entries() {
            if entry.kind == EntityKind::CreditCard {
                assert!(is_valid_luhn(&entry.replacement));
            }
            if entry.kind == EntityKind::Iban {
                assert!(is_valid_iban(&entry.replacement));
            }
        }

        assert_eq!(res1.vault.restore(&res1.text), input);
    }

    #[test]
    fn test_api_keys_and_json_redaction() {
        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let mut vault = Vault::new();

        let payload = r#"{
            "customer": "ana@cliente.com",
            "password": "SuperSecretPassword123!",
            "openai": "sk-proj-abc123def456ghi789jkl012mno345pqr",
            "anthropic": "sk-ant-api03-abc123def456ghi789jkl012mno345pqr",
            "aws": "AKIAIOSFODNN7EXAMPLE"
        }"#;

        let sanitized = engine.redact_json_str(payload, &mut vault).unwrap();
        assert!(!sanitized.contains("ana@cliente.com"));
        assert!(!sanitized.contains("SuperSecretPassword123!"));
        assert!(!sanitized.contains("sk-proj-abc123def456ghi789jkl012mno345pqr"));
        assert!(!sanitized.contains("sk-ant-api03-abc123def456ghi789jkl012mno345pqr"));
        assert!(!sanitized.contains("AKIAIOSFODNN7EXAMPLE"));
        assert_eq!(vault.len(), 5);
    }

    #[test]
    fn test_policy_allowlist_and_custom_rules() {
        let policy = VeilPolicy::default();
        let engine = VeilEngine::from_policy(policy).unwrap();

        let text = "Connect 127.0.0.1 for test@example.com or real@corp.io (Employee EMP-123456)";
        let res = engine.redact(text);

        assert!(res.text.contains("127.0.0.1"));
        assert!(res.text.contains("test@example.com"));
        assert!(!res.text.contains("real@corp.io"));
        assert!(!res.text.contains("EMP-123456"));
        assert!(res.text.contains("[EMAIL_1]"));
        assert!(res.text.contains("[EMPLOYEE_ID_1]"));
    }

    #[test]
    fn test_sql_and_csv_streaming_and_restore_stream() {
        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let csv_input =
            "id,user_email,user_password,notes\n1,carlos@empresa.com,MyPlainPass99,Normal note\n";
        let mut csv_out = Vec::new();
        let mut vault = Vault::new();

        let stats = engine
            .redact_stream(
                Cursor::new(csv_input.as_bytes()),
                &mut csv_out,
                StreamFormat::Csv,
                &mut vault,
            )
            .unwrap();

        let redacted_csv = String::from_utf8(csv_out).unwrap();
        assert!(!redacted_csv.contains("carlos@empresa.com"));
        assert!(!redacted_csv.contains("MyPlainPass99"));
        assert!(redacted_csv.contains("[EMAIL_1]"));
        assert!(redacted_csv.contains("[SECRET_FIELD_1]"));
        assert_eq!(stats.spans_redacted, 2);

        let mut restored_out = Vec::new();
        vault
            .restore_stream(Cursor::new(redacted_csv.as_bytes()), &mut restored_out)
            .unwrap();
        assert_eq!(String::from_utf8(restored_out).unwrap(), csv_input);
    }

    #[test]
    fn test_streaming_llm_chunk_restorer_and_encrypted_vault() {
        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let res = engine.redact("Contacta a sofia@fintech.cl o cobra en 4532-0151-1283-0366.");

        // 1. Test encrypted vault persistence
        let encrypted = res.vault.to_encrypted_json("my-master-passphrase").unwrap();
        assert!(!encrypted.contains("sofia@fintech.cl"));
        assert!(Vault::from_encrypted_json(&encrypted, "wrong-passphrase").is_err());

        let decrypted = Vault::from_encrypted_json(&encrypted, "my-master-passphrase").unwrap();

        // 2. Simulate LLM streaming token-by-token where [EMAIL_1] and [CREDIT_CARD_1] are split mid-token
        let mut stream_restorer = decrypted.streaming_restorer();
        let chunks = [
            "Hola, envié a [EMA",
            "IL_1] el recibo de [CRED",
            "IT_CARD_1] hoy.",
        ];
        let mut reconstructed = String::new();
        for c in chunks {
            reconstructed.push_str(&stream_restorer.push_chunk(c));
        }
        reconstructed.push_str(&stream_restorer.finish());

        assert_eq!(
            reconstructed,
            "Hola, envié a sofia@fintech.cl el recibo de 4532-0151-1283-0366 hoy."
        );
    }

    #[test]
    fn test_regional_ids_conn_uris_and_webhooks() {
        // Valid ES DNI (00000000T), valid AR CUIT (20-12345678-6), valid CL RUT (12.345.678-5)
        assert!(is_valid_spanish_dni_nie("00000000T"));
        assert!(!is_valid_spanish_dni_nie("00000000Z"));
        assert!(is_valid_arg_cuit("20-12345678-6"));
        assert!(!is_valid_arg_cuit("20-12345678-1"));
        assert!(is_valid_chilean_rut("12.345.678-5"));
        assert!(!is_valid_chilean_rut("12.345.678-9"));

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let input = "DB: postgres://admin:Sup3rS3cret@db.internal:5432/prod, DNI: 00000000T, CUIT: 20-12345678-6, RUT: 12.345.678-5, Webhook: https://hooks.slack.com/services/T12345678/B12345678/abcdefghijklmnopqrstuvwx";
        let res = engine.redact(input);

        assert!(res.text.contains("[CONNECTION_URI_1]"));
        assert!(res.text.contains("[NATIONAL_ID_1]"));
        assert!(res.text.contains("[NATIONAL_ID_2]"));
        assert!(res.text.contains("[NATIONAL_ID_3]"));
        assert!(res.text.contains("[WEBHOOK_URL_1]"));
        assert!(!res.text.contains("Sup3rS3cret"));
    }
}

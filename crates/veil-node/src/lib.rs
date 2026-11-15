use napi::bindgen_prelude::*;
use napi_derive::napi;
use pii_veil_core::{RedactionMode, StreamingRestorer, Vault, VeilEngine, VeilPolicy};

#[napi(object)]
pub struct NodeRedactOutput {
    pub text: String,
    pub spans_found: u32,
    pub vault_json: String,
}

#[napi(object)]
pub struct NodeDetectedSpan {
    pub kind: String,
    pub start: u32,
    pub end: u32,
    pub original: String,
}

#[napi]
pub struct VeilStreamingRestorer {
    inner: StreamingRestorer,
}

#[napi]
impl VeilStreamingRestorer {
    #[napi(constructor)]
    pub fn new(vault_json: String) -> Result<Self> {
        let vault = Vault::from_json(&vault_json)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        Ok(Self {
            inner: vault.streaming_restorer(),
        })
    }

    /// Feeds a new LLM SSE token chunk and returns the portion safe to emit immediately.
    #[napi]
    pub fn push_chunk(&mut self, chunk: String) -> String {
        self.inner.push_chunk(&chunk)
    }

    /// Flushes and restores any remaining buffered characters at the end of the LLM stream.
    #[napi]
    pub fn finish(&mut self) -> String {
        self.inner.finish()
    }
}

#[napi]
pub struct VeilNode {
    engine: VeilEngine,
}

#[napi]
impl VeilNode {
    #[napi(constructor)]
    pub fn new(mode: Option<String>, secret_key: Option<String>) -> Result<Self> {
        let mode_str = mode.unwrap_or_else(|| "placeholder".to_string());
        let parsed_mode = match mode_str.to_ascii_lowercase().as_str() {
            "placeholder" => RedactionMode::Placeholder,
            "synthetic" => RedactionMode::Synthetic,
            "mask" => RedactionMode::Mask,
            other => {
                return Err(Error::new(
                    Status::InvalidArg,
                    format!(
                        "Unknown mode '{}'. Use 'placeholder', 'synthetic', or 'mask'.",
                        other
                    ),
                ))
            }
        };

        let key = secret_key.unwrap_or_else(|| "pii-veil-default-seed-key".to_string());
        Ok(Self {
            engine: VeilEngine::new(parsed_mode).with_secret_key(key.as_bytes()),
        })
    }

    /// Creates a `VeilNode` instance from a declarative `veil.json` policy string.
    #[napi(factory)]
    pub fn from_policy_json(policy_json: String) -> Result<Self> {
        let policy = VeilPolicy::from_json(&policy_json)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        let engine = VeilEngine::from_policy(policy)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        Ok(Self { engine })
    }

    /// Registers a custom entity regex rule (e.g. `addCustomRule("EMPLOYEE_ID", "\\bEMP-\\d{6}\\b")`).
    #[napi]
    pub fn add_custom_rule(&mut self, name: String, pattern: String) -> Result<()> {
        self.engine
            .add_custom_rule(name, &pattern)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))
    }

    /// Adds an allowlist entry (exact string like `"127.0.0.1"` or domain suffix like `"@example.com"`).
    #[napi]
    pub fn add_allowlist(&mut self, entry: String) {
        self.engine.add_allowlist(entry);
    }

    /// Adds a custom sensitive JSON key name whose string values are always redacted in `redactJson`.
    #[napi]
    pub fn add_sensitive_json_key(&mut self, key: String) {
        self.engine.add_sensitive_json_key(key);
    }

    /// Redacts PII & secrets from text and returns `{ text, spansFound, vaultJson }`.
    #[napi]
    pub fn redact(&self, text: String) -> Result<NodeRedactOutput> {
        let res = self.engine.redact(&text);
        let vault_json = res
            .vault
            .to_json()
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;

        Ok(NodeRedactOutput {
            text: res.text,
            spans_found: res.spans_found as u32,
            vault_json,
        })
    }

    /// Restores anonymized text back to original PII values using `vaultJson`.
    #[napi]
    pub fn restore(&self, sanitized_text: String, vault_json: String) -> Result<String> {
        let vault = Vault::from_json(&vault_json)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        Ok(vault.restore(&sanitized_text))
    }

    /// Encrypts a `vaultJson` string with `passphrase` for secure storage in Redis/S3/disk.
    #[napi]
    pub fn encrypt_vault(&self, vault_json: String, passphrase: String) -> Result<String> {
        let vault = Vault::from_json(&vault_json)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        vault
            .to_encrypted_json(&passphrase)
            .map_err(|e| Error::new(Status::GenericFailure, e))
    }

    /// Decrypts and authenticates an encrypted vault envelope back to `vaultJson`.
    #[napi]
    pub fn decrypt_vault(&self, encrypted_json: String, passphrase: String) -> Result<String> {
        let vault = Vault::from_encrypted_json(&encrypted_json, &passphrase)
            .map_err(|e| Error::new(Status::InvalidArg, e))?;
        vault
            .to_json()
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))
    }

    /// Sanitizes a JSON string while preserving structure and redacting sensitive keys.
    #[napi]
    pub fn redact_json(&self, json_str: String) -> Result<NodeRedactOutput> {
        let mut vault = Vault::new();
        let text = self
            .engine
            .redact_json_str(&json_str, &mut vault)
            .map_err(|e| Error::new(Status::InvalidArg, e.to_string()))?;
        let spans_found = vault.len() as u32;
        let vault_json = vault
            .to_json()
            .map_err(|e| Error::new(Status::GenericFailure, e.to_string()))?;

        Ok(NodeRedactOutput {
            text,
            spans_found,
            vault_json,
        })
    }

    /// Scans `text` without modifying it and returns all detected sensitive spans.
    #[napi]
    pub fn scan(&self, text: String) -> Vec<NodeDetectedSpan> {
        self.engine
            .scan(&text)
            .into_iter()
            .map(|s| NodeDetectedSpan {
                kind: s.kind.label().to_string(),
                start: s.start as u32,
                end: s.end as u32,
                original: s.original,
            })
            .collect()
    }
}

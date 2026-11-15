use pii_veil_core::{RedactionMode, StreamingRestorer, Vault, VeilEngine, VeilPolicy};
use pyo3::exceptions::PyValueError;
use pyo3::prelude::*;

#[pyclass(name = "StreamingRestorer")]
pub struct PyStreamingRestorer {
    inner: StreamingRestorer,
}

#[pymethods]
impl PyStreamingRestorer {
    /// Feeds a new LLM stream chunk (e.g. from OpenAI/Anthropic SSE) and returns the restored text ready to emit.
    pub fn push_chunk(&mut self, chunk: &str) -> String {
        self.inner.push_chunk(chunk)
    }

    /// Flushes and restores any remaining buffered characters when the LLM stream ends.
    pub fn finish(&mut self) -> String {
        self.inner.finish()
    }
}

#[pyclass(name = "Vault")]
#[derive(Clone)]
pub struct PyVault {
    inner: Vault,
}

#[pymethods]
impl PyVault {
    #[new]
    pub fn new() -> Self {
        Self {
            inner: Vault::new(),
        }
    }

    /// Restores all placeholders or synthetic tokens in `text` back to original values in O(N) time.
    pub fn restore(&self, text: &str) -> String {
        self.inner.restore(text)
    }

    /// Creates a `StreamingRestorer` for token-by-token LLM SSE stream restoration.
    pub fn streaming_restorer(&self) -> PyStreamingRestorer {
        PyStreamingRestorer {
            inner: self.inner.streaming_restorer(),
        }
    }

    /// Exports the vault to a JSON string.
    pub fn to_json(&self) -> PyResult<String> {
        self.inner
            .to_json()
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Loads a vault from a JSON string.
    #[staticmethod]
    pub fn from_json(json_str: &str) -> PyResult<Self> {
        let inner =
            Vault::from_json(json_str).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { inner })
    }

    /// Encrypts and authenticates the vault with `passphrase`, returning an encrypted JSON envelope.
    pub fn to_encrypted_json(&self, passphrase: &str) -> PyResult<String> {
        self.inner
            .to_encrypted_json(passphrase)
            .map_err(PyValueError::new_err)
    }

    /// Decrypts and verifies a `Vault` from an encrypted JSON envelope.
    #[staticmethod]
    pub fn from_encrypted_json(encrypted_json: &str, passphrase: &str) -> PyResult<Self> {
        let inner = Vault::from_encrypted_json(encrypted_json, passphrase)
            .map_err(PyValueError::new_err)?;
        Ok(Self { inner })
    }

    pub fn __len__(&self) -> usize {
        self.inner.len()
    }
}

#[pyclass(name = "Veil")]
pub struct PyVeil {
    engine: VeilEngine,
}

#[pymethods]
impl PyVeil {
    #[new]
    #[pyo3(signature = (mode="placeholder", secret_key="pii-veil-default-seed-key"))]
    pub fn new(mode: &str, secret_key: &str) -> PyResult<Self> {
        let parsed_mode = match mode.to_ascii_lowercase().as_str() {
            "placeholder" => RedactionMode::Placeholder,
            "synthetic" => RedactionMode::Synthetic,
            "mask" => RedactionMode::Mask,
            other => {
                return Err(PyValueError::new_err(format!(
                    "Invalid mode '{}'. Expected 'placeholder', 'synthetic', or 'mask'.",
                    other
                )))
            }
        };

        Ok(Self {
            engine: VeilEngine::new(parsed_mode).with_secret_key(secret_key.as_bytes()),
        })
    }

    /// Creates a `Veil` instance from a JSON policy string (`veil.json` format).
    #[staticmethod]
    pub fn from_policy_json(policy_json: &str) -> PyResult<Self> {
        let policy =
            VeilPolicy::from_json(policy_json).map_err(|e| PyValueError::new_err(e.to_string()))?;
        let engine =
            VeilEngine::from_policy(policy).map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok(Self { engine })
    }

    /// Registers a custom entity regex rule (e.g. `add_custom_rule("EMPLOYEE_ID", r"\bEMP-\d{6}\b")`).
    pub fn add_custom_rule(&mut self, name: &str, pattern: &str) -> PyResult<()> {
        self.engine
            .add_custom_rule(name, pattern)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }

    /// Adds an allowlist entry (exact string like `"127.0.0.1"` or domain suffix like `"@example.com"`).
    pub fn add_allowlist(&mut self, entry: &str) {
        self.engine.add_allowlist(entry);
    }

    /// Adds a custom sensitive JSON key name whose string values are always redacted in `redact_json`.
    pub fn add_sensitive_json_key(&mut self, key: &str) {
        self.engine.add_sensitive_json_key(key);
    }

    /// Redacts PII from `text` and returns `(redacted_text, vault)`.
    pub fn redact(&self, text: &str) -> (String, PyVault) {
        let res = self.engine.redact(text);
        (res.text, PyVault { inner: res.vault })
    }

    /// Redacts PII from `text` using an existing `Vault` (for multi-turn LLM conversations).
    pub fn redact_with_vault(&self, text: &str, vault: &mut PyVault) -> String {
        self.engine.redact_with_vault(text, &mut vault.inner)
    }

    /// Sanitizes a JSON string while preserving structure, returning `(sanitized_json, vault)`.
    pub fn redact_json(&self, json_str: &str) -> PyResult<(String, PyVault)> {
        let mut vault = Vault::new();
        let out = self
            .engine
            .redact_json_str(json_str, &mut vault)
            .map_err(|e| PyValueError::new_err(e.to_string()))?;
        Ok((out, PyVault { inner: vault }))
    }

    /// Scans `text` and returns a JSON array of detected spans (`[{kind, start, end, original}]`).
    pub fn scan_json(&self, text: &str) -> PyResult<String> {
        self.engine
            .scan_json(text)
            .map_err(|e| PyValueError::new_err(e.to_string()))
    }
}

#[pymodule]
fn pii_veil(m: &Bound<'_, PyModule>) -> PyResult<()> {
    m.add_class::<PyVeil>()?;
    m.add_class::<PyVault>()?;
    m.add_class::<PyStreamingRestorer>()?;
    Ok(())
}

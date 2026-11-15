use crate::detector::EntityKind;
use crate::strategy::RedactionMode;
use serde::{Deserialize, Serialize};

/// Declarative custom regex rule definition for [`VeilPolicy`].
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct CustomRuleConfig {
    /// Placeholder/entity label (e.g. `"EMPLOYEE_ID"`, `"INTERNAL_TICKET"`).
    pub name: String,
    /// Regular expression pattern.
    pub pattern: String,
}

/// Portable policy configuration for `VeilEngine` (can be loaded from `veil.json`).
#[derive(Debug, Clone, Serialize, Deserialize)]
pub struct VeilPolicy {
    /// Redaction mode: `"placeholder"`, `"synthetic"`, or `"mask"`.
    #[serde(default)]
    pub mode: RedactionMode,

    /// Optional secret seed key for deterministic synthetic replacements.
    #[serde(default = "default_secret_key")]
    pub secret_key: String,

    /// Built-in entity kinds to disable (e.g. `["IPV4", "PHONE"]`).
    #[serde(default)]
    pub disabled_entities: Vec<EntityKind>,

    /// Values or domain suffixes (starting with `@`, e.g. `"@example.com"`, `"127.0.0.1"`)
    /// that should never be redacted.
    #[serde(default)]
    pub allowlist: Vec<String>,

    /// Additional sensitive JSON keys whose string values should always be redacted.
    #[serde(default)]
    pub extra_sensitive_keys: Vec<String>,

    /// User-defined regex rules.
    #[serde(default)]
    pub custom_rules: Vec<CustomRuleConfig>,
}

fn default_secret_key() -> String {
    "pii-veil-default-seed-key-2026".to_string()
}

impl Default for VeilPolicy {
    fn default() -> Self {
        Self {
            mode: RedactionMode::Placeholder,
            secret_key: default_secret_key(),
            disabled_entities: Vec::new(),
            allowlist: vec![
                "127.0.0.1".to_string(),
                "0.0.0.0".to_string(),
                "@example.com".to_string(),
                "@example.org".to_string(),
            ],
            extra_sensitive_keys: vec![
                "session_token".to_string(),
                "x_api_key".to_string(),
                "authorization".to_string(),
            ],
            custom_rules: vec![CustomRuleConfig {
                name: "EMPLOYEE_ID".to_string(),
                pattern: r"\bEMP-\d{5,8}\b".to_string(),
            }],
        }
    }
}

impl VeilPolicy {
    /// Parses a [`VeilPolicy`] from a JSON string.
    pub fn from_json(json_str: &str) -> Result<Self, serde_json::Error> {
        serde_json::from_str(json_str)
    }

    /// Serializes this [`VeilPolicy`] into a pretty-printed JSON configuration string.
    pub fn to_json_pretty(&self) -> Result<String, serde_json::Error> {
        serde_json::to_string_pretty(self)
    }
}

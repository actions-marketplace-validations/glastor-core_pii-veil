use pii_veil_core::DetectedSpan;
use serde_json::{json, Value};
use std::collections::BTreeSet;

/// A file-scoped scan result passed to the SARIF 2.1.0 builder.
pub struct SarifFileResult<'a> {
    pub uri: String,
    pub content: &'a str,
    pub spans: Vec<DetectedSpan>,
}

/// Computes 1-based `(start_line, start_column)` for a byte offset inside `content`.
fn byte_offset_to_line_col(content: &str, byte_offset: usize) -> (usize, usize) {
    let clamped = byte_offset.min(content.len());
    let prefix = &content[..clamped];
    let line = prefix.bytes().filter(|&b| b == b'\n').count() + 1;
    let col = match prefix.rfind('\n') {
        Some(nl) => prefix[nl + 1..].chars().count() + 1,
        None => prefix.chars().count() + 1,
    };
    (line, col)
}

/// Maps an entity label to a SARIF severity level.
fn sarif_level_for_label(label: &str) -> &'static str {
    match label {
        "PRIVATE_KEY" | "AWS_KEY" | "OPENAI_KEY" | "ANTHROPIC_KEY" | "STRIPE_KEY"
        | "GITHUB_TOKEN" | "SLACK_TOKEN" | "GOOGLE_API_KEY" | "CONNECTION_URI" | "WEBHOOK_URL"
        | "JWT_TOKEN" | "CREDIT_CARD" | "IBAN" => "error",
        _ => "warning",
    }
}

/// Builds a SARIF 2.1.0 JSON report from scan findings.
///
/// Never embeds raw PII values in SARIF messages so reports can be safely uploaded
/// to GitHub Code Scanning (Security tab) without leaking sensitive data.
pub fn build_sarif_report(results_in: &[SarifFileResult<'_>]) -> Value {
    let mut rule_ids: BTreeSet<String> = BTreeSet::new();
    let mut sarif_results: Vec<Value> = Vec::new();

    for file_res in results_in {
        let normalized_uri = file_res.uri.replace('\\', "/");
        for span in &file_res.spans {
            let label = span.kind.label();
            let rule_id = format!("PII-VEIL-{}", label);
            rule_ids.insert(rule_id.clone());

            let (start_line, start_col) = byte_offset_to_line_col(file_res.content, span.start);
            let char_len = span.original.chars().count();

            sarif_results.push(json!({
                "ruleId": rule_id,
                "level": sarif_level_for_label(label),
                "message": {
                    "text": format!(
                        "Detected sensitive {} entity ({} characters redacted from report).",
                        label, char_len
                    )
                },
                "locations": [{
                    "physicalLocation": {
                        "artifactLocation": {
                            "uri": normalized_uri
                        },
                        "region": {
                            "startLine": start_line,
                            "startColumn": start_col
                        }
                    }
                }]
            }));
        }
    }

    let rules: Vec<Value> = rule_ids
        .into_iter()
        .map(|id| {
            let label = id.strip_prefix("PII-VEIL-").unwrap_or(&id);
            json!({
                "id": id,
                "name": label,
                "shortDescription": {
                    "text": format!("Sensitive {} detected by GLASTOR pii-veil", label)
                },
                "defaultConfiguration": {
                    "level": sarif_level_for_label(label)
                },
                "properties": {
                    "tags": ["security", "privacy", "dlp", "pii"]
                }
            })
        })
        .collect();

    json!({
        "$schema": "https://json.schemastore.org/sarif-2.1.0.json",
        "version": "2.1.0",
        "runs": [{
            "tool": {
                "driver": {
                    "name": "GLASTOR pii-veil",
                    "version": env!("CARGO_PKG_VERSION"),
                    "informationUri": "https://pii-veil.glastor.es",
                    "rules": rules
                }
            },
            "results": sarif_results
        }]
    })
}

#[cfg(test)]
mod tests {
    use super::*;
    use pii_veil_core::{RedactionMode, VeilEngine};

    #[test]
    fn test_sarif_2_1_0_structure_and_zero_raw_pii_leak() {
        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let content = "line1 ok\ncontact: alice@fintech.io\ncard: 4532-0151-1283-0366\n";
        let spans = engine.scan(content);
        let report = build_sarif_report(&[SarifFileResult {
            uri: "src\\config.txt".to_string(),
            content,
            spans,
        }]);

        let serialized = serde_json::to_string_pretty(&report).unwrap();
        assert_eq!(report["version"], "2.1.0");
        assert_eq!(
            report["$schema"],
            "https://json.schemastore.org/sarif-2.1.0.json"
        );
        assert_eq!(
            report["runs"][0]["tool"]["driver"]["name"],
            "GLASTOR pii-veil"
        );
        assert_eq!(report["runs"][0]["results"].as_array().unwrap().len(), 2);
        assert_eq!(
            report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["artifactLocation"]
                ["uri"],
            "src/config.txt"
        );
        assert_eq!(
            report["runs"][0]["results"][0]["locations"][0]["physicalLocation"]["region"]
                ["startLine"],
            2
        );
        // Critical security invariant: raw PII must NEVER appear in the SARIF output
        assert!(!serialized.contains("alice@fintech.io"));
        assert!(!serialized.contains("4532-0151-1283-0366"));
    }
}

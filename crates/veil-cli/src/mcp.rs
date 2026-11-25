use pii_veil_core::{RedactionMode, Vault, VeilEngine};
use serde_json::{json, Value};
use std::io::{self, BufRead, Write};

/// Runs a Model Context Protocol (MCP) server over `stdio` (JSON-RPC 2.0).
/// Exposes `veil_redact`, `veil_restore`, `veil_redact_json`, and `veil_scan` tools
/// for Claude Desktop, Cursor, Windsurf, and custom AI agents.
pub fn run_mcp_stdio_server(engine: VeilEngine) -> io::Result<()> {
    let stdin = io::stdin();
    let mut stdout = io::stdout();
    let mut session_vault = Vault::new();

    for line_res in stdin.lock().lines() {
        let line = line_res?;
        let trimmed = line.trim();
        if trimmed.is_empty() {
            continue;
        }

        let req: Value = match serde_json::from_str(trimmed) {
            Ok(v) => v,
            Err(e) => {
                let err_resp = json!({
                    "jsonrpc": "2.0",
                    "id": Value::Null,
                    "error": { "code": -32700, "message": format!("Parse error: {}", e) }
                });
                writeln!(stdout, "{}", err_resp)?;
                stdout.flush()?;
                continue;
            }
        };

        let id = req.get("id").cloned();
        let method = req.get("method").and_then(|m| m.as_str()).unwrap_or("");
        let params = req.get("params").cloned().unwrap_or_else(|| json!({}));

        // Notifications have no "id" and expect no response
        if id.is_none() {
            continue;
        }
        let req_id = id.unwrap();

        let response = match method {
            "initialize" => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "protocolVersion": "2024-11-05",
                    "capabilities": {
                        "tools": {}
                    },
                    "serverInfo": {
                        "name": "pii-veil-mcp",
                        "version": env!("CARGO_PKG_VERSION")
                    }
                }
            }),
            "ping" => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {}
            }),
            "tools/list" => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "tools": [
                        {
                            "name": "veil_redact",
                            "description": "Anonymizes PII and secrets in text (emails, credit cards, IBANs, API keys, DB URIs, national IDs) and stores reversible mappings in the session vault.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": { "type": "string", "description": "Input text to redact" },
                                    "mode": { "type": "string", "enum": ["placeholder", "synthetic", "mask"], "description": "Optional redaction mode override" }
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "veil_restore",
                            "description": "Restores placeholder tokens (e.g. [EMAIL_1], [CREDIT_CARD_1]) back to their original PII values using the active session vault or an explicit vault_json.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": { "type": "string", "description": "Sanitized text containing placeholders" },
                                    "vault_json": { "type": "string", "description": "Optional serialized Vault JSON; uses session vault if omitted" }
                                },
                                "required": ["text"]
                            }
                        },
                        {
                            "name": "veil_redact_json",
                            "description": "Sanitizes a JSON string while preserving structure, redacting both regex PII and sensitive keys (password, api_key, secret, cvv).",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "json": { "type": "string", "description": "Raw JSON payload string" }
                                },
                                "required": ["json"]
                            }
                        },
                        {
                            "name": "veil_scan",
                            "description": "Audits text or code for PII and secrets without modifying it, returning detected spans.",
                            "inputSchema": {
                                "type": "object",
                                "properties": {
                                    "text": { "type": "string", "description": "Text or source code to scan" }
                                },
                                "required": ["text"]
                            }
                        }
                    ]
                }
            }),
            "tools/call" => {
                let tool_name = params.get("name").and_then(|n| n.as_str()).unwrap_or("");
                let args = params
                    .get("arguments")
                    .cloned()
                    .unwrap_or_else(|| json!({}));
                handle_tool_call(req_id, tool_name, &args, &engine, &mut session_vault)
            }
            _ => json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "error": { "code": -32601, "message": format!("Method not found: {}", method) }
            }),
        };

        writeln!(stdout, "{}", response)?;
        stdout.flush()?;
    }

    Ok(())
}

fn handle_tool_call(
    req_id: Value,
    tool_name: &str,
    args: &Value,
    default_engine: &VeilEngine,
    session_vault: &mut Vault,
) -> Value {
    match tool_name {
        "veil_redact" => {
            let text = args.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let active_engine = match args.get("mode").and_then(|m| m.as_str()) {
                Some("placeholder") => default_engine.with_mode(RedactionMode::Placeholder),
                Some("synthetic") => default_engine.with_mode(RedactionMode::Synthetic),
                Some("mask") => default_engine.with_mode(RedactionMode::Mask),
                _ => default_engine.clone(),
            };

            let (redacted, count) = active_engine.redact_with_vault_counted(text, session_vault);
            let payload = json!({
                "redacted_text": redacted,
                "spans_redacted": count,
                "session_vault_entries": session_vault.len()
            });

            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{ "type": "text", "text": serde_json::to_string_pretty(&payload).unwrap() }]
                }
            })
        }
        "veil_restore" => {
            let text = args.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let restored = if let Some(v_json) = args.get("vault_json").and_then(|v| v.as_str()) {
                match Vault::from_json(v_json) {
                    Ok(v) => v.restore(text),
                    Err(e) => {
                        return json!({
                            "jsonrpc": "2.0",
                            "id": req_id,
                            "result": {
                                "isError": true,
                                "content": [{ "type": "text", "text": format!("Invalid vault_json: {}", e) }]
                            }
                        })
                    }
                }
            } else {
                session_vault.restore(text)
            };

            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{ "type": "text", "text": restored }]
                }
            })
        }
        "veil_redact_json" => {
            let raw_json = args.get("json").and_then(|j| j.as_str()).unwrap_or("{}");
            match default_engine.redact_json_str(raw_json, session_vault) {
                Ok(sanitized) => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "content": [{ "type": "text", "text": sanitized }]
                    }
                }),
                Err(e) => json!({
                    "jsonrpc": "2.0",
                    "id": req_id,
                    "result": {
                        "isError": true,
                        "content": [{ "type": "text", "text": format!("JSON error: {}", e) }]
                    }
                }),
            }
        }
        "veil_scan" => {
            let text = args.get("text").and_then(|t| t.as_str()).unwrap_or("");
            let spans = default_engine.scan(text);
            let out = serde_json::to_string_pretty(&spans).unwrap_or_else(|_| "[]".to_string());
            json!({
                "jsonrpc": "2.0",
                "id": req_id,
                "result": {
                    "content": [{ "type": "text", "text": out }]
                }
            })
        }
        other => json!({
            "jsonrpc": "2.0",
            "id": req_id,
            "error": { "code": -32602, "message": format!("Unknown tool: {}", other) }
        }),
    }
}

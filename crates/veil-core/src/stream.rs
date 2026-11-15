use crate::detector::EntityKind;
use crate::strategy::generate_replacement;
use crate::{Vault, VeilEngine};
use serde::{Deserialize, Serialize};
use serde_json::Value;
use std::collections::HashSet;
use std::io::{self, BufRead, Write};

/// Input stream format for [`VeilEngine::redact_stream`].
#[derive(Debug, Clone, Copy, PartialEq, Eq, Serialize, Deserialize, Default)]
#[serde(rename_all = "snake_case")]
pub enum StreamFormat {
    /// Arbitrary line-oriented text or application logs.
    #[default]
    Lines,
    /// Newline-delimited JSON (`NDJSON` / `.jsonl`), sanitizing both JSON keys and string values.
    Ndjson,
    /// PostgreSQL (`pg_dump` `COPY ... FROM stdin`) and SQL `INSERT INTO` dumps.
    /// Preserves DDL/schema statements (`CREATE`, `ALTER`, `SET`, `--`) untouched.
    Sql,
    /// Comma-Separated Values (`CSV`) with automatic header inspection for sensitive columns
    /// (`password`, `secret`, `api_key`, `cvv`, `token`, etc.) plus regex PII detection per cell.
    Csv,
}

/// Statistics returned after processing a stream.
#[derive(Debug, Clone, Copy, Default, PartialEq, Eq, Serialize, Deserialize)]
pub struct StreamStats {
    pub lines_processed: usize,
    pub bytes_processed: usize,
    pub spans_redacted: usize,
    pub unique_entities: usize,
}

/// Returns `true` if a SQL line is a comment or schema/DDL command that should pass through untouched.
#[inline]
fn is_sql_ddl_or_comment(trimmed: &str) -> bool {
    if trimmed.is_empty()
        || trimmed.starts_with("--")
        || trimmed.starts_with("/*")
        || trimmed == "\\."
    {
        return true;
    }

    let upper_prefix: String = trimmed
        .chars()
        .take(16)
        .collect::<String>()
        .to_ascii_uppercase();
    upper_prefix.starts_with("SET ")
        || upper_prefix.starts_with("SELECT PG_")
        || upper_prefix.starts_with("CREATE ")
        || upper_prefix.starts_with("ALTER ")
        || upper_prefix.starts_with("DROP ")
        || upper_prefix.starts_with("COMMENT ON ")
        || upper_prefix.starts_with("GRANT ")
        || upper_prefix.starts_with("REVOKE ")
        || upper_prefix.starts_with("BEGIN")
        || upper_prefix.starts_with("COMMIT")
}

/// Splits a CSV line into fields, respecting RFC 4180 double-quoted fields and escaped `""`.
fn parse_csv_row(line: &str) -> Vec<String> {
    let mut fields = Vec::new();
    let mut current = String::new();
    let mut in_quotes = false;
    let mut chars = line.chars().peekable();

    while let Some(c) = chars.next() {
        if in_quotes {
            if c == '"' {
                if chars.peek() == Some(&'"') {
                    current.push('"');
                    let _ = chars.next();
                } else {
                    in_quotes = false;
                }
            } else {
                current.push(c);
            }
        } else if c == '"' {
            in_quotes = true;
        } else if c == ',' {
            fields.push(std::mem::take(&mut current));
        } else {
            current.push(c);
        }
    }
    fields.push(current);
    fields
}

/// Formats a slice of CSV fields back into an RFC 4180 CSV line.
fn format_csv_row(fields: &[String]) -> String {
    fields
        .iter()
        .map(|f| {
            if f.contains(',') || f.contains('"') || f.contains('\n') {
                format!("\"{}\"", f.replace('"', "\"\""))
            } else {
                f.clone()
            }
        })
        .collect::<Vec<_>>()
        .join(",")
}

impl VeilEngine {
    /// Streams input from `reader` line-by-line in $O(1)$ memory per line, writing sanitized
    /// output to `writer` and recording reversible mappings into `vault`.
    pub fn redact_stream<R: BufRead, W: Write>(
        &self,
        mut reader: R,
        mut writer: W,
        format: StreamFormat,
        vault: &mut Vault,
    ) -> io::Result<StreamStats> {
        let mut stats = StreamStats::default();
        let mut line_buf = String::with_capacity(4096);
        let mut in_pg_copy_block = false;
        let mut csv_sensitive_cols: Option<HashSet<usize>> = None;

        loop {
            line_buf.clear();
            let bytes_read = reader.read_line(&mut line_buf)?;
            if bytes_read == 0 {
                break;
            }

            stats.lines_processed += 1;
            stats.bytes_processed += bytes_read;

            let has_crlf = line_buf.ends_with("\r\n");
            let has_lf = !has_crlf && line_buf.ends_with('\n');
            let content = line_buf.trim_end_matches(['\r', '\n']);

            match format {
                StreamFormat::Lines => {
                    let (redacted, count) = self.redact_with_vault_counted(content, vault);
                    stats.spans_redacted += count;
                    writer.write_all(redacted.as_bytes())?;
                }
                StreamFormat::Ndjson => {
                    let trimmed = content.trim();
                    if trimmed.starts_with('{') && trimmed.ends_with('}') {
                        if let Ok(mut json_val) = serde_json::from_str::<Value>(trimmed) {
                            let spans = self.redact_json_value_counted(&mut json_val, vault);
                            stats.spans_redacted += spans;
                            let serialized = serde_json::to_string(&json_val)
                                .unwrap_or_else(|_| content.to_string());
                            writer.write_all(serialized.as_bytes())?;
                        } else {
                            let (redacted, count) = self.redact_with_vault_counted(content, vault);
                            stats.spans_redacted += count;
                            writer.write_all(redacted.as_bytes())?;
                        }
                    } else {
                        let (redacted, count) = self.redact_with_vault_counted(content, vault);
                        stats.spans_redacted += count;
                        writer.write_all(redacted.as_bytes())?;
                    }
                }
                StreamFormat::Sql => {
                    let trimmed = content.trim();
                    if in_pg_copy_block {
                        if trimmed == "\\." {
                            in_pg_copy_block = false;
                            writer.write_all(content.as_bytes())?;
                        } else {
                            let (redacted, count) = self.redact_with_vault_counted(content, vault);
                            stats.spans_redacted += count;
                            writer.write_all(redacted.as_bytes())?;
                        }
                    } else {
                        let upper_start: String = trimmed
                            .chars()
                            .take(12)
                            .collect::<String>()
                            .to_ascii_uppercase();
                        if upper_start.starts_with("COPY ")
                            && trimmed.to_ascii_lowercase().ends_with("from stdin;")
                        {
                            in_pg_copy_block = true;
                            writer.write_all(content.as_bytes())?;
                        } else if is_sql_ddl_or_comment(trimmed) {
                            writer.write_all(content.as_bytes())?;
                        } else {
                            let (redacted, count) = self.redact_with_vault_counted(content, vault);
                            stats.spans_redacted += count;
                            writer.write_all(redacted.as_bytes())?;
                        }
                    }
                }
                StreamFormat::Csv => {
                    if let Some(sens_cols) = &csv_sensitive_cols {
                        let mut fields = parse_csv_row(content);
                        for (idx, field) in fields.iter_mut().enumerate() {
                            if field.is_empty() {
                                continue;
                            }
                            let (redacted, count) = self.redact_with_vault_counted(field, vault);
                            if count > 0 {
                                *field = redacted;
                                stats.spans_redacted += count;
                            } else if sens_cols.contains(&idx) {
                                let kind = EntityKind::Custom("SECRET_FIELD".to_string());
                                let mode = self.mode();
                                let secret = self.secret_key();
                                let rep = vault.get_or_insert(kind.clone(), field, |i| {
                                    generate_replacement(mode, &kind, field, i, secret)
                                });
                                *field = rep;
                                stats.spans_redacted += 1;
                            }
                        }
                        let formatted = format_csv_row(&fields);
                        writer.write_all(formatted.as_bytes())?;
                    } else {
                        // First non-empty line is treated as the CSV header row
                        let headers = parse_csv_row(content);
                        let mut sens = HashSet::new();
                        for (idx, h) in headers.iter().enumerate() {
                            if self.is_sensitive_key_name(h.trim()) {
                                sens.insert(idx);
                            }
                        }
                        csv_sensitive_cols = Some(sens);
                        writer.write_all(content.as_bytes())?;
                    }
                }
            }

            if has_crlf {
                writer.write_all(b"\r\n")?;
            } else if has_lf {
                writer.write_all(b"\n")?;
            }
        }

        writer.flush()?;
        stats.unique_entities = vault.len();
        Ok(stats)
    }
}

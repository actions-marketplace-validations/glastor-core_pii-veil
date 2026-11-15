mod mcp;
mod proxy;

use clap::{Parser, Subcommand, ValueEnum};
use pii_veil_core::{RedactionMode, StreamFormat, Vault, VeilEngine, VeilPolicy};
use std::collections::BTreeMap;
use std::fs::{self, File};
use std::io::{self, BufReader, BufWriter, Read, Write};
use std::path::PathBuf;
use std::process;
use std::time::Instant;

#[derive(Parser)]
#[command(
    name = "veil",
    version,
    about = "🛡️ pii-veil: Ultrafast, deterministic & reversible PII/Secret anonymizer for LLMs, MCP Agents, Logs, and SQL/CSV streams."
)]
struct Cli {
    #[command(subcommand)]
    command: Commands,
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum CliMode {
    /// Semantic tokens like [EMAIL_1], [CREDIT_CARD_1] (Best for LLMs & MCP)
    Placeholder,
    /// Deterministic realistic fake data via keyed hash (Best for SQL dumps & E2E)
    Synthetic,
    /// Irreversible partial masking like j***@company.com (Best for Logs)
    Mask,
}

impl From<CliMode> for RedactionMode {
    fn from(val: CliMode) -> Self {
        match val {
            CliMode::Placeholder => RedactionMode::Placeholder,
            CliMode::Synthetic => RedactionMode::Synthetic,
            CliMode::Mask => RedactionMode::Mask,
        }
    }
}

#[derive(Copy, Clone, PartialEq, Eq, PartialOrd, Ord, ValueEnum, Debug)]
enum CliStreamFormat {
    /// Plain line-oriented text or application logs
    Lines,
    /// Newline-delimited JSON (.jsonl / NDJSON) with sensitive key DLP
    Ndjson,
    /// PostgreSQL COPY / SQL INSERT dumps (preserves DDL & comments)
    Sql,
    /// Comma-Separated Values (.csv) with automatic sensitive column detection
    Csv,
}

impl From<CliStreamFormat> for StreamFormat {
    fn from(val: CliStreamFormat) -> Self {
        match val {
            CliStreamFormat::Lines => StreamFormat::Lines,
            CliStreamFormat::Ndjson => StreamFormat::Ndjson,
            CliStreamFormat::Sql => StreamFormat::Sql,
            CliStreamFormat::Csv => StreamFormat::Csv,
        }
    }
}

#[derive(Subcommand)]
enum Commands {
    /// Redact PII and secrets from text, a file, or STDIN
    Redact {
        /// Input text to redact (if omitted, reads from --file or STDIN)
        #[arg(short, long)]
        text: Option<String>,

        /// Path to an input file to redact
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Redaction strategy mode
        #[arg(short, long, value_enum, default_value_t = CliMode::Placeholder)]
        mode: CliMode,

        /// Secret seed key for deterministic synthetic replacements
        #[arg(short, long, default_value = "pii-veil-default-seed-key")]
        key: String,

        /// Optional path to a `veil.json` policy file (overrides mode/key and loads custom rules & allowlists)
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Optional file path to save the reversible Vault JSON
        #[arg(long)]
        vault_out: Option<PathBuf>,

        /// Optional passphrase to encrypt and authenticate the exported Vault file
        #[arg(long)]
        vault_pass: Option<String>,
    },

    /// Restore original PII values into sanitized text or stream using a saved Vault file
    Restore {
        /// Sanitized text (if omitted, reads from --file or STDIN)
        #[arg(short, long)]
        text: Option<String>,

        /// Path to sanitized input file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Optional output file path (when omitted, prints to STDOUT)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Path to the Vault JSON file created during `redact --vault-out` or `stream --vault-out`
        #[arg(short, long)]
        vault: PathBuf,

        /// Passphrase if the Vault file was encrypted with `--vault-pass`
        #[arg(long)]
        vault_pass: Option<String>,

        /// Stream line-by-line in O(1) memory (ideal for restoring multi-GB files)
        #[arg(long)]
        stream: bool,
    },

    /// Sanitize a JSON payload (redacts both regex entities and sensitive keys like "password" or "api_key")
    Json {
        /// Raw JSON string (or reads from --file / STDIN)
        #[arg(short, long)]
        json: Option<String>,

        /// Path to JSON file
        #[arg(short, long)]
        file: Option<PathBuf>,

        /// Redaction strategy mode
        #[arg(short, long, value_enum, default_value_t = CliMode::Placeholder)]
        mode: CliMode,

        /// Optional path to a `veil.json` policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Optional file path to save the reversible Vault JSON
        #[arg(long)]
        vault_out: Option<PathBuf>,

        /// Optional passphrase to encrypt and authenticate the exported Vault file
        #[arg(long)]
        vault_pass: Option<String>,
    },

    /// Stream-anonymize multi-GB log files, NDJSON (.jsonl), CSVs, or SQL dumps (`pg_dump`) in O(1) memory per line
    Stream {
        /// Input file path (if omitted, streams from STDIN)
        #[arg(short, long)]
        input: Option<PathBuf>,

        /// Output file path (if omitted, writes to STDOUT)
        #[arg(short, long)]
        output: Option<PathBuf>,

        /// Stream format: `lines`, `ndjson`, `sql`, or `csv`
        #[arg(short, long, value_enum, default_value_t = CliStreamFormat::Lines)]
        format: CliStreamFormat,

        /// Redaction strategy mode
        #[arg(short, long, value_enum, default_value_t = CliMode::Synthetic)]
        mode: CliMode,

        /// Secret seed key for deterministic synthetic replacements
        #[arg(short, long, default_value = "pii-veil-default-seed-key")]
        key: String,

        /// Optional path to a `veil.json` policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Optional file path to save the reversible Vault JSON
        #[arg(long)]
        vault_out: Option<PathBuf>,

        /// Optional passphrase to encrypt and authenticate the exported Vault file
        #[arg(long)]
        vault_pass: Option<String>,
    },

    /// Audit/scan text, files, or directories for PII and secrets without modifying them (CI/CD DLP check)
    Scan {
        /// Input text to scan (or reads from --file / --path / STDIN)
        #[arg(short, long)]
        text: Option<String>,

        /// Path to a file or directory to scan recursively
        #[arg(short, long, visible_alias = "path")]
        file: Option<PathBuf>,

        /// Comma-separated path substrings to exclude when scanning a directory (e.g. "examples,tests")
        #[arg(long, default_value = "")]
        exclude: String,

        /// Optional path to a `veil.json` policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,

        /// Output scan findings as machine-readable JSON
        #[arg(long)]
        json: bool,

        /// Exit with status code 1 if any PII or secret is detected (useful for CI/CD pre-commit hooks)
        #[arg(long)]
        fail_on_detect: bool,
    },

    /// Start a Model Context Protocol (MCP) server over STDIO for Claude Desktop, Cursor, or Windsurf
    Mcp {
        /// Optional path to a `veil.json` policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },

    /// Start a local HTTP/SSE DLP reverse proxy that redacts outgoing LLM prompts and restores incoming SSE/JSON responses
    Proxy {
        /// Local address to bind the HTTP proxy to
        #[arg(short, long, default_value = "127.0.0.1:8080")]
        listen: String,

        /// Upstream HTTP server address (`host:port`, e.g. `127.0.0.1:11434` for Ollama or local gateway)
        #[arg(short, long)]
        upstream: Option<String>,

        /// Enable built-in local LLM echo / SSE simulator mode for testing without an upstream server
        #[arg(long)]
        echo: bool,

        /// Optional path to a `veil.json` policy file
        #[arg(short, long)]
        policy: Option<PathBuf>,
    },

    /// Generate a starter `veil.json` policy configuration file with custom rules and allowlists
    Init {
        /// Output path for the policy file
        #[arg(short, long, default_value = "veil.json")]
        output: PathBuf,

        /// Print the policy template to STDOUT instead of writing a file
        #[arg(long)]
        stdout: bool,
    },

    /// Run an interactive showcase of LLM Roundtrip, Deterministic SQL/Log Anonymization, and JSON DLP
    Demo,

    /// Run an in-memory performance benchmark (throughput in MB/s and latency in microseconds)
    Bench {
        /// Number of iterations to run
        #[arg(short, long, default_value_t = 10_000)]
        iterations: usize,
    },
}

fn collect_scannable_files(
    root: &std::path::Path,
    excludes: &[String],
    out: &mut Vec<PathBuf>,
) -> io::Result<()> {
    const IGNORED_DIRS: &[&str] = &[
        ".git",
        "target",
        "node_modules",
        ".venv",
        "venv",
        "dist",
        "build",
    ];
    for entry in fs::read_dir(root)? {
        let entry = entry?;
        let path = entry.path();
        let path_str = path.to_string_lossy();
        if excludes
            .iter()
            .any(|ex| !ex.is_empty() && path_str.contains(ex.as_str()))
        {
            continue;
        }
        if path.is_dir() {
            if let Some(name) = path.file_name().and_then(|n| n.to_str()) {
                if IGNORED_DIRS.contains(&name) {
                    continue;
                }
            }
            collect_scannable_files(&path, excludes, out)?;
        } else if path.is_file() {
            out.push(path);
        }
    }
    Ok(())
}

fn read_input(text: Option<String>, file: Option<PathBuf>) -> io::Result<String> {
    if let Some(t) = text {
        return Ok(t);
    }
    if let Some(path) = file {
        return fs::read_to_string(path);
    }
    let mut buf = String::new();
    io::stdin().read_to_string(&mut buf)?;
    Ok(buf)
}

fn build_engine(
    mode: CliMode,
    key: Option<&str>,
    policy_path: Option<PathBuf>,
) -> Result<VeilEngine, Box<dyn std::error::Error>> {
    if let Some(path) = policy_path {
        let raw = fs::read_to_string(path)?;
        let policy = VeilPolicy::from_json(&raw)?;
        Ok(VeilEngine::from_policy(policy)?)
    } else {
        let mut engine = VeilEngine::new(mode.into());
        if let Some(k) = key {
            engine = engine.with_secret_key(k.as_bytes());
        }
        Ok(engine)
    }
}

fn save_vault_file(
    vault: &Vault,
    vault_path: &PathBuf,
    vault_pass: Option<&str>,
) -> Result<(), Box<dyn std::error::Error>> {
    let serialized = if let Some(pass) = vault_pass {
        vault.to_encrypted_json(pass)?
    } else {
        vault.to_json()?
    };
    fs::write(vault_path, serialized)?;
    let enc_badge = if vault_pass.is_some() {
        "encrypted "
    } else {
        ""
    };
    eprintln!(
        "✔ Saved {}reversible vault ({} entities) to {}",
        enc_badge,
        vault.len(),
        vault_path.display()
    );
    Ok(())
}

fn load_vault_file(
    vault_path: &PathBuf,
    vault_pass: Option<&str>,
) -> Result<Vault, Box<dyn std::error::Error>> {
    let raw = fs::read_to_string(vault_path)?;
    if let Some(pass) = vault_pass {
        Ok(Vault::from_encrypted_json(&raw, pass)?)
    } else {
        Ok(Vault::from_json(&raw)?)
    }
}

fn main() -> Result<(), Box<dyn std::error::Error>> {
    let cli = Cli::parse();

    match cli.command {
        Commands::Redact {
            text,
            file,
            mode,
            key,
            policy,
            vault_out,
            vault_pass,
        } => {
            let input = read_input(text, file)?;
            let engine = build_engine(mode, Some(&key), policy)?;
            let mut vault = Vault::new();
            let output = engine.redact_with_vault(&input, &mut vault);

            println!("{}", output);

            if let Some(vault_path) = vault_out {
                save_vault_file(&vault, &vault_path, vault_pass.as_deref())?;
            }
        }

        Commands::Restore {
            text,
            file,
            output,
            vault,
            vault_pass,
            stream,
        } => {
            let loaded_vault = load_vault_file(&vault, vault_pass.as_deref())?;
            if stream {
                let reader: Box<dyn io::BufRead> = match file {
                    Some(path) => Box::new(BufReader::new(File::open(path)?)),
                    None => Box::new(BufReader::new(io::stdin().lock())),
                };
                let writer: Box<dyn Write> = match output {
                    Some(path) => Box::new(BufWriter::new(File::create(path)?)),
                    None => Box::new(BufWriter::new(io::stdout().lock())),
                };
                let lines = loaded_vault.restore_stream(reader, writer)?;
                eprintln!("✔ Restored {} line(s) in streaming mode.", lines);
            } else {
                let input = read_input(text, file)?;
                let restored = loaded_vault.restore(&input);
                if let Some(out_path) = output {
                    fs::write(out_path, restored)?;
                } else {
                    println!("{}", restored);
                }
            }
        }

        Commands::Json {
            json,
            file,
            mode,
            policy,
            vault_out,
            vault_pass,
        } => {
            let input = read_input(json, file)?;
            let engine = build_engine(mode, None, policy)?;
            let mut vault = Vault::new();
            let sanitized = engine.redact_json_str(&input, &mut vault)?;
            println!("{}", sanitized);

            if let Some(vault_path) = vault_out {
                save_vault_file(&vault, &vault_path, vault_pass.as_deref())?;
            }
        }

        Commands::Stream {
            input,
            output,
            format,
            mode,
            key,
            policy,
            vault_out,
            vault_pass,
        } => {
            let engine = build_engine(mode, Some(&key), policy)?;
            let mut vault = Vault::new();
            let start = Instant::now();

            let reader: Box<dyn io::BufRead> = match input {
                Some(path) => Box::new(BufReader::new(File::open(path)?)),
                None => Box::new(BufReader::new(io::stdin().lock())),
            };

            let writer: Box<dyn Write> = match output {
                Some(path) => Box::new(BufWriter::new(File::create(path)?)),
                None => Box::new(BufWriter::new(io::stdout().lock())),
            };

            let stats = engine.redact_stream(reader, writer, format.into(), &mut vault)?;
            let elapsed = start.elapsed();

            if let Some(vault_path) = vault_out {
                save_vault_file(&vault, &vault_path, vault_pass.as_deref())?;
            }

            eprintln!(
                "✔ Stream complete in {:.2?}: {} lines ({} bytes), {} spans redacted ({} unique entities)",
                elapsed,
                stats.lines_processed,
                stats.bytes_processed,
                stats.spans_redacted,
                stats.unique_entities
            );
        }

        Commands::Scan {
            text,
            file,
            exclude,
            policy,
            json,
            fail_on_detect,
        } => {
            let engine = build_engine(CliMode::Placeholder, None, policy)?;
            let excludes: Vec<String> = exclude
                .split(',')
                .map(|s| s.trim().to_string())
                .filter(|s| !s.is_empty())
                .collect();

            if let Some(ref target_path) = file {
                if target_path.is_dir() {
                    let mut files = Vec::new();
                    collect_scannable_files(target_path, &excludes, &mut files)?;
                    files.sort();

                    let mut total_spans = 0usize;
                    let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
                    let mut file_findings = Vec::new();

                    for f in files {
                        if let Ok(content) = fs::read_to_string(&f) {
                            let spans = engine.scan(&content);
                            if !spans.is_empty() {
                                total_spans += spans.len();
                                for s in &spans {
                                    *by_kind.entry(s.kind.label().to_string()).or_insert(0) += 1;
                                }
                                file_findings.push(serde_json::json!({
                                    "file": f.display().to_string(),
                                    "spans_count": spans.len(),
                                    "spans": spans,
                                }));
                            }
                        }
                    }

                    if json {
                        println!(
                            "{}",
                            serde_json::to_string_pretty(&serde_json::json!({
                                "total_spans": total_spans,
                                "by_kind": by_kind,
                                "files": file_findings,
                            }))?
                        );
                    } else if total_spans == 0 {
                        println!(
                            "✅ Clean: No PII or secrets detected across directory '{}'.",
                            target_path.display()
                        );
                    } else {
                        println!(
                            "⚠️  Detected {} sensitive entity span(s) across {} file(s):",
                            total_spans,
                            file_findings.len()
                        );
                        for (kind, count) in by_kind {
                            println!("   • {:<18} : {}", kind, count);
                        }
                    }

                    if fail_on_detect && total_spans > 0 {
                        process::exit(1);
                    }
                    return Ok(());
                }
            }

            let input = read_input(text, file)?;
            let spans = engine.scan(&input);

            if json {
                println!("{}", serde_json::to_string_pretty(&spans)?);
            } else if spans.is_empty() {
                println!("✅ Clean: No PII or secrets detected.");
            } else {
                let mut by_kind: BTreeMap<String, usize> = BTreeMap::new();
                for s in &spans {
                    *by_kind.entry(s.kind.label().to_string()).or_insert(0) += 1;
                }
                println!("⚠️  Detected {} sensitive entity span(s):", spans.len());
                for (kind, count) in by_kind {
                    println!("   • {:<18} : {}", kind, count);
                }
            }

            if fail_on_detect && !spans.is_empty() {
                process::exit(1);
            }
        }

        Commands::Mcp { policy } => {
            let engine = build_engine(CliMode::Placeholder, None, policy)?;
            mcp::run_mcp_stdio_server(engine)?;
        }

        Commands::Proxy {
            listen,
            upstream,
            echo,
            policy,
        } => {
            let engine = build_engine(CliMode::Placeholder, None, policy)?;
            let cfg = proxy::ProxyConfig {
                listen_addr: listen,
                upstream_addr: upstream,
                echo_mode: echo,
            };
            proxy::run_http_proxy(engine, cfg)?;
        }

        Commands::Init { output, stdout } => {
            let default_policy = VeilPolicy::default();
            let pretty = default_policy.to_json_pretty()?;
            if stdout {
                println!("{}", pretty);
            } else {
                fs::write(&output, pretty)?;
                println!(
                    "✔ Created starter policy configuration at {}",
                    output.display()
                );
            }
        }

        Commands::Demo => {
            run_demo()?;
        }

        Commands::Bench { iterations } => {
            run_benchmark(iterations);
        }
    }

    Ok(())
}

fn run_demo() -> Result<(), Box<dyn std::error::Error>> {
    println!("================================================================================");
    println!("🛡️  PII-VEIL: DEMO DE DOBLE MERCADO (IA / MCP + LOGS + BASES DE DATOS SQL/CSV)");
    println!("================================================================================\n");

    let sample_prompt = "Hola soporte, soy Martín Gómez (martin.gomez@fintech.io, CUIT 20-12345678-6), mi teléfono es +54 911 4521-8890. \
Intento pagar con mi Visa 4532-0151-1283-0366 o IBAN DE89 3704 0044 0532 0130 00 desde la IP 181.45.210.14 \
pero falla mi conexión postgres://admin:SecretPass99@db.fintech.io:5432/prod y mi clave sk-proj-99a8b7c6d5e4f3g2h1i0jklmnopqrst.";

    // 1. MODO PLACEHOLDER (Ideal para Agentes de IA / LLMs)
    println!("1️⃣  [MODO IA / LLM ROUNDTRIP] -> Anonimización Reversible con Tokens Semánticos");
    println!("--------------------------------------------------------------------------------");
    let llm_engine = VeilEngine::new(RedactionMode::Placeholder);
    let res = llm_engine.redact(sample_prompt);
    println!("📥 Prompt Original del Usuario:\n   {}\n", sample_prompt);
    println!(
        "🔒 Prompt Seguro enviado a OpenAI/Claude ({} entidades protegidas):\n   {}\n",
        res.spans_found, res.text
    );

    let simulated_llm_reply = "Hola! He verificado la cuenta de [EMAIL_1] (ID fiscal [NATIONAL_ID_1]), la tarjeta [CREDIT_CARD_1] y cuenta [IBAN_1] desde [IPV4_1]. Rotamos las credenciales de [CONNECTION_URI_1] y [OPENAI_KEY_1] y enviamos SMS al [PHONE_1].";
    println!(
        "🤖 Respuesta del LLM (usando tokens sin conocer los datos reales):\n   {}\n",
        simulated_llm_reply
    );

    let restored_reply = res.vault.restore(simulated_llm_reply);
    println!(
        "🔓 Respuesta Restaurada al Usuario (en < 5 microsegundos con Aho-Corasick):\n   {}\n",
        restored_reply
    );

    // 2. MODO SYNTHETIC (Ideal para pg_dump / SQL / Staging)
    println!("2️⃣  [MODO SYNTHETIC DETERMINISTA] -> Para Dumps SQL, CSVs y Entornos de Prueba");
    println!("--------------------------------------------------------------------------------");
    let synth_engine =
        VeilEngine::new(RedactionMode::Synthetic).with_secret_key("clave-secreta-empresa");
    let synth_res = synth_engine.redact(sample_prompt);
    println!(
        "🧬 Salida con Datos Sintéticos Realistas (Tarjeta Luhn + IBAN Mod-97 válidos):\n   {}\n",
        synth_res.text
    );

    // 3. MODO JSON DLP (Ideal para Node.js / Python APIs / Logs)
    println!("3️⃣  [MODO JSON DLP] -> Sanitización de Payloads y Claves Sensibles (Node/Python)");
    println!("--------------------------------------------------------------------------------");
    let sample_json = r#"{
  "event": "checkout_failed",
  "customer_email": "martin.gomez@fintech.io",
  "password": "MiPasswordSuperSecreto2026!",
  "stripe_key": "sk_live_51Nz9a8b7c6d5e4f3g2h1i0jklmnop",
  "anthropic_key": "sk-ant-api03-99a8b7c6d5e4f3g2h1i0jklmnopqrst",
  "card_number": "4532 0151 1283 0366"
}"#;
    let mask_engine = VeilEngine::new(RedactionMode::Mask);
    let mut json_vault = Vault::new();
    let clean_json = mask_engine.redact_json_str(sample_json, &mut json_vault)?;
    println!("📄 JSON Sanitizado para Datadog/Sentry:\n{}\n", clean_json);

    Ok(())
}

fn run_benchmark(iterations: usize) {
    let payload = "User martin.gomez@fintech.io (CUIT 20-12345678-6) logged in from 181.45.210.14 using key sk-proj-99a8b7c6d5e4f3g2h1i0jklmnopqrst, IBAN DE89 3704 0044 0532 0130 00 and card 4532-0151-1283-0366 (phone +1 415 890-1234).";
    let engine = VeilEngine::new(RedactionMode::Placeholder);

    // Warmup
    let warmup = engine.redact(payload);
    let _ = warmup.vault.restore(&warmup.text);

    let start = Instant::now();
    let mut total_bytes = 0usize;
    for _ in 0..iterations {
        let res = engine.redact(payload);
        let _restored = res.vault.restore(&res.text);
        total_bytes += payload.len();
    }
    let elapsed = start.elapsed();

    let secs = elapsed.as_secs_f64();
    let us_per_op = (elapsed.as_nanos() as f64 / iterations as f64) / 1_000.0;
    let mb_per_sec = (total_bytes as f64 / (1024.0 * 1024.0)) / secs;

    println!(
        "🚀 PII-VEIL BENCHMARK ({} iteraciones de Redact + Restore)",
        iterations
    );
    println!(
        "   • Tamaño del payload : {} bytes (7 entidades PII/Secretos)",
        payload.len()
    );
    println!("   • Tiempo total       : {:.2?}", elapsed);
    println!(
        "   • Latencia por op    : {:.2} µs (microsegundos)",
        us_per_op
    );
    println!("   • Rendimiento        : {:.2} MB/s", mb_per_sec);
}

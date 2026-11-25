use pii_veil_core::{Vault, VeilEngine};
use serde_json::{json, Value};
use std::collections::HashMap;
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::atomic::{AtomicU64, Ordering};
use std::sync::{Arc, Mutex};
use std::thread;
use std::time::{Duration, Instant};

/// Maximum allowed HTTP request body size (10 MiB) to prevent memory exhaustion DoS.
pub const MAX_BODY_SIZE: usize = 10 * 1024 * 1024;

/// Maximum number of concurrent session vaults held in memory.
pub const MAX_ACTIVE_SESSIONS: usize = 10_000;

/// Configuration for the local HTTP/SSE DLP Proxy (`veil proxy`).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub upstream_addr: Option<String>,
    pub echo_mode: bool,
    pub session_ttl_secs: u64,
}

/// Zero-PII Prometheus telemetry & latency histogram for `veil proxy`.
#[derive(Default)]
pub struct ProxyMetrics {
    pub requests_total: AtomicU64,
    pub rejected_413_total: AtomicU64,
    pub entities_redacted_total: AtomicU64,
    pub redaction_us_sum: AtomicU64,
    pub redaction_us_count: AtomicU64,
    // Histogram cumulative buckets (microseconds): <=100, <=500, <=1000, <=5000, <=10000, +Inf
    pub bucket_le_100: AtomicU64,
    pub bucket_le_500: AtomicU64,
    pub bucket_le_1000: AtomicU64,
    pub bucket_le_5000: AtomicU64,
    pub bucket_le_10000: AtomicU64,
}

impl ProxyMetrics {
    pub fn record_redaction(&self, elapsed_us: u64, spans: u64) {
        self.entities_redacted_total
            .fetch_add(spans, Ordering::Relaxed);
        self.redaction_us_sum
            .fetch_add(elapsed_us, Ordering::Relaxed);
        self.redaction_us_count.fetch_add(1, Ordering::Relaxed);
        if elapsed_us <= 100 {
            self.bucket_le_100.fetch_add(1, Ordering::Relaxed);
        }
        if elapsed_us <= 500 {
            self.bucket_le_500.fetch_add(1, Ordering::Relaxed);
        }
        if elapsed_us <= 1000 {
            self.bucket_le_1000.fetch_add(1, Ordering::Relaxed);
        }
        if elapsed_us <= 5000 {
            self.bucket_le_5000.fetch_add(1, Ordering::Relaxed);
        }
        if elapsed_us <= 10000 {
            self.bucket_le_10000.fetch_add(1, Ordering::Relaxed);
        }
    }

    pub fn render_prometheus(&self, active_sessions: usize) -> String {
        let reqs = self.requests_total.load(Ordering::Relaxed);
        let rej = self.rejected_413_total.load(Ordering::Relaxed);
        let ents = self.entities_redacted_total.load(Ordering::Relaxed);
        let us_sum = self.redaction_us_sum.load(Ordering::Relaxed);
        let us_cnt = self.redaction_us_count.load(Ordering::Relaxed);
        let b100 = self.bucket_le_100.load(Ordering::Relaxed);
        let b500 = self.bucket_le_500.load(Ordering::Relaxed);
        let b1000 = self.bucket_le_1000.load(Ordering::Relaxed);
        let b5000 = self.bucket_le_5000.load(Ordering::Relaxed);
        let b10000 = self.bucket_le_10000.load(Ordering::Relaxed);

        format!(
            "# HELP veil_proxy_requests_total Total HTTP requests handled by pii-veil proxy.\n\
             # TYPE veil_proxy_requests_total counter\n\
             veil_proxy_requests_total {reqs}\n\
             # HELP veil_proxy_requests_rejected_413_total Requests rejected for exceeding MAX_BODY_SIZE.\n\
             # TYPE veil_proxy_requests_rejected_413_total counter\n\
             veil_proxy_requests_rejected_413_total {rej}\n\
             # HELP veil_proxy_entities_redacted_total Total PII and secret spans redacted.\n\
             # TYPE veil_proxy_entities_redacted_total counter\n\
             veil_proxy_entities_redacted_total {ents}\n\
             # HELP veil_proxy_active_sessions Current number of active TTL-scoped session vaults.\n\
             # TYPE veil_proxy_active_sessions gauge\n\
             veil_proxy_active_sessions {active_sessions}\n\
             # HELP veil_proxy_redaction_duration_microseconds Redaction latency histogram in microseconds.\n\
             # TYPE veil_proxy_redaction_duration_microseconds histogram\n\
             veil_proxy_redaction_duration_microseconds_bucket{{le=\"100\"}} {b100}\n\
             veil_proxy_redaction_duration_microseconds_bucket{{le=\"500\"}} {b500}\n\
             veil_proxy_redaction_duration_microseconds_bucket{{le=\"1000\"}} {b1000}\n\
             veil_proxy_redaction_duration_microseconds_bucket{{le=\"5000\"}} {b5000}\n\
             veil_proxy_redaction_duration_microseconds_bucket{{le=\"10000\"}} {b10000}\n\
             veil_proxy_redaction_duration_microseconds_bucket{{le=\"+Inf\"}} {us_cnt}\n\
             veil_proxy_redaction_duration_microseconds_sum {us_sum}\n\
             veil_proxy_redaction_duration_microseconds_count {us_cnt}\n"
        )
    }
}

struct SessionEntry {
    vault: Vault,
    expires_at: Instant,
}

/// Bounded in-memory session store with automatic TTL eviction for `X-Veil-Session-Id`.
pub struct SessionStore {
    ttl: Duration,
    entries: Mutex<HashMap<String, SessionEntry>>,
}

impl SessionStore {
    pub fn new(ttl: Duration) -> Self {
        Self {
            ttl,
            entries: Mutex::new(HashMap::new()),
        }
    }

    pub fn take_or_create(&self, session_id: &str) -> Vault {
        let Ok(mut map) = self.entries.lock() else {
            return Vault::new();
        };
        let now = Instant::now();
        map.retain(|_, v| v.expires_at > now);
        if let Some(entry) = map.get(session_id) {
            entry.vault.clone()
        } else {
            Vault::new()
        }
    }

    pub fn save(&self, session_id: String, vault: Vault) {
        let Ok(mut map) = self.entries.lock() else {
            return;
        };
        let now = Instant::now();
        map.retain(|_, v| v.expires_at > now);
        if map.len() >= MAX_ACTIVE_SESSIONS && !map.contains_key(&session_id) {
            if let Some(oldest_key) = map
                .iter()
                .min_by_key(|(_, v)| v.expires_at)
                .map(|(k, _)| k.clone())
            {
                map.remove(&oldest_key);
            }
        }
        map.insert(
            session_id,
            SessionEntry {
                vault,
                expires_at: now + self.ttl,
            },
        );
    }

    pub fn active_count(&self) -> usize {
        let Ok(mut map) = self.entries.lock() else {
            return 0;
        };
        let now = Instant::now();
        map.retain(|_, v| v.expires_at > now);
        map.len()
    }
}

/// Shared runtime state across proxy worker threads.
pub struct ProxyState {
    pub metrics: ProxyMetrics,
    pub sessions: SessionStore,
}

impl ProxyState {
    pub fn new(session_ttl_secs: u64) -> Self {
        Self {
            metrics: ProxyMetrics::default(),
            sessions: SessionStore::new(Duration::from_secs(session_ttl_secs)),
        }
    }
}

/// Runs the local HTTP/SSE reverse proxy that redacts outgoing LLM JSON prompts
/// and restores incoming JSON or `text/event-stream` SSE responses in real time.
///
/// Uses per-request ephemeral vaults by default, or isolated TTL-expiring vaults
/// when clients supply `X-Veil-Session-Id`.
pub fn run_http_proxy(engine: VeilEngine, config: ProxyConfig) -> io::Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)?;
    let shared_engine = Arc::new(engine);
    let shared_state = Arc::new(ProxyState::new(config.session_ttl_secs));
    let shared_config = Arc::new(config);

    eprintln!("================================================================================");
    eprintln!(
        "pii-veil HTTP/SSE DLP Proxy listening on http://{}",
        shared_config.listen_addr
    );
    if let Some(up) = &shared_config.upstream_addr {
        eprintln!("   • Upstream target : http://{}", up);
    }
    if shared_config.echo_mode {
        eprintln!("   • Mode            : Local LLM Echo / SSE Simulator (--echo)");
    }
    eprintln!(
        "   • Isolation       : Per-request Vault (or TTL={}s via X-Veil-Session-Id)",
        shared_config.session_ttl_secs
    );
    eprintln!("   • Max body size   : {} bytes", MAX_BODY_SIZE);
    eprintln!(
        "   • Endpoints       : GET /health | GET /metrics | POST /v1/chat/completions | POST /*"
    );
    eprintln!("================================================================================");

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let eng = Arc::clone(&shared_engine);
                let st = Arc::clone(&shared_state);
                let cfg = Arc::clone(&shared_config);
                thread::spawn(move || {
                    let _ = handle_client(client, &eng, &st, &cfg);
                });
            }
            Err(e) => eprintln!("Proxy connection error: {}", e),
        }
    }

    Ok(())
}

/// Processes a single HTTP request/response cycle on `client` with isolated vaults and metrics.
pub fn handle_client(
    mut client: TcpStream,
    engine: &VeilEngine,
    state: &Arc<ProxyState>,
    config: &ProxyConfig,
) -> io::Result<()> {
    state.metrics.requests_total.fetch_add(1, Ordering::Relaxed);
    let mut reader = BufReader::new(client.try_clone()?);

    // 1. Read request line
    let mut request_line = String::new();
    if reader.read_line(&mut request_line)? == 0 {
        return Ok(());
    }
    let parts: Vec<&str> = request_line.split_whitespace().collect();
    if parts.len() < 2 {
        return Ok(());
    }
    let method = parts[0];
    let path = parts[1];

    // 2. Read HTTP headers
    let mut headers: Vec<(String, String)> = Vec::new();
    let mut content_length: usize = 0;
    let mut force_echo = config.echo_mode || path == "/v1/echo";
    let mut session_id: Option<String> = None;

    loop {
        let mut line = String::new();
        if reader.read_line(&mut line)? == 0 {
            break;
        }
        let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
        if trimmed.is_empty() {
            break;
        }
        if let Some((k, v)) = trimmed.split_once(':') {
            let key = k.trim().to_string();
            let val = v.trim().to_string();
            if key.eq_ignore_ascii_case("content-length") {
                content_length = val.parse::<usize>().unwrap_or(0);
            } else if key.eq_ignore_ascii_case("x-veil-echo") && val.eq_ignore_ascii_case("true") {
                force_echo = true;
            } else if key.eq_ignore_ascii_case("x-veil-session-id") && !val.is_empty() {
                session_id = Some(val.clone());
            }
            headers.push((key, val));
        }
    }

    // Reject oversized bodies before allocating memory (DoS protection)
    if content_length > MAX_BODY_SIZE {
        state
            .metrics
            .rejected_413_total
            .fetch_add(1, Ordering::Relaxed);
        let payload = json!({
            "error": "payload_too_large",
            "max_body_size": MAX_BODY_SIZE
        })
        .to_string();
        let resp = format!(
            "HTTP/1.1 413 Payload Too Large\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // 3. Read request body if present
    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body_bytes)?;
    }

    // Strip query string (e.g. ?v=2) for static asset matching
    let clean_path = path.split('?').next().unwrap_or(path);

    // Handle static favicon & webmanifest routes
    if method.eq_ignore_ascii_case("GET") {
        let static_asset: Option<(&str, &[u8])> = match clean_path {
            "/favicon.svg" | "/public/favicon/favicon.svg" => {
                Some(("image/svg+xml", FAVICON_SVG.as_bytes()))
            }
            "/favicon.ico" | "/public/favicon/favicon.ico" => Some(("image/x-icon", FAVICON_ICO)),
            "/favicon-16x16.png" | "/public/favicon/favicon-16x16.png" => {
                Some(("image/png", FAVICON_16))
            }
            "/favicon-32x32.png" | "/public/favicon/favicon-32x32.png" => {
                Some(("image/png", FAVICON_32))
            }
            "/favicon-48x48.png" | "/public/favicon/favicon-48x48.png" => {
                Some(("image/png", FAVICON_48))
            }
            "/apple-touch-icon.png" | "/public/favicon/apple-touch-icon.png" => {
                Some(("image/png", APPLE_TOUCH_ICON))
            }
            "/android-chrome-192x192.png" | "/public/favicon/android-chrome-192x192.png" => {
                Some(("image/png", ANDROID_192))
            }
            "/android-chrome-512x512.png" | "/public/favicon/android-chrome-512x512.png" => {
                Some(("image/png", ANDROID_512))
            }
            "/site.webmanifest" | "/public/favicon/site.webmanifest" => {
                Some(("application/manifest+json", WEBMANIFEST.as_bytes()))
            }
            _ => None,
        };

        if let Some((content_type, bytes)) = static_asset {
            let header = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: {}\r\nContent-Length: {}\r\nCache-Control: no-cache\r\nConnection: close\r\n\r\n",
                content_type,
                bytes.len()
            );
            client.write_all(header.as_bytes())?;
            client.write_all(bytes)?;
            client.flush()?;
            return Ok(());
        }
    }

    // Handle OPTIONS CORS preflight
    if method.eq_ignore_ascii_case("OPTIONS") {
        let resp = "HTTP/1.1 204 No Content\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Allow-Methods: GET, POST, OPTIONS\r\nAccess-Control-Allow-Headers: Content-Type, Authorization, X-Veil-Echo, X-Veil-Sanitized-Request\r\nAccess-Control-Max-Age: 86400\r\nConnection: close\r\n\r\n";
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // Handle GET / or GET /index.html (Interactive DLP Proxy Dashboard)
    if method.eq_ignore_ascii_case("GET") && (clean_path == "/" || clean_path == "/index.html") {
        let html = DASHBOARD_HTML;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nX-Content-Type-Options: nosniff\r\nX-Frame-Options: SAMEORIGIN\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // Handle GET /metrics (Zero-PII Prometheus exposition format 0.0.4)
    if method.eq_ignore_ascii_case("GET") && clean_path == "/metrics" {
        let body = state
            .metrics
            .render_prometheus(state.sessions.active_count());
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/plain; version=0.0.4; charset=utf-8\r\nCache-Control: no-cache\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // Handle GET /health
    if method.eq_ignore_ascii_case("GET") && path == "/health" {
        let total_redacted = state
            .metrics
            .entities_redacted_total
            .load(Ordering::Relaxed);
        let active_sessions = state.sessions.active_count();
        let payload = json!({
            "status": "ok",
            "service": "pii-veil-proxy",
            "isolation": "per-request-or-session-ttl",
            "active_sessions": active_sessions,
            "entities_redacted_total": total_redacted,
            "vault_entries": total_redacted
        })
        .to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // 4. Redact outgoing request body using an isolated request-scoped or TTL session Vault
    let body_str = String::from_utf8_lossy(&body_bytes);
    let mut req_vault = match session_id.as_deref() {
        Some(sid) => state.sessions.take_or_create(sid),
        None => Vault::new(),
    };
    let redact_start = Instant::now();
    let (sanitized_body, is_streaming_req, spans_redacted) =
        if let Ok(mut parsed_json) = serde_json::from_str::<Value>(&body_str) {
            let stream_flag = parsed_json
                .get("stream")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            let spans = engine.redact_json_value_counted(&mut parsed_json, &mut req_vault);
            let out = serde_json::to_string(&parsed_json).unwrap_or_else(|_| body_str.to_string());
            (out, stream_flag, spans)
        } else {
            let (out, spans) = engine.redact_with_vault_counted(&body_str, &mut req_vault);
            (out, false, spans)
        };
    let elapsed_us = redact_start.elapsed().as_micros() as u64;
    state
        .metrics
        .record_redaction(elapsed_us, spans_redacted as u64);
    if let Some(sid) = session_id {
        state.sessions.save(sid, req_vault.clone());
    }

    // 5. Either handle in local Echo simulator or forward to upstream TCP server
    if force_echo || config.upstream_addr.is_none() {
        if is_streaming_req {
            let mut restorer = req_vault.streaming_restorer();
            let raw_sse_chunks = [
                "data: {\"object\":\"chat.completion.chunk\",\"choices\":[{\"delta\":{\"content\":\"Processed sanitized payload: \"}}]}\n\n".to_string(),
                format!(
                    "data: {{\"object\":\"chat.completion.chunk\",\"choices\":[{{\"delta\":{{\"content\":{}}}}} ]}}\n\n",
                    serde_json::to_string(&sanitized_body).unwrap_or_else(|_| "\"\"".to_string())
                ),
                "data: [DONE]\n\n".to_string(),
            ];

            let mut restored_sse = String::new();
            for chunk in &raw_sse_chunks {
                restored_sse.push_str(&restorer.push_chunk(chunk));
            }
            restored_sse.push_str(&restorer.finish());

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: X-Veil-Sanitized-Request\r\nX-Veil-Sanitized-Request: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                sanitized_body.replace(['\r', '\n'], " "),
                restored_sse.len(),
                restored_sse
            );
            client.write_all(resp.as_bytes())?;
            client.flush()?;
        } else {
            let simulated_llm_json = json!({
                "id": "chatcmpl-veil-proxy",
                "object": "chat.completion",
                "veil_sanitized_prompt": sanitized_body,
                "choices": [{
                    "index": 0,
                    "message": {
                        "role": "assistant",
                        "content": format!("Restored response for request: {}", sanitized_body)
                    }
                }]
            })
            .to_string();

            let mut resp_val: Value = serde_json::from_str(&simulated_llm_json).unwrap();
            if let Some(content_val) = resp_val
                .pointer_mut("/choices/0/message/content")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
            {
                let restored_msg = req_vault.restore(&content_val);
                resp_val["choices"][0]["message"]["content"] = Value::String(restored_msg);
            }
            let final_body = serde_json::to_string_pretty(&resp_val).unwrap();

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nAccess-Control-Allow-Origin: *\r\nAccess-Control-Expose-Headers: X-Veil-Sanitized-Request\r\nX-Veil-Sanitized-Request: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
                sanitized_body.replace(['\r', '\n'], " "),
                final_body.len(),
                final_body
            );
            client.write_all(resp.as_bytes())?;
            client.flush()?;
        }
        return Ok(());
    }

    // 6. Forward sanitized request to upstream HTTP server and restore response
    let upstream_addr = config.upstream_addr.as_ref().unwrap();
    let mut upstream = TcpStream::connect(upstream_addr)?;
    let mut out_req = format!("{} {} HTTP/1.1\r\n", method, path);
    for (k, v) in &headers {
        if k.eq_ignore_ascii_case("content-length") || k.eq_ignore_ascii_case("connection") {
            continue;
        }
        out_req.push_str(&format!("{}: {}\r\n", k, v));
    }
    out_req.push_str(&format!(
        "Content-Length: {}\r\nConnection: close\r\n\r\n",
        sanitized_body.len()
    ));
    upstream.write_all(out_req.as_bytes())?;
    upstream.write_all(sanitized_body.as_bytes())?;
    upstream.flush()?;

    // Read upstream response headers & body, restoring tokens via StreamingRestorer
    let mut up_reader = BufReader::new(upstream);
    let mut resp_header_block = String::new();
    let mut is_event_stream = false;
    loop {
        let mut line = String::new();
        if up_reader.read_line(&mut line)? == 0 {
            break;
        }
        let lower = line.to_ascii_lowercase();
        if lower.starts_with("content-length:") {
            continue;
        }
        if lower.starts_with("content-type:") && lower.contains("text/event-stream") {
            is_event_stream = true;
        }
        resp_header_block.push_str(&line);
        if line == "\r\n" || line == "\n" {
            break;
        }
    }
    client.write_all(resp_header_block.as_bytes())?;

    let mut restorer = req_vault.streaming_restorer();

    if is_event_stream {
        let mut line = String::new();
        loop {
            line.clear();
            if up_reader.read_line(&mut line)? == 0 {
                break;
            }
            let trimmed = line.trim_end_matches(&['\r', '\n'][..]);
            if trimmed.is_empty() {
                client.write_all(line.as_bytes())?;
                client.flush()?;
                continue;
            }
            if trimmed == "data: [DONE]" {
                let flushed = restorer.finish();
                if !flushed.is_empty() {
                    let tail_event = format!("data: {}\n\n", json!({ "delta": flushed }));
                    client.write_all(tail_event.as_bytes())?;
                }
                client.write_all(line.as_bytes())?;
                client.flush()?;
                continue;
            }
            if let Some(json_part) = trimmed.strip_prefix("data: ") {
                if let Ok(mut val) = serde_json::from_str::<Value>(json_part) {
                    restore_sse_json_value(&mut val, &mut restorer);
                    let out_line = format!("data: {}\n", val);
                    client.write_all(out_line.as_bytes())?;
                    client.flush()?;
                    continue;
                }
            }
            let restored_line = restorer.push_chunk(&line);
            if !restored_line.is_empty() {
                client.write_all(restored_line.as_bytes())?;
                client.flush()?;
            }
        }
    } else {
        let mut buf = [0u8; 4096];
        loop {
            let n = up_reader.read(&mut buf)?;
            if n == 0 {
                break;
            }
            let chunk_str = String::from_utf8_lossy(&buf[..n]);
            let restored_chunk = restorer.push_chunk(&chunk_str);
            if !restored_chunk.is_empty() {
                client.write_all(restored_chunk.as_bytes())?;
                client.flush()?;
            }
        }
    }
    let tail = restorer.finish();
    if !tail.is_empty() {
        client.write_all(tail.as_bytes())?;
    }
    client.flush()?;
    Ok(())
}

fn restore_sse_json_value(val: &mut Value, restorer: &mut pii_veil_core::StreamingRestorer) {
    match val {
        Value::String(s) => {
            *s = restorer.push_chunk(s);
        }
        Value::Array(arr) => {
            for item in arr {
                restore_sse_json_value(item, restorer);
            }
        }
        Value::Object(map) => {
            for (k, v) in map.iter_mut() {
                if matches!(
                    k.as_str(),
                    "id" | "object" | "model" | "role" | "finish_reason"
                ) {
                    continue;
                }
                restore_sse_json_value(v, restorer);
            }
        }
        _ => {}
    }
}

const FAVICON_SVG: &str = include_str!("../assets/favicon/favicon.svg");
const FAVICON_ICO: &[u8] = include_bytes!("../assets/favicon/favicon.ico");
const FAVICON_16: &[u8] = include_bytes!("../assets/favicon/favicon-16x16.png");
const FAVICON_32: &[u8] = include_bytes!("../assets/favicon/favicon-32x32.png");
const FAVICON_48: &[u8] = include_bytes!("../assets/favicon/favicon-48x48.png");
const APPLE_TOUCH_ICON: &[u8] = include_bytes!("../assets/favicon/apple-touch-icon.png");
const ANDROID_192: &[u8] = include_bytes!("../assets/favicon/android-chrome-192x192.png");
const ANDROID_512: &[u8] = include_bytes!("../assets/favicon/android-chrome-512x512.png");
const WEBMANIFEST: &str = include_str!("../assets/favicon/site.webmanifest");

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="en">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GLASTOR pii-veil — Live DLP & SSE Proxy Dashboard</title>
  <link rel="icon" type="image/svg+xml" href="/public/favicon/favicon.svg?v=2" />
  <link rel="icon" type="image/png" sizes="48x48" href="/public/favicon/favicon-48x48.png?v=2" />
  <link rel="icon" type="image/png" sizes="32x32" href="/public/favicon/favicon-32x32.png?v=2" />
  <link rel="icon" type="image/png" sizes="16x16" href="/public/favicon/favicon-16x16.png?v=2" />
  <link rel="shortcut icon" href="/favicon.ico?v=2" />
  <link rel="apple-touch-icon" sizes="180x180" href="/public/favicon/apple-touch-icon.png?v=2" />
  <link rel="manifest" href="/public/favicon/site.webmanifest?v=2" />
  <style>
    :root {
      --bg: #0b0f19;
      --card: #131b2e;
      --border: #23304d;
      --accent: #38bdf8;
      --emerald: #34d399;
      --amber: #fbbf24;
      --text: #f1f5f9;
      --muted: #94a3b8;
    }
    * { box-sizing: border-box; }
    body {
      margin: 0;
      padding: 32px 20px;
      font-family: system-ui, -apple-system, BlinkMacSystemFont, "Segoe UI", Roboto, sans-serif;
      background: var(--bg);
      color: var(--text);
      line-height: 1.5;
    }
    .container { max-width: 1080px; margin: 0 auto; }
    header {
      display: flex;
      justify-content: space-between;
      align-items: center;
      flex-wrap: wrap;
      gap: 16px;
      padding-bottom: 20px;
      border-bottom: 1px solid var(--border);
      margin-bottom: 24px;
    }
    .title-group h1 { margin: 0; font-size: 1.65rem; display: flex; align-items: center; gap: 10px; }
    .title-group p { margin: 4px 0 0; color: var(--muted); font-size: 0.95rem; }
    .badge {
      background: rgba(52, 211, 153, 0.12);
      border: 1px solid rgba(52, 211, 153, 0.4);
      color: var(--emerald);
      padding: 6px 14px;
      border-radius: 999px;
      font-size: 0.85rem;
      font-weight: 600;
    }
    .card {
      background: var(--card);
      border: 1px solid var(--border);
      border-radius: 12px;
      padding: 20px;
      margin-bottom: 20px;
    }
    .card h2 { margin-top: 0; font-size: 1.05rem; color: var(--accent); }
    textarea {
      width: 100%;
      min-height: 105px;
      background: #080c14;
      color: var(--text);
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 12px;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.9rem;
      resize: vertical;
    }
    .actions { display: flex; gap: 12px; margin-top: 14px; flex-wrap: wrap; }
    button {
      cursor: pointer;
      border: none;
      border-radius: 8px;
      padding: 10px 18px;
      font-weight: 600;
      font-size: 0.9rem;
      transition: opacity 0.15s;
    }
    button:hover { opacity: 0.9; }
    .btn-primary { background: var(--accent); color: #08101d; }
    .btn-sse { background: var(--emerald); color: #061812; }
    .grid {
      display: grid;
      grid-template-columns: repeat(auto-fit, minmax(320px, 1fr));
      gap: 20px;
    }
    pre {
      margin: 0;
      background: #080c14;
      border: 1px solid var(--border);
      border-radius: 8px;
      padding: 14px;
      overflow-x: auto;
      white-space: pre-wrap;
      word-break: break-word;
      font-family: ui-monospace, SFMono-Regular, Menlo, Consolas, monospace;
      font-size: 0.86rem;
      min-height: 150px;
    }
    .tag-lock { color: var(--amber); }
    .tag-unlock { color: var(--emerald); }
  </style>
</head>
<body>
  <div class="container">
    <header>
      <div class="title-group">
        <h1><img src="/public/favicon/android-chrome-192x192.png?v=2" width="38" height="38" alt="GLASTOR icon" style="border-radius:8px;" /> GLASTOR <code>pii-veil</code> — DLP &amp; SSE Proxy</h1>
        <p>Sub-millisecond Reversible PII &amp; Secret Anonymizer (Per-request isolated Vaults)</p>
      </div>
      <div class="badge" id="vaultStatus">Proxy Online • Redacted: 0 entities</div>
    </header>

    <div class="card">
      <h2>1. Input Prompt (PII, Credit Cards, IBAN, National IDs)</h2>
      <textarea id="promptInput">Hello support, I am Martin Gomez (martin.gomez@fintech.io, CUIT 20-12345678-6, DNI 00000000T). Please bill card 4532-0151-1283-0366 or IBAN DE89 3704 0044 0532 0130 00.</textarea>
      <div class="actions">
        <button class="btn-primary" onclick="sendRequest(false)">Test JSON Roundtrip (/v1/chat/completions)</button>
        <button class="btn-sse" onclick="sendRequest(true)">Test Real-Time SSE Stream (stream: true)</button>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2 class="tag-lock">2. What the LLM Sees (Sanitized by <code>veil proxy</code>)</h2>
        <pre id="sanitizedOut">Click one of the buttons above to intercept and sanitize the prompt...</pre>
      </div>
      <div class="card">
        <h2 class="tag-unlock">3. What the User Receives (Restored by <code>StreamingRestorer</code>)</h2>
        <pre id="restoredOut">The restored response with original values will appear here...</pre>
      </div>
    </div>
  </div>

  <script>
    async function refreshHealth() {
      try {
        const res = await fetch('/health');
        const data = await res.json();
        document.getElementById('vaultStatus').textContent =
          `Proxy Online • Redacted: ${data.entities_redacted_total} entities (per-request isolated)`;
      } catch (_) {}
    }

    async function sendRequest(streamMode) {
      const prompt = document.getElementById('promptInput').value;
      const sanitizedEl = document.getElementById('sanitizedOut');
      const restoredEl = document.getElementById('restoredOut');
      sanitizedEl.textContent = 'Sanitizing...';
      restoredEl.textContent = 'Restoring...';

      const payload = {
        model: 'gpt-4o',
        stream: streamMode,
        messages: [{ role: 'user', content: prompt }]
      };

      const res = await fetch('/v1/chat/completions', {
        method: 'POST',
        headers: { 'Content-Type': 'application/json', 'X-Veil-Echo': 'true' },
        body: JSON.stringify(payload)
      });

      if (streamMode) {
        const sanitizedHeader = res.headers.get('X-Veil-Sanitized-Request') || '(See stream)';
        try {
          sanitizedEl.textContent = JSON.stringify(JSON.parse(sanitizedHeader), null, 2);
        } catch (_) {
          sanitizedEl.textContent = sanitizedHeader;
        }
        const text = await res.text();
        restoredEl.textContent = text;
      } else {
        const data = await res.json();
        try {
          sanitizedEl.textContent = JSON.stringify(JSON.parse(data.veil_sanitized_prompt), null, 2);
        } catch (_) {
          sanitizedEl.textContent = data.veil_sanitized_prompt;
        }
        restoredEl.textContent = data.choices[0].message.content;
      }
      await refreshHealth();
    }

    refreshHealth();
  </script>
</body>
</html>
"#;

#[cfg(test)]
mod tests {
    use super::*;
    use pii_veil_core::RedactionMode;

    #[test]
    fn test_http_proxy_echo_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(300));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
            session_ttl_secs: 300,
        };

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_client(stream, &engine, &state, &config).unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let body = r#"{"model":"gpt-4o","messages":[{"role":"user","content":"Cobrar a laura@fintech.es (DNI 00000000T) en tarjeta 4532-0151-1283-0366"}]}"#;
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(req.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut resp = String::new();
        client.read_to_string(&mut resp).unwrap();
        server_handle.join().unwrap();

        assert!(resp.contains("[EMAIL_1]"));
        assert!(resp.contains("[NATIONAL_ID_1]"));
        assert!(resp.contains("[CREDIT_CARD_1]"));
        assert!(resp.contains("laura@fintech.es"));
        assert!(resp.contains("00000000T"));
        assert!(resp.contains("4532-0151-1283-0366"));
    }

    #[test]
    fn test_http_proxy_upstream_sse_stream_roundtrip() {
        let upstream_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let upstream_addr = upstream_listener.local_addr().unwrap();

        let upstream_handle = thread::spawn(move || {
            if let Ok((mut up_stream, _)) = upstream_listener.accept() {
                let mut reader = BufReader::new(up_stream.try_clone().unwrap());
                let mut content_len = 0usize;
                loop {
                    let mut line = String::new();
                    reader.read_line(&mut line).unwrap();
                    if line.trim().is_empty() {
                        break;
                    }
                    if let Some((k, v)) = line.split_once(':') {
                        if k.trim().eq_ignore_ascii_case("content-length") {
                            content_len = v.trim().parse().unwrap_or(0);
                        }
                    }
                }
                let mut req_body = vec![0u8; content_len];
                reader.read_exact(&mut req_body).unwrap();
                let req_str = String::from_utf8(req_body).unwrap();

                assert!(!req_str.contains("diego@fintech.ar"));
                assert!(!req_str.contains("4532-0151-1283-0366"));
                assert!(req_str.contains("[EMAIL_1]"));
                assert!(req_str.contains("[CREDIT_CARD_1]"));

                let sse_headers =
                    "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nConnection: close\r\n\r\n";
                up_stream.write_all(sse_headers.as_bytes()).unwrap();
                let chunks = [
                    "data: {\"delta\":\"Recibo enviado a [EMA\"}\n\n",
                    "data: {\"delta\":\"IL_1] con cargo a [CRED\"}\n\n",
                    "data: {\"delta\":\"IT_CARD_1].\"}\n\n",
                    "data: [DONE]\n\n",
                ];
                for chunk in chunks {
                    up_stream.write_all(chunk.as_bytes()).unwrap();
                    up_stream.flush().unwrap();
                }
            }
        });

        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(300));
        let config = ProxyConfig {
            listen_addr: proxy_addr.to_string(),
            upstream_addr: Some(upstream_addr.to_string()),
            echo_mode: false,
            session_ttl_secs: 300,
        };

        let proxy_handle = thread::spawn(move || {
            if let Ok((stream, _)) = proxy_listener.accept() {
                handle_client(stream, &engine, &state, &config).unwrap();
            }
        });

        let mut client = TcpStream::connect(proxy_addr).unwrap();
        let body = r#"{"model":"gpt-4o","stream":true,"messages":[{"role":"user","content":"Cobrar a diego@fintech.ar en 4532-0151-1283-0366"}]}"#;
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        client.write_all(req.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut restored_sse = String::new();
        client.read_to_string(&mut restored_sse).unwrap();

        proxy_handle.join().unwrap();
        upstream_handle.join().unwrap();

        assert!(restored_sse.contains("diego@fintech.ar"));
        assert!(restored_sse.contains("4532-0151-1283-0366"));
        assert!(!restored_sse.contains("[EMAIL_1]"));
        assert!(!restored_sse.contains("[CREDIT_CARD_1]"));
    }

    #[test]
    fn test_http_proxy_cors_options_preflight() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(300));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
            session_ttl_secs: 300,
        };

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_client(stream, &engine, &state, &config).unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let req = "OPTIONS /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nOrigin: http://localhost:3000\r\nAccess-Control-Request-Method: POST\r\n\r\n";
        client.write_all(req.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server_handle.join().unwrap();

        assert!(response.starts_with("HTTP/1.1 204 No Content"));
        assert!(response.contains("Access-Control-Allow-Origin: *"));
        assert!(response.contains("Access-Control-Allow-Methods: GET, POST, OPTIONS"));
    }

    #[test]
    fn test_http_proxy_rejects_oversized_body_413() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(300));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
            session_ttl_secs: 300,
        };

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_client(stream, &engine, &state, &config).unwrap();
            }
        });

        let mut client = TcpStream::connect(addr).unwrap();
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Length: {}\r\n\r\n",
            MAX_BODY_SIZE + 1
        );
        client.write_all(req.as_bytes()).unwrap();
        client.flush().unwrap();

        let mut response = String::new();
        client.read_to_string(&mut response).unwrap();
        server_handle.join().unwrap();

        assert!(response.starts_with("HTTP/1.1 413 Payload Too Large"));
        assert!(response.contains("payload_too_large"));
    }

    #[test]
    fn test_http_proxy_per_request_vault_isolation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(300));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
            session_ttl_secs: 300,
        };

        let server_handle = thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((stream, _)) = listener.accept() {
                    handle_client(stream, &engine, &state, &config).unwrap();
                }
            }
        });

        let mut client_a = TcpStream::connect(addr).unwrap();
        let body_a = r#"{"messages":[{"role":"user","content":"User A: alice@tenant-a.io"}]}"#;
        let req_a = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body_a.len(),
            body_a
        );
        client_a.write_all(req_a.as_bytes()).unwrap();
        client_a.flush().unwrap();
        let mut resp_a = String::new();
        client_a.read_to_string(&mut resp_a).unwrap();

        let mut client_b = TcpStream::connect(addr).unwrap();
        let body_b = r#"{"messages":[{"role":"user","content":"User B: bob@tenant-b.io"}]}"#;
        let req_b = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body_b.len(),
            body_b
        );
        client_b.write_all(req_b.as_bytes()).unwrap();
        client_b.flush().unwrap();
        let mut resp_b = String::new();
        client_b.read_to_string(&mut resp_b).unwrap();

        server_handle.join().unwrap();

        assert!(resp_a.contains("[EMAIL_1]"));
        assert!(resp_a.contains("alice@tenant-a.io"));
        assert!(!resp_a.contains("bob@tenant-b.io"));

        assert!(resp_b.contains("[EMAIL_1]"));
        assert!(!resp_b.contains("[EMAIL_2]"));
        assert!(resp_b.contains("bob@tenant-b.io"));
        assert!(!resp_b.contains("alice@tenant-a.io"));
    }

    #[test]
    fn test_http_proxy_prometheus_metrics_endpoint_zero_pii() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(300));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
            session_ttl_secs: 300,
        };

        let server_handle = thread::spawn(move || {
            for _ in 0..2 {
                if let Ok((stream, _)) = listener.accept() {
                    handle_client(stream, &engine, &state, &config).unwrap();
                }
            }
        });

        // 1. Send a request containing PII
        let mut post_client = TcpStream::connect(addr).unwrap();
        let body = r#"{"messages":[{"role":"user","content":"Private: secret.user@corp.io"}]}"#;
        let req = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            body.len(),
            body
        );
        post_client.write_all(req.as_bytes()).unwrap();
        post_client.flush().unwrap();
        let mut post_resp = String::new();
        post_client.read_to_string(&mut post_resp).unwrap();

        // 2. Scrape GET /metrics
        let mut metrics_client = TcpStream::connect(addr).unwrap();
        metrics_client
            .write_all(b"GET /metrics HTTP/1.1\r\nHost: localhost\r\n\r\n")
            .unwrap();
        metrics_client.flush().unwrap();
        let mut metrics_resp = String::new();
        metrics_client.read_to_string(&mut metrics_resp).unwrap();

        server_handle.join().unwrap();

        assert!(metrics_resp.starts_with("HTTP/1.1 200 OK"));
        assert!(metrics_resp.contains("text/plain; version=0.0.4"));
        assert!(metrics_resp.contains("veil_proxy_requests_total 2"));
        assert!(metrics_resp.contains("veil_proxy_entities_redacted_total 1"));
        assert!(metrics_resp
            .contains("veil_proxy_redaction_duration_microseconds_bucket{le=\"+Inf\"} 1"));
        // Zero-PII telemetry invariant
        assert!(!metrics_resp.contains("secret.user@corp.io"));
    }

    #[test]
    fn test_http_proxy_session_id_ttl_reuse_and_isolation() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let state = Arc::new(ProxyState::new(60));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
            session_ttl_secs: 60,
        };

        let server_handle = thread::spawn(move || {
            for _ in 0..3 {
                if let Ok((stream, _)) = listener.accept() {
                    handle_client(stream, &engine, &state, &config).unwrap();
                }
            }
        });

        // Turn 1 in session S1
        let mut c1 = TcpStream::connect(addr).unwrap();
        let b1 = r#"{"messages":[{"role":"user","content":"Email 1: one@s1.io"}]}"#;
        let r1 = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Veil-Session-Id: sess-1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            b1.len(),
            b1
        );
        c1.write_all(r1.as_bytes()).unwrap();
        c1.flush().unwrap();
        let mut resp1 = String::new();
        c1.read_to_string(&mut resp1).unwrap();

        // Turn 2 in session S1 (new email must become [EMAIL_2] because S1 vault persisted!)
        let mut c2 = TcpStream::connect(addr).unwrap();
        let b2 = r#"{"messages":[{"role":"user","content":"Email 2: two@s1.io"}]}"#;
        let r2 = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Veil-Session-Id: sess-1\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            b2.len(),
            b2
        );
        c2.write_all(r2.as_bytes()).unwrap();
        c2.flush().unwrap();
        let mut resp2 = String::new();
        c2.read_to_string(&mut resp2).unwrap();

        // Session S2 (completely isolated from S1 -> must get [EMAIL_1])
        let mut c3 = TcpStream::connect(addr).unwrap();
        let b3 = r#"{"messages":[{"role":"user","content":"Email S2: other@s2.io"}]}"#;
        let r3 = format!(
            "POST /v1/chat/completions HTTP/1.1\r\nHost: localhost\r\nX-Veil-Session-Id: sess-2\r\nContent-Type: application/json\r\nContent-Length: {}\r\n\r\n{}",
            b3.len(),
            b3
        );
        c3.write_all(r3.as_bytes()).unwrap();
        c3.flush().unwrap();
        let mut resp3 = String::new();
        c3.read_to_string(&mut resp3).unwrap();

        server_handle.join().unwrap();

        assert!(resp1.contains("[EMAIL_1]"));
        assert!(resp2.contains("[EMAIL_2]"));
        assert!(resp3.contains("[EMAIL_1]"));
        assert!(!resp3.contains("one@s1.io"));
    }
}

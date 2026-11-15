use pii_veil_core::{Vault, VeilEngine};
use serde_json::{json, Value};
use std::io::{self, BufRead, BufReader, Read, Write};
use std::net::{TcpListener, TcpStream};
use std::sync::{Arc, Mutex};
use std::thread;

/// Configuration for the local HTTP/SSE DLP Proxy (`veil proxy`).
#[derive(Debug, Clone)]
pub struct ProxyConfig {
    pub listen_addr: String,
    pub upstream_addr: Option<String>,
    pub echo_mode: bool,
}

/// Runs the local HTTP/SSE reverse proxy that redacts outgoing LLM JSON prompts
/// and restores incoming JSON or `text/event-stream` SSE responses in real time.
pub fn run_http_proxy(engine: VeilEngine, config: ProxyConfig) -> io::Result<()> {
    let listener = TcpListener::bind(&config.listen_addr)?;
    let shared_engine = Arc::new(engine);
    let shared_vault = Arc::new(Mutex::new(Vault::new()));
    let shared_config = Arc::new(config);

    eprintln!("================================================================================");
    eprintln!(
        "🛡️  pii-veil HTTP/SSE DLP Proxy listening on http://{}",
        shared_config.listen_addr
    );
    if let Some(up) = &shared_config.upstream_addr {
        eprintln!("   • Upstream target : http://{}", up);
    }
    if shared_config.echo_mode {
        eprintln!("   • Mode            : Local LLM Echo / SSE Simulator (--echo)");
    }
    eprintln!("   • Endpoints       : GET /health | POST /v1/chat/completions | POST /*");
    eprintln!("================================================================================");

    for stream in listener.incoming() {
        match stream {
            Ok(client) => {
                let eng = Arc::clone(&shared_engine);
                let vlt = Arc::clone(&shared_vault);
                let cfg = Arc::clone(&shared_config);
                thread::spawn(move || {
                    let _ = handle_client(client, &eng, &vlt, &cfg);
                });
            }
            Err(e) => eprintln!("Proxy connection error: {}", e),
        }
    }

    Ok(())
}

/// Processes a single HTTP request/response cycle on `client`.
pub fn handle_client(
    mut client: TcpStream,
    engine: &VeilEngine,
    vault_mutex: &Arc<Mutex<Vault>>,
    config: &ProxyConfig,
) -> io::Result<()> {
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
            }
            headers.push((key, val));
        }
    }

    // 3. Read request body if present
    let mut body_bytes = vec![0u8; content_length];
    if content_length > 0 {
        reader.read_exact(&mut body_bytes)?;
    }

    // Handle GET /health
    if method.eq_ignore_ascii_case("GET") && path == "/health" {
        let entries_count = vault_mutex.lock().map(|v| v.len()).unwrap_or(0);
        let payload = json!({
            "status": "ok",
            "service": "pii-veil-proxy",
            "vault_entries": entries_count
        })
        .to_string();
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            payload.len(),
            payload
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // 4. Redact outgoing request body using VeilEngine & shared Vault
    let body_str = String::from_utf8_lossy(&body_bytes);
    let (sanitized_body, is_streaming_req) = {
        let mut vault = vault_mutex
            .lock()
            .map_err(|_| io::Error::other("vault lock poisoned"))?;
        if let Ok(mut parsed_json) = serde_json::from_str::<Value>(&body_str) {
            let stream_flag = parsed_json
                .get("stream")
                .and_then(|v| v.as_bool())
                .unwrap_or(false);
            engine.redact_json_value(&mut parsed_json, &mut vault);
            let out = serde_json::to_string(&parsed_json).unwrap_or_else(|_| body_str.to_string());
            (out, stream_flag)
        } else {
            let out = engine.redact_with_vault(&body_str, &mut vault);
            (out, false)
        }
    };

    // 5. Either handle in local Echo simulator or forward to upstream TCP server
    if force_echo || config.upstream_addr.is_none() {
        let vault_snapshot = vault_mutex
            .lock()
            .map_err(|_| io::Error::other("vault lock poisoned"))?
            .clone();

        if is_streaming_req {
            // Simulate chunked SSE response where placeholders are split mid-token
            // and restored on the fly by StreamingRestorer!
            let mut restorer = vault_snapshot.streaming_restorer();
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
                "HTTP/1.1 200 OK\r\nContent-Type: text/event-stream\r\nCache-Control: no-cache\r\nX-Veil-Sanitized-Request: {}\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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

            // Restore only the assistant message content so the user can inspect both
            // `veil_sanitized_prompt` (what the LLM saw) and `choices[0].message.content` (restored)!
            let mut resp_val: Value = serde_json::from_str(&simulated_llm_json).unwrap();
            if let Some(content_val) = resp_val
                .pointer_mut("/choices/0/message/content")
                .and_then(|v| v.as_str().map(|s| s.to_string()))
            {
                let restored_msg = vault_snapshot.restore(&content_val);
                resp_val["choices"][0]["message"]["content"] = Value::String(restored_msg);
            }
            let final_body = serde_json::to_string_pretty(&resp_val).unwrap();

            let resp = format!(
                "HTTP/1.1 200 OK\r\nContent-Type: application/json\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
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
            // Omit fixed Content-Length since restored PII may differ in byte length
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

    let vault_snapshot = vault_mutex
        .lock()
        .map_err(|_| io::Error::other("vault lock poisoned"))?
        .clone();
    let mut restorer = vault_snapshot.streaming_restorer();

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

#[cfg(test)]
mod tests {
    use super::*;
    use pii_veil_core::RedactionMode;

    #[test]
    fn test_http_proxy_echo_roundtrip() {
        let listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let addr = listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let vault = Arc::new(Mutex::new(Vault::new()));
        let config = ProxyConfig {
            listen_addr: addr.to_string(),
            upstream_addr: None,
            echo_mode: true,
        };

        let server_handle = thread::spawn(move || {
            if let Ok((stream, _)) = listener.accept() {
                handle_client(stream, &engine, &vault, &config).unwrap();
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

        // Verify the LLM only saw placeholders in `veil_sanitized_prompt`
        assert!(resp.contains("[EMAIL_1]"));
        assert!(resp.contains("[NATIONAL_ID_1]"));
        assert!(resp.contains("[CREDIT_CARD_1]"));
        // Verify the assistant's message was restored back to real PII
        assert!(resp.contains("laura@fintech.es"));
        assert!(resp.contains("00000000T"));
        assert!(resp.contains("4532-0151-1283-0366"));
    }

    #[test]
    fn test_http_proxy_upstream_sse_stream_roundtrip() {
        // 1. Start a mock upstream LLM server that verifies it NEVER receives raw PII
        //    and responds with SSE chunks where `[EMAIL_1]` and `[CREDIT_CARD_1]` are split mid-token!
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

                // Upstream LLM must ONLY see placeholders, never raw PII!
                assert!(!req_str.contains("diego@fintech.ar"));
                assert!(!req_str.contains("4532-0151-1283-0366"));
                assert!(req_str.contains("[EMAIL_1]"));
                assert!(req_str.contains("[CREDIT_CARD_1]"));

                // Stream back SSE chunks with placeholders split mid-token
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

        // 2. Start `veil proxy` pointing to `upstream_addr`
        let proxy_listener = TcpListener::bind("127.0.0.1:0").unwrap();
        let proxy_addr = proxy_listener.local_addr().unwrap();

        let engine = VeilEngine::new(RedactionMode::Placeholder);
        let vault = Arc::new(Mutex::new(Vault::new()));
        let config = ProxyConfig {
            listen_addr: proxy_addr.to_string(),
            upstream_addr: Some(upstream_addr.to_string()),
            echo_mode: false,
        };

        let proxy_handle = thread::spawn(move || {
            if let Ok((stream, _)) = proxy_listener.accept() {
                handle_client(stream, &engine, &vault, &config).unwrap();
            }
        });

        // 3. Client sends raw PII prompt to `veil proxy`
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

        // 4. Verify client received the restored PII across the split SSE chunks!
        assert!(restored_sse.contains("diego@fintech.ar"));
        assert!(restored_sse.contains("4532-0151-1283-0366"));
        assert!(!restored_sse.contains("[EMAIL_1]"));
        assert!(!restored_sse.contains("[CREDIT_CARD_1]"));
    }
}

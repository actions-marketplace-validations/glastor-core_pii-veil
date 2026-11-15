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

    // Handle GET /favicon.svg or GET /favicon.ico
    if method.eq_ignore_ascii_case("GET") && (path == "/favicon.svg" || path == "/favicon.ico") {
        let svg = FAVICON_SVG;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: image/svg+xml\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            svg.len(),
            svg
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
    }

    // Handle GET / or GET /index.html (Interactive DLP Proxy Dashboard)
    if method.eq_ignore_ascii_case("GET") && (path == "/" || path == "/index.html") {
        let html = DASHBOARD_HTML;
        let resp = format!(
            "HTTP/1.1 200 OK\r\nContent-Type: text/html; charset=utf-8\r\nContent-Length: {}\r\nConnection: close\r\n\r\n{}",
            html.len(),
            html
        );
        client.write_all(resp.as_bytes())?;
        client.flush()?;
        return Ok(());
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

const FAVICON_SVG: &str = include_str!("../../../assets/favicon.svg");

const DASHBOARD_HTML: &str = r#"<!DOCTYPE html>
<html lang="es">
<head>
  <meta charset="UTF-8" />
  <meta name="viewport" content="width=device-width, initial-scale=1.0" />
  <title>GLASTOR® pii-veil — Live DLP & SSE Proxy Dashboard</title>
  <link rel="icon" type="image/svg+xml" href="/favicon.svg" />
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
        <h1>🛡️ GLASTOR® <code>pii-veil</code> — DLP & SSE Proxy</h1>
        <p>Sub-millisecond Reversible PII & Secret Anonymizer (Luhn, Mod-97 IBAN, Mod-23 DNI, Mod-11 CUIT/RUT)</p>
      </div>
      <div class="badge" id="vaultStatus">🟢 Proxy Online • Vault: 0 entidades</div>
    </header>

    <div class="card">
      <h2>1️⃣ Prompt de Entrada (con PII, Tarjetas, IBAN, Documentos y Credenciales)</h2>
      <textarea id="promptInput">Hola soporte, soy Martín Gómez (martin.gomez@fintech.io, CUIT 20-12345678-6, DNI 00000000T). Necesito pagar con mi tarjeta 4532-0151-1283-0366 o IBAN DE89 3704 0044 0532 0130 00 desde mi servidor postgres://admin:SuperSecret99@db.fintech.io:5432/prod usando mi clave sk-proj-99a8b7c6d5e4f3g2h1i0jklmnopqrst.</textarea>
      <div class="actions">
        <button class="btn-primary" onclick="sendRequest(false)">⚡ Probar Roundtrip JSON (/v1/chat/completions)</button>
        <button class="btn-sse" onclick="sendRequest(true)">🌊 Probar Stream SSE en Tiempo Real (stream: true)</button>
      </div>
    </div>

    <div class="grid">
      <div class="card">
        <h2 class="tag-lock">🔒 2️⃣ Lo que ve el LLM (Prompt Sanitizado por <code>veil proxy</code>)</h2>
        <pre id="sanitizedOut">Haz clic en uno de los botones superiores para interceptar y sanitizar el prompt...</pre>
      </div>
      <div class="card">
        <h2 class="tag-unlock">🔓 3️⃣ Lo que recibe el Usuario (Restaurado por <code>Vault</code> / <code>StreamingRestorer</code>)</h2>
        <pre id="restoredOut">La respuesta restaurada con los valores reales aparecerá aquí...</pre>
      </div>
    </div>
  </div>

  <script>
    async function refreshHealth() {
      try {
        const res = await fetch('/health');
        const data = await res.json();
        document.getElementById('vaultStatus').textContent =
          `🟢 Proxy Online • Vault: ${data.vault_entries} entidades en sesión`;
      } catch (_) {}
    }

    async function sendRequest(streamMode) {
      const prompt = document.getElementById('promptInput').value;
      const sanitizedEl = document.getElementById('sanitizedOut');
      const restoredEl = document.getElementById('restoredOut');
      sanitizedEl.textContent = 'Sanitizando...';
      restoredEl.textContent = 'Restaurando...';

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
        const sanitizedHeader = res.headers.get('X-Veil-Sanitized-Request') || '(Ver stream)';
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

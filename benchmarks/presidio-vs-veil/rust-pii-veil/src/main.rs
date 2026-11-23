use axum::{
    extract::State,
    http::StatusCode,
    routing::{get, post},
    Json, Router,
};
use pii_veil_core::{RedactionMode, VeilEngine};
use serde::{Deserialize, Serialize};
use std::sync::Arc;

#[derive(Deserialize)]
struct RedactRequest {
    text: String,
}

#[derive(Serialize)]
struct RedactResponse {
    text: String,
    spans_found: usize,
}

async fn health() -> StatusCode {
    StatusCode::OK
}

async fn redact(
    State(engine): State<Arc<VeilEngine>>,
    Json(payload): Json<RedactRequest>,
) -> Json<RedactResponse> {
    let result = engine.redact(&payload.text);
    Json(RedactResponse {
        text: result.text,
        spans_found: result.spans_found,
    })
}

#[tokio::main]
async fn main() {
    let engine = Arc::new(VeilEngine::new(RedactionMode::Placeholder));

    let app = Router::new()
        .route("/health", get(health))
        .route("/api/v1/redact", post(redact))
        .with_state(engine);

    let listener = tokio::net::TcpListener::bind("0.0.0.0:8080")
        .await
        .expect("failed to bind 0.0.0.0:8080");
    axum::serve(listener, app).await.expect("server error");
}

//! Async HTTP server with Kyber‑1024 decapsulation and Z3 verification.

use axum::{Router, routing::post, Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::net::TcpListener;

use crate::post_quantum_identity::QuantumIdentity;
use crate::z3_verifier::verify_transaction_amount;

#[derive(Clone)]
struct AppState {
    identity: Arc<QuantumIdentity>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    pub amount: u64,
    /// Hex‑encoded Kyber‑1024 ciphertext.
    pub ciphertext_hex: String,
}

#[derive(Debug, Serialize)]
pub struct TransactionResponse {
    pub approved: bool,
    pub message: String,
}

async fn handle_transaction(
    State(state): State<AppState>,
    Json(req): Json<TransactionRequest>,
) -> Result<Json<TransactionResponse>, (StatusCode, String)> {
    // 1. Decapsulate shared secret from the ciphertext
    let ciphertext = hex::decode(&req.ciphertext_hex)
        .map_err(|e| (StatusCode::BAD_REQUEST, format!("Invalid hex: {}", e)))?;
    let _shared_secret = state
        .identity
        .decapsulate(&ciphertext)
        .ok_or((StatusCode::UNAUTHORIZED, "Decapsulation failed".to_string()))?;
    // In a real app, you'd use the shared secret for authentication/encryption.

    // 2. Verify transaction amount using Z3
    let approved = verify_transaction_amount(req.amount);
    let message = if approved {
        "Transaction approved".to_string()
    } else {
        "Amount out of allowed range".to_string()
    };
    Ok(Json(TransactionResponse { approved, message }))
}

/// Runs the HTTP server on `0.0.0.0:3000`.
pub async fn run_server() -> anyhow::Result<()> {
    let identity = Arc::new(QuantumIdentity::new_secure("aigis-node-01"));
    let app = Router::new()
        .route("/api/tx", post(handle_transaction))
        .with_state(identity);

    let addr = "0.0.0.0:3000".parse()?;
    let listener = TcpListener::bind(addr).await?;
    println!("🚀 Server running on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

#[tokio::main]
async fn main() -> anyhow::Result<()> {
    run_server().await
}

#[cfg(test)]
mod tests {
    use super::*;
    use axum::http::Request;
    use tower::ServiceExt; // for oneshot

    #[tokio::test]
    async fn test_handle_transaction_bad_hex() {
        let identity = Arc::new(QuantumIdentity::new_secure("test"));
        let app = Router::new()
            .route("/api/tx", post(handle_transaction))
            .with_state(identity);

        let request = Request::builder()
            .method("POST")
            .uri("/api/tx")
            .header("content-type", "application/json")
            .body(axum::body::Body::from(r#"{"amount": 500000, "ciphertext_hex": "not-hex"}"#))
            .unwrap();

        let response = app.oneshot(request).await.unwrap();
        assert_eq!(response.status(), StatusCode::BAD_REQUEST);
    }
}

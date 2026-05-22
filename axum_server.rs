use axum::{Router, routing::post, Json, extract::State, http::StatusCode};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use crate::post_quantum_identity::QuantumIdentity;
use crate::z3_verifier::verify_transaction_amount;

#[derive(Clone)]
struct AppState {
    identity: Arc<QuantumIdentity>,
}

#[derive(Debug, Deserialize)]
pub struct TransactionRequest {
    pub amount: u64,
    pub ciphertext_hex: String, // Kyber ciphertext from client
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
    // 1. Decapsulate shared secret
    let ciphertext = hex::decode(&req.ciphertext_hex)
        .map_err(|_| (StatusCode::BAD_REQUEST, "Invalid hex".into()))?;
    let shared = state.identity.decapsulate(&ciphertext)
        .ok_or((StatusCode::UNAUTHORIZED, "Decapsulation failed".into()))?;
    // (In real app: use shared for MAC or further verification)

    // 2. Z3 amount check
    let approved = verify_transaction_amount(req.amount);
    let message = if approved {
        "Transaction approved".into()
    } else {
        "Amount out of allowed range".into()
    };
    Ok(Json(TransactionResponse { approved, message }))
}

pub async fn run_server() -> anyhow::Result<()> {
    let identity = Arc::new(QuantumIdentity::new_secure("aigis-node-01"));
    let app = Router::new()
        .route("/api/tx", post(handle_transaction))
        .with_state(identity);

    let addr = "0.0.0.0:3000".parse().unwrap();
    let listener = tokio::net::TcpListener::bind(addr).await?;
    println!("Server running on http://{}", addr);
    axum::serve(listener, app).await?;
    Ok(())
}

use anyhow::Result;
use axum::{Router, extract::State, http::StatusCode, response::Json, routing::get};
use serde::Serialize;
use std::sync::Arc;
use std::time::SystemTime;
use tokio::net::TcpListener;
use tracing::info;

#[derive(Clone)]
pub struct HealthState {
    pub started_at: SystemTime,
    pub version: String,
    pub storage_path: String,
}

#[derive(Serialize)]
struct HealthResponse {
    status: &'static str,
    version: String,
    uptime_seconds: u64,
    storage_path: String,
    timestamp: SystemTime,
}

#[derive(Serialize)]
struct LivenessResponse {
    alive: bool,
}

#[derive(Serialize)]
struct ReadinessResponse {
    ready: bool,
    storage_accessible: bool,
}

async fn health_check(State(state): State<Arc<HealthState>>) -> Json<HealthResponse> {
    let uptime = SystemTime::now()
        .duration_since(state.started_at)
        .unwrap_or_default()
        .as_secs();

    Json(HealthResponse {
        status: "healthy",
        version: state.version.clone(),
        uptime_seconds: uptime,
        storage_path: state.storage_path.clone(),
        timestamp: SystemTime::now(),
    })
}

async fn liveness_check() -> Json<LivenessResponse> {
    // Simple liveness check - if we can respond, we're alive
    Json(LivenessResponse { alive: true })
}

async fn readiness_check(
    State(state): State<Arc<HealthState>>,
) -> (StatusCode, Json<ReadinessResponse>) {
    // Check if storage directory is accessible
    let storage_accessible = tokio::fs::metadata(&state.storage_path)
        .await
        .map(|m| m.is_dir())
        .unwrap_or(false);

    let ready = storage_accessible;

    let status = if ready {
        StatusCode::OK
    } else {
        StatusCode::SERVICE_UNAVAILABLE
    };

    (
        status,
        Json(ReadinessResponse {
            ready,
            storage_accessible,
        }),
    )
}

pub async fn run_health_server(port: u16, state: HealthState) -> Result<()> {
    let app = Router::new()
        .route("/health", get(health_check))
        .route("/livez", get(liveness_check))
        .route("/readyz", get(readiness_check))
        .with_state(Arc::new(state));

    let addr = format!("0.0.0.0:{}", port);
    let listener = TcpListener::bind(&addr).await?;

    info!("Health check endpoint listening on {}", addr);

    axum::serve(listener, app)
        .await
        .map_err(|e| anyhow::anyhow!("Health server error: {}", e))
}

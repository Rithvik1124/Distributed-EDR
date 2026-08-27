mod db;
mod node_roles;
mod detect;
mod handlers;
mod telemetry;

use crate::telemetry::TelemetryEvent;
use crate::detect::edr_detect_rules;

use axum::{
    extract::State,
    routing::post,
    Json,
    Router,
};
use serde::{Deserialize, Serialize};
use std::sync::Arc;
use tokio::sync::{mpsc, Mutex};

#[derive(Clone)]
struct AppState {
    sender: mpsc::Sender<TelemetryEvent>,
}

async fn publish(
    State(state): State<AppState>,
    Json(event): Json<TelemetryEvent>,
) -> &'static str {
    if state.sender.send(event).await.is_err() {
        return "Queue is closed";
    }

    "Event queued successfully"
}


async fn yara_event_in(
    Json(event): Json<String>,
) -> &'static str {
    println!("Received YARA event: {}", event);

    // Process the string here.

    "YARA event received"
}

async fn ioc_event_in(
    Json(event): Json<String>,
) -> &'static str {
    println!("Received IOC event: {}", event);

    // Process the string here.

    "IOC event received"
}

async fn sigma_event_in(
    Json(event): Json<String>,
) -> &'static str {
    println!("Received Sigma event: {}", event);

    // Process the string here.

    "Sigma event received"
}

async fn consensus_event_in(
    Json(event): Json<String>,
) -> &'static str {
    println!("Received Consensus event: {}", event);

    // Process the string here.

    "Consensus event received"
}

#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel::<TelemetryEvent>(100_000);

    let rx = Arc::new(Mutex::new(rx));

    for worker_id in 0..2 {
        let rx = rx.clone();

        tokio::spawn(async move {
            loop {
                let event = {
                    let mut rx = rx.lock().await;
                    rx.recv().await
                };

                match event {
                    Some(event) => {
                        crate::db::events_in::write_event(event);
                    }
                    None => break,
                }
            }
        });
    }

    let app = Router::new()
        .route("/publish", post(publish))
        .route("/yara-check", post(yara_event_in))
        .route("/sigma-check", post(sigma_event_in))
        .route("/ioc-check", post(ioc_event_in))
        .route("/consensus-check", post(consensus_event_in))

        .with_state(AppState { sender: tx });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    println!("Listening on http://localhost:3000");

    axum::serve(listener, app).await.unwrap();
}
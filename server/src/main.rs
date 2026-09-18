// mod db;
mod handlers;
mod node_roles;
mod telemetry;
use axum::middleware::Next;
use axum::response::Response;
use axum::extract::Request;
use crate::{node_roles::{ioc::ioc_detection::{FileHashRequest, HashResponse, find_ioc_result, return_file_hash, send_ioc_result}, sigma::sigma_detection::find_sigma_result, yara::yara_detection::{handle_yara_request, match_yara_rule}}, telemetry::{TelemetryEvent, YaraRequest}};
// use crate::detect::edr_detect_rules;

use axum::{
    extract::State,
    routing::post,
    Json,
    Router,
};
use sha256::try_digest;
// use serde::{Deserialize, Serialize};
use std::{path::Path, sync::Arc};
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

// removable
async fn yara_event_in(
    Json(event): Json<String>,
) -> &'static str {
    println!("Received YARA event: {}", event);

    // Process the string here.

    "YARA event received"
}

async fn yara_request_in(
    Json(event): Json<YaraRequest>,
) -> &'static str {
    handle_yara_request(event);

    "YARA request received"
}

async fn cache_event(
    Json(event): Json<String>,
) -> &'static str {
    println!("Received event for caching: {}", event);

    // Process the string here.

    "YARA event received"
}

async fn ioc_event_in(
    payload: Result<Json<TelemetryEvent>, axum::extract::rejection::JsonRejection>,
) -> &'static str {
    match payload {
        Ok(Json(event)) => {
            println!("RECEIVED IOC: {:?}", &event);
            send_ioc_result(event).await;
            "ok"
        }
        Err(e) => {
            println!("JSON ERROR: {:?}", e);
            "bad request"
        }
    }
}

// respond to the request sent by ioc server
async fn send_file_hash(
    Json(req): Json<FileHashRequest>,
) -> Json<HashResponse> {
    //needs to be replaced - no exception handling
    let hash = return_file_hash(&req.file_path);
    Json(HashResponse { hash })
}

async fn sigma_event_in(
    payload: Result<Json<TelemetryEvent>, axum::extract::rejection::JsonRejection>,
) -> &'static str {
    match payload {
        Ok(Json(event)) => {
            println!("RECEIVED: {:?}", &event);
            find_sigma_result(event).await;
            "ok"
        }
        Err(e) => {
            println!("JSON ERROR: {:?}", e);
            "bad request"
        }
    }
}

async fn log_requests(req: Request, next: Next) -> Response {
    println!("--> {:?}", req.uri());
    next.run(req).await
}

async fn consensus_event_in(
    Json(event): Json<TelemetryEvent>,
) -> &'static str {
    println!("CONSENSUS HIT: {:#?}", event);
    "ok"
}
#[tokio::main]
async fn main() {
    let (tx, rx) = mpsc::channel::<TelemetryEvent>(100_000);
    let rx = Arc::new(Mutex::new(rx));

    for _ in 0..2 {
        let rx = rx.clone();
        tokio::spawn(async move {
            loop {
                let event = {
                    let mut rx = rx.lock().await;
                    rx.recv().await
                };

                match event {
                    Some(event) => {
                        println!("{:?}", event);
                    }
                    None => break,
                }
                
            }
        });
    }

    let internal_routes = Router::new()
        .route("/consensus-check", post(consensus_event_in))
        .route("/sigma-check", post(sigma_event_in))
        .route("/publish", post(publish))
        .route("/yara-reqs", post(yara_request_in))
        .route("/cache-event", post(cache_event))
        .route("/ioc-check", post(ioc_event_in))
        .route("/file-hash", post(send_file_hash));

    let app = Router::new()
        .merge(internal_routes)
        .layer(axum::middleware::from_fn(log_requests))
        .with_state(AppState { sender: tx });

    let listener = tokio::net::TcpListener::bind("0.0.0.0:3000")
        .await
        .unwrap();

    println!("Listening on http://localhost:3000");

    axum::serve(listener, app)
        .await
        .unwrap();
}
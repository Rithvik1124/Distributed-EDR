use crate::node_roles::ioc::{BLOCKLIST_IP_IOC_MAP, FILE_HASHES_MAP};
use crate::node_roles::cache::*;
use crate::telemetry::{BlockedIPResponse, BlockedIPStatus, FileHashResponse, FileHashStatus, IOCEventResponse, TelemetryEvent};
use sha256::{digest, try_digest};
use std::net::Ipv4Addr;
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    fs::File,
    net::IpAddr,
    sync::LazyLock,
    path::Path,
};
use reqwest::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FileHashRequest {
    pub file_path: String,
}

#[derive(Serialize)]
pub struct HashResponse {
    pub hash: Option<String>,
}


pub async fn get_file_hash(dir: &str) -> String {
    println!("get_file_hash\n\n");
    let client = Client::new();

    let req = FileHashRequest {
        file_path: dir.to_string(),
    };

    let resp = client
        .post("http://127.0.0.1:3000/file-hash")
        .json(&req)
        .send()
        .await
        .unwrap()
        .text()
        .await
        .unwrap();

    resp
}

pub fn return_file_hash(path: &str) -> Option<String> {
    let input = Path::new(path);

    if !input.is_file() {
        return None;
    }

    try_digest(input).ok()
}

fn blocked_ip_check(ip: IpAddr) -> BlockedIPResponse {
    if BLOCKLIST_IP_IOC_MAP.contains_key(&ip) {
        BlockedIPResponse {
            status: BlockedIPStatus::IPHit,
            mal_ip: Some(ip),
        }
    } else {
        BlockedIPResponse {
            status: BlockedIPStatus::NoIPMatched,
            mal_ip: None,
        }
    }
}

fn check_file_hash(file_hash: String) -> FileHashResponse {
    if FILE_HASHES_MAP.contains_key(&file_hash) {
        FileHashResponse {
            file_hash_status: FileHashStatus::HashHit,
            file_hash,
        }
    } else {
        FileHashResponse {
            file_hash_status: FileHashStatus::NoHashMatched,
            file_hash,
        }
    }
}
//Adds all responses to the telemetry struct


pub async fn find_ioc_result(mut result: TelemetryEvent) -> TelemetryEvent {
    println!("find_ioc_result\n\n");
    let file_hash = get_file_hash(&result.filename).await;

    let file_result = check_file_hash(file_hash);

    let ip: IpAddr = result.dst_ip.parse().unwrap_or(IpAddr::V4(Ipv4Addr::UNSPECIFIED));

    let ip_result = blocked_ip_check(ip);

    result.analysis_result.ioc_results = IOCEventResponse {
        file_hash_result: file_result,
        blocked_ip_result: ip_result,
    };
    result.ioc_check=true;

    result
}
pub async fn send_ioc_result(event: TelemetryEvent) {
    let client = Client::new();

    let event_id = crate::handlers::hash_event(&event);

    if let Some(cached) = get_ioc_cached_event(event_id) {
        let enriched = TelemetryEvent {
            analysis_result: crate::telemetry::AnalysisResult {
                ioc_results: cached,
                ..event.analysis_result.clone()
            },
            ..event
        };

        let _ = client
            .post("http://127.0.0.1:3000/consensus-check")
            .json(&enriched)
            .send()
            .await;

        return;
    }

    let enriched_event = find_ioc_result(event).await;

    let ioc_result = enriched_event.analysis_result.ioc_results.clone();
    cache_ioc_event(event_id, &ioc_result);

    let _ = client
        .post("http://127.0.0.1:3000/consensus-check")
        .json(&enriched_event)
        .send()
        .await;
}
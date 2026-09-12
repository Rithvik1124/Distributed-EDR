use crate::node_roles::ioc::{BLOCKLIST_IP_IOC_MAP, FILE_HASHES_MAP};
use crate::node_roles::cache::*;
use crate::telemetry::{BlockedIPResponse, BlockedIPStatus, FileHashResponse, FileHashStatus, IOCEventResponse, TelemetryEvent};
use sha256::{digest, try_digest};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    fs::File,
    net::IpAddr,
    sync::LazyLock,
    path::Path,
};
use reqwest::blocking::Client;
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize)]
pub struct FileHashRequest {
    pub file_path: String,
}

#[derive(Serialize)]
pub struct HashResponse {
    pub hash: String,
}


fn get_file_hash(dir: &str) -> String {
    let client = Client::new();

    let req = FileHashRequest {
        file_path: dir.to_string(),
    };

    let resp = client
        .post("http://127.0.0.1:8000/file-hash")
        .json(&req)
        .send()
        .unwrap()
        .text()
        .unwrap();

    resp
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


pub fn find_ioc_result(mut result: TelemetryEvent) -> TelemetryEvent {
    // 1. compute file hash
    let file_hash = get_file_hash(&result.filename);

    let file_result = check_file_hash(file_hash);

    // 2. parse IP
    let ip: IpAddr = result.dst_ip.parse().unwrap_or_else(|_| {
        "0.0.0.0".parse().unwrap()
    });

    let ip_result = blocked_ip_check(ip);
    

    // 3. combine into IOC response
    result.analysis_result.ioc_results = IOCEventResponse {
        file_hash_result: file_result,
        blocked_ip_result: ip_result,
    };

    result
}
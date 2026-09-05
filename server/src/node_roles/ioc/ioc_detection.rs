use crate::node_roles::ioc::{BLOCKLIST_IP_IOC_MAP, FILE_HASHES_MAP};
use crate::telemetry::{BlockedIPStatus, BlockedIPResponse, FileHashResponse, FileHashStatus, TelemetryEvent};
use sha256::{digest, try_digest};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    fs::File,
    net::IpAddr,
    sync::LazyLock,
    path::Path,
};

use reqwest::blocking::get;


fn get_file_hash(dir: &str) -> String {
    let input = Path::new(dir);
    try_digest(input).unwrap()
}

fn blocked_ip_check(ip: IpAddr)-> BlockedIPResponse{
    if BLOCKLIST_IP_IOC_MAP.contains_key(&ip) {
        BlockedIPResponse{
            status: BlockedIPStatus::IPHit,
            mal_ip: Some(ip),
        }
    } else {
        BlockedIPResponse{
            status: BlockedIPStatus::NoIPMatched,
            mal_ip: Some(ip),
        }
    }
}

fn check_file_hash(file_hash: String) -> FileHashResponse {
    if FILE_HASHES_MAP.contains_key(&file_hash) {
        FileHashResponse { file_hash_status: FileHashStatus::HashHit, file_hash: file_hash }
    } else {
        FileHashResponse { file_hash_status: FileHashStatus::NoHashMatched, file_hash: "None".to_string()}
    }
}

//Adds all responses to the telemetry struct

// pub fn find_ioc_result(mut result: TelemetryEvent)-> TelemetryEvent{
//     let sigma_input = telemetry_to_event(&result);
//     let sigma_result = match_sigma_rule(&sigma_input);

//     //Add a cache checing logix

//     //send this result to server
//     result.analysis_result.sigma_results = sigma_result;
//     result
    
// }
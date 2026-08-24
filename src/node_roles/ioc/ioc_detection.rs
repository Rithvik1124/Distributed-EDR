use crate::node_roles::ioc::{BLOCKLIST_IP_IOC_MAP, FILE_HASHES_MAP};
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

#[derive(PartialEq, Debug)]

pub enum FileHashStatus {
    HashHit,
    NoHashMatched,
}

pub enum BlockedIPStatus{
    IPHit,
    NoIPMatched,
}


struct BlockedIPResponse{
    status: BlockedIPStatus,
    mal_ip: IpAddr,
}

fn get_file_hash(dir: &str) -> String {
    let input = Path::new(dir);
    try_digest(input).unwrap()
}

fn blocked_ip_check(ip: IpAddr)-> BlockedIPResponse{
    if BLOCKLIST_IP_IOC_MAP.contains_key(&ip) {
        BlockedIPResponse{
            status: BlockedIPStatus::IPHit,
            mal_ip: ip,
        }
    } else {
        BlockedIPResponse{
            status: BlockedIPStatus::NoIPMatched,
            mal_ip: ip,
        }
    }
}

fn check_file_hash(file_hash: String) -> FileHashStatus {
    if FILE_HASHES_MAP.contains_key(&file_hash) {
        FileHashStatus::HashHit
    } else {
        FileHashStatus::NoHashMatched
    }
}


use crate::ioc::{BLOCKLIST_IP_IOC_MAP, FILE_HASHES_MAP};
use sha256::{digest, try_digest};
use std::{
    collections::HashMap,
    io::{BufRead, BufReader},
    fs::File,
    net::Ipv4Addr,
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


fn get_file_hash(dir: &str) -> String {
    let input = Path::new(dir);
    try_digest(input).unwrap()
}

fn blocked_ip_check(ip: IpAddr)-> BlockedIPStatus{
    if BLOCKLIST_IP_IOC_MAP.contains_key(&file_hash) {
        BlockedIPStatus::IPHit
    } else {
        BlockedIPStatus::NoIPMatched
    }
}

fn check_file_hash(file_hash: String) -> FileHashStatus {
    if FILE_HASHES_MAP.contains_key(&file_hash) {
        FileHashStatus::HashHit
    } else {
        FileHashStatus::NoHashMatched
    }
}


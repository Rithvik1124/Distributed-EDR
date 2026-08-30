pub mod ioc;
pub mod sigma;
pub mod yara;
pub mod consensus;
pub mod transport;
use std::{ fs, net::Ipv4Addr, str::FromStr, sync::{Arc, LazyLock, RwLock}, };
use axum::routing::get;
use serde::Deserialize;

use lru::LruCache;
//CACHING

pub static CACHE: LazyLock<Arc<RwLock<LruCache<String, String>>>> =
    LazyLock::new(|| Arc::new(RwLock::new(LruCache::unbounded())));
pub static CONSENSUS_NODE_IP: LazyLock<Ipv4Addr>= LazyLock::new(|| get_consensus_ip());
pub static SERVER_IP: LazyLock<Ipv4Addr>= LazyLock::new(|| get_server_ip());

#[derive(Deserialize)]
struct NodeConfig {
    Sigma: bool,
    Consensus: bool,
    IOC: bool,
    Server: String,
    Sigma_Server: String,
    Consensus_Server: String,
    IOC_Server: String,
}

fn get_consensus_ip() -> Ipv4Addr {
    let data = fs::read_to_string("node.config.json")
        .expect("Unable to read file");

    let config: NodeConfig = serde_json::from_str(&data)
        .expect("Unable to parse JSON");

    config.Consensus_Server
        .parse()
        .expect("Consensus_Server must be a valid IPv4 address")
}

pub fn get_server_ip()-> Ipv4Addr{

    let data = fs::read_to_string("node.config.json")
            .expect("Unable to read file");

    let config: NodeConfig = serde_json::from_str(&data)
        .expect("Unable to parse JSON");

    config.Server
        .parse()
        .expect("Consensus_Server must be a valid IPv4 address")
}

pub fn get_sigma_ip()-> Ipv4Addr{
    let data = fs::read_to_string("node.config.json")
        .expect("Unable to read file");

    let config: NodeConfig = serde_json::from_str(&data)
        .expect("Unable to parse JSON");

    config.Sigma_Server
        .parse()
        .expect("Consensus_Server must be a valid IPv4 address")

}


pub fn get_ioc_ip()-> Ipv4Addr{
    let data = fs::read_to_string("node.config.json")
        .expect("Unable to read file");

    let config: NodeConfig = serde_json::from_str(&data)
        .expect("Unable to parse JSON");

    config.IOC_Server
        .parse()
        .expect("Consensus_Server must be a valid IPv4 address")
}

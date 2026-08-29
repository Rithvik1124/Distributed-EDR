use serde::{Deserialize, Serialize};
use std::{fs, net::IpAddr};

const NODE_CONFIG_FILE: &str = "node.config.json";

#[derive(Debug, Clone, Copy)]
enum Role {
    Sigma,
    IOC,
    Consensus,
}

#[derive(Debug, Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct NodeConfig {
    sigma: bool,
    ioc: bool,
    consensus: bool,
    server_ip: IpAddr,
}

impl Default for NodeConfig {
    fn default() -> Self {
        Self {
            sigma: false,
            ioc: false,
            consensus: false,
            server_ip: "127.0.0.1".parse().unwrap(),
        }
    }
}

fn find_roles() -> Vec<Role> {
    let file = match fs::File::open(NODE_CONFIG_FILE) {
        Ok(file) => file,
        Err(_) => return Vec::new(),
    };

    let config: NodeConfig = match serde_json::from_reader(file) {
        Ok(config) => config,
        Err(_) => return Vec::new(),
    };

    let mut roles = Vec::new();

    if config.sigma {
        roles.push(Role::Sigma);
    }

    if config.ioc {
        roles.push(Role::IOC);
    }

    if config.consensus {
        roles.push(Role::Consensus);
    }

    roles
}
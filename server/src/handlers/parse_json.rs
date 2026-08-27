use serde::{Deserialize, Serialize};
use std::{fs, io::Write, net::IpAddr};

const NODE_CONFIG_FILE: &str = "node.config.json";

#[derive(Debug, Deserialize)]
enum Role {
    Sigma,
    IOC,
    Consensus,
}
#[derive(Deserialize, Serialize)]
#[serde(rename_all = "PascalCase")]
struct JSON{
    sigma: bool,
    ioc: bool,
    consensus: bool,
    server_ip: IpAddr,
}

fn find_roles()-> Vec<Role> {
    let mut roles: Vec<Role> = Vec::new();
    let file = fs::File::open("node.config.json")
        .expect("file should open read only");
    let json: serde_json::Value = serde_json::from_reader(file)
        .expect("file should be proper JSON");
    if json.get("Sigma").is_some(){
        roles.push(Role::Sigma);
    }else if json.get("IOC").is_some(){
        roles.push(Role::IOC);
    }else if json.get("Consensus").is_some(){
        roles.push(Role::Consensus);
    } 
    roles
}

fn write_roles(body: &str){
    let file = fs::File::open(NODE_CONFIG_FILE)
        .expect("file should open read only");
    let request = match serde_json::from_str::<Role>(body) {
        Ok(req) => req,
        // 🟡 Fix this to something relevant
        Err(e) => {
            req = JSON {
                sigma: false,
                ioc: false,
                consensus: false,
                server_ip: IpAddr::new()
            };
        }
    };
    let roles = serde_json::to_string(&request).unwrap();
    file.write_all(roles.as_bytes()).expect("Should be able to write data");
}

pub mod ioc_detection;
use std::{
    collections::HashMap, fs::{File}, hash::Hash, net::IpAddr, sync::LazyLock, io::{BufRead, BufReader}
};
use reqwest::blocking::get;

/// Global IOC map:
/// IPSum -> threat level (1–8)
pub static BLOCKLIST_IP_IOC_MAP: LazyLock<HashMap<IpAddr, u8>> =
    LazyLock::new(|| load_ipsum_ioc());

pub static FILE_HASHES_MAP: LazyLock<HashMap<String, u8>> = LazyLock::new(|| {
    load_file_hashes("file_hashes/full_sha256.txt")
});

fn load_file_hashes(dir: &str) -> HashMap<String, u8> {
    let mut map = HashMap::new();

    let file = match File::open(dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("failed to open file hashes: {:?}", e);
            return map;
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines().flatten() {
        let line = line.trim();
        if !line.is_empty() {
            map.insert(line.to_string(), 1);
        }
    }

    println!("shit worked");
    map
}


fn load_ipsum_ioc() -> HashMap<IpAddr, u8> {
    let mut map: HashMap<IpAddr, u8> = HashMap::new();

    for level in 1..=8 {
        let url = format!(
            "https://raw.githubusercontent.com/stamparm/ipsum/master/levels/{}.txt",
            level
        );

        let body = match get(&url) {
            Ok(resp) => match resp.text() {
                Ok(t) => t,
                Err(_) => continue,
            },
            Err(_) => continue,
        };

        for line in body.lines() {
            let ip_str = line.trim();

            if ip_str.is_empty() || ip_str.starts_with('#') {
                continue;
            }

            if let Ok(ip) = ip_str.parse::<IpAddr>() {
                map.insert(ip, level as u8);
            }
        }
    }

    map
}
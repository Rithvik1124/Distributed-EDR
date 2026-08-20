use std::{
    collections::HashMap, fs::{File}, hash::Hash, net::Ipv4Addr, sync::LazyLock, io::{BufRead, BufReader}
};

use reqwest::blocking::get;

/// Global IOC map:
/// IPSum -> threat level (1–8)
pub static BLOCKLIST_IP_IOC_MAP: LazyLock<HashMap<Ipv4Addr, u8>> = LazyLock::new(|| {
    load_ipsum_ioc()
});

pub static FILE_HASHES_MAP: LazyLock<HashMap<String, u8>> = LazyLock::new(|| {
    load_file_hashes("file_hashes/full_sha256.txt")
});

fn load_file_hashes(dir: &str) -> HashMap<String, u8> {
    let mut file_hashes = HashMap::new();

    let file = File::open(dir).unwrap();
    let reader = BufReader::new(file);

    println!("Reading file line-by-line:\n");

    for line_result in reader.lines() {
        let line = line_result.unwrap();
        let line = line.trim().to_string(); // FIX: must own String

        file_hashes.insert(line, 1);
    }

    file_hashes
}


fn load_ipsum_ioc() -> HashMap<Ipv4Addr, u8> {
    let mut map: HashMap<Ipv4Addr, u8> = HashMap::new();

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

            if let Ok(ip) = ip_str.parse::<Ipv4Addr>() {
                map.insert(ip, level as u8);
            }
        }
    }

    map
}
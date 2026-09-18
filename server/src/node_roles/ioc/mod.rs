pub mod ioc_detection;
use std::{
    collections::HashMap, fs::{File}, hash::Hash, net::IpAddr, sync::LazyLock, io::{BufRead, BufReader}
};
use reqwest;

/// Global IOC map:
/// IPSum -> threat level (1–8)
pub static BLOCKLIST_IP_IOC_MAP: LazyLock<HashMap<IpAddr, u8>> =
LazyLock::new(|| {
    println!("[IOC INIT] BLOCKLIST START");

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/node_roles/ioc/file_hashes/ipsum.txt");

    println!("[IOC IPSUM INIT] path = {:?}", path);

    let res = load_ipsum_ioc(path.to_str().unwrap());

    println!("[IOC INIT] BLOCKLIST DONE size={}", res.len());

    res
});

pub static FILE_HASHES_MAP: LazyLock<HashMap<String, u8>> =
LazyLock::new(|| {
    println!("[IOC INIT] FILE_HASHES_MAP START");

    let path = std::path::Path::new(env!("CARGO_MANIFEST_DIR"))
        .join("src/node_roles/ioc/file_hashes/full_sha256.txt");

    println!("[IOC INIT] path = {:?}", path);

    let res = load_file_hashes(path.to_str().unwrap());

    println!("[IOC INIT] FILE_HASHES_MAP DONE size={}", res.len());

    res
});

fn load_file_hashes(dir: &str) -> HashMap<String, u8> {
    let mut map = HashMap::new();

    let file = match File::open(dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[IOC INIT] failed to open {}: {:?}", dir, e);
            return map; // ❗ NO PANIC
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines() {
        match line {
            Ok(l) => {
                let l = l.trim();
                if !l.is_empty() {
                    map.insert(l.to_string(), 1);
                }
            }
            Err(e) => {
                eprintln!("[IOC INIT] bad line: {:?}", e);
                continue;
            }
        }
    }

    println!("[IOC INIT] file hash map loaded: {}", map.len());
    map
}

fn load_ipsum_ioc(dir: &str) -> HashMap<IpAddr, u8> {
    let mut map = HashMap::new();

    let file = match File::open(dir) {
        Ok(f) => f,
        Err(e) => {
            eprintln!("[IOC INIT] failed to open {}: {:?}", dir, e);
            return map;
        }
    };

    let reader = BufReader::new(file);

    for line in reader.lines() {
        match line {
            Ok(line) => {
                if let Ok(ip) = line.trim().parse::<IpAddr>() {
                    map.insert(ip, 1);
                }
            }
            Err(e) => {
                eprintln!("[IOC INIT] failed to read line: {:?}", e);
            }
        }
    }

    println!("[IOC INIT] loaded {} IPs", map.len());

    map
}
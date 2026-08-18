use std::{
    collections::HashMap,
    net::Ipv4Addr,
    sync::LazyLock,
};

use reqwest::blocking::get;

/// Global IOC map:
/// IPSum -> threat level (1–8)
pub static IPSUM_IOC_MAP: LazyLock<HashMap<Ipv4Addr, u8>> = LazyLock::new(|| {
    load_ipsum_ioc()
});

fn load_ipsum_ioc() -> HashMap<Ipv4Addr, u8> {
    let mut map: HashMap<Ipv4Addr, u8> = HashMap::new();

    // IPsum levels 1 to 8
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
pub mod parse_json;
pub use parse_json::*; 
use chrono::{DateTime, Utc};

pub fn convert_result_to_string(x: &[u8]) -> String {
    let mut output = String::new();

    for i in 0..x.len(){
        if x[i] == 0 {
        break;
    }
        output.push_str(&format!("{}", x[i] as char));

    }


    return output;
}

pub fn nanosec_to_timestamp(monotonic_ns: u64, offset_ns: i128) -> String {
    let unix_ns = monotonic_ns as i128 + offset_ns;

    let timestamp = DateTime::<Utc>::from_timestamp_nanos(unix_ns as i64);

    timestamp
        .format("%Y-%m-%d %H:%M:%S%.3f UTC")
        .to_string()
} 

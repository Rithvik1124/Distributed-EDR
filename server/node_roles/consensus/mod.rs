pub mod detection;
use std::{ fs::{File, exists}, io::prelude::*};
use chrono::{Local, Utc, NaiveDate};
use std::hash::{Hasher,DefaultHasher, Hash};
use crate::node_roles::{telemetry::TelemetryEvent, CACHE};

fn log_event(event: &TelemetryEvent)->std::io::Result<()>{
    let dt1: NaiveDate = Local::now().date_naive();
    let timestamp_utc = Utc::now();
    let timestamp: i64 = timestamp_utc.timestamp();
    let file_path = format!("{}.txt",dt1);
    if exists(file_path)?{
        let mut file = File::open("foo.txt")?;
        file.write(&format!("{}: {:#?}", timestamp, event).into_bytes());

        
    }else{
        let mut file = File::create(format!("{}.txt",dt1))?;
        file.write("Time(UTC): Event".as_bytes());
        file.write(&format!("{}: {:#?}", timestamp, event).into_bytes());
    }
    Ok(())
    
}

fn drop_redundant_event(event: TelemetryEvent){
    let mut cache = CACHE.write().unwrap();

    if !cache.contains(&hash_event(&event).to_string()) {
        cache.put(hash_event(&event).to_string(), "0".to_string());
    }
}



fn hash_event(event: &TelemetryEvent) -> u64 {
    let mut hasher = DefaultHasher::new();

    event.event_type.hash(&mut hasher);
    event.pid.hash(&mut hasher);
    event.filename.hash(&mut hasher);

    hasher.finish()
}
use redb::{Database, TableDefinition, ReadableTable, ReadableDatabase};
use serde::{Deserialize, Serialize};
//mod initialize_db;
use crate::telemetry::{TelemetryEvent, DetectionResult};
use crate::detect::edr_detect_rules;
use reqwest::Client;
use tokio::sync::mpsc;
use std::hash::{DefaultHasher, Hash, Hasher};
const EVENTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events_in");
use std::sync::LazyLock;

use crate::node_roles::{sigma::sigma_detection::match_sigma_rule, yara::yara_detection::match_yara_rule};

// Was calling setdb in the function each time so turned it into static
const PATH: &str = "events_in.redb";
static DB: LazyLock<Database> = LazyLock::new(|| {
    Database::create(PATH)
        .expect("Failed to create DB")
});

fn calculate_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

// 🟡 dynamic ip yara requests
// pub fn write_sigma_rule()
fn get_yara(file_dir: String){
    let client = Client::new();

    let (tx, mut rx) = mpsc::channel::<String>(1024); // 1024 is the channel capacity, both want EVent here

    let http_client = client.clone();
    tokio::spawn(async move {
        while let Some(some_event) = rx.recv().await {
            if let Err(e) = http_client
                .post("http://127.0.0.1:3000/yara-check")
                .json(&some_event)
                .send()
                .await
            {
                eprintln!("Failed to send telemetry: {}", e);
            }
        }
    });

    if let Err(e) = tx.try_send(file_dir) {
        eprintln!("Telemetry queue full, dropping event: {}", e);
    }
}

pub fn write_event(mut event: TelemetryEvent) -> Result<(), Box<dyn std::error::Error>>{
    println!("Starting write");
    let event_id = calculate_hash(&event);
    event.analysis_result.sigma_results = match_sigma_rule(&event);
    
    event.analysis_result.yara_results = Vec::new();

    match event.event_type.as_str() {
        "Execve" | "Execveat" | "Unlinkat" | "Renameat" | "Renameat2" => {
            if !event.filename.trim().is_empty() {
                event.analysis_result.yara_results = match_yara_rule(&event.filename.to_string());
            }
        }
        _ => {}
    }

    let write_txn = DB.begin_write().unwrap();
    {
        let mut table = write_txn.open_table(EVENTS_TABLE)?;
        
        //event.insert("event_id",calculate_hash(&event));
        // Serialize to bytes before inserting.
        // bincode is faster and smaller than JSON for internal storage.
        let bytes = bincode::serde::encode_to_vec(
            &event,
            bincode::config::standard(),
        )?;
        table.insert(event_id, &bytes.as_slice())?;
    }
    write_txn.commit()?;

    let read_txn = DB.begin_read()?;
    println!("Opened DB");
    let table = read_txn.open_table(EVENTS_TABLE)?;
    // Clone the bytes to own them outside the transaction scope.
    // redb values borrow from the transaction and cannot outlive it.//  
    let stored_bytes = table.get(event_id)?.map(|v| v.value().to_vec());

    if let Some(bytes) = stored_bytes {
        let (coffee, _): (TelemetryEvent, usize) =
        bincode::serde::decode_from_slice(
            &bytes,
            bincode::config::standard(),
        )?;
        println!("Loaded: {:?}", coffee);
    }
    Ok(())

}


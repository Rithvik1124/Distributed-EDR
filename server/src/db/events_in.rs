use redb::{Database, TableDefinition, 
            ReadableTable, ReadableDatabase};
use std::{sync::LazyLock, hash::{DefaultHasher, Hash, Hasher}};
use crate::telemetry::{TelemetryEvent, YaraEventResponse, SigmaEventResponse};
use crate::detect::edr_detect_rules;
use reqwest::Client;
use tokio::sync::mpsc;
use crate::node_roles::{sigma::sigma_detection::match_sigma_rule, 
            yara::yara_detection::match_yara_rule};
//mod initialize_db;

const EVENTS_TABLE: TableDefinition<u64, &[u8]> =
    TableDefinition::new("events_in");
const FLAGS_INDEX: TableDefinition<(u8, u64), ()> =
    TableDefinition::new("events_flags");
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

fn calculate_flags(event: &TelemetryEvent) -> u8 {
    (event.ioc_check as u8)
        | ((event.yara_check as u8) << 1)
        | ((event.sigma_check as u8) << 2)
}

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

pub fn find_all_checks_true(
) -> Result<Vec<TelemetryEvent>, Box<dyn std::error::Error>> {
    let read_txn = DB.begin_read()?;

    let flags_table = read_txn.open_table(FLAGS_INDEX)?;
    let events_table = read_txn.open_table(EVENTS_TABLE)?;

    let mut results = Vec::new();

    let target_flags = 7u8;
    let start = (target_flags, 0u64);
    let end = (target_flags, u64::MAX);

    for entry in flags_table.range(start..=end)? {
        let (key, _) = entry?;

        let (_flags, event_id) = key.value();

        if let Some(value) = events_table.get(event_id)? {
            let bytes = value.value();

            let (event, _): (TelemetryEvent, usize) =
                bincode::serde::decode_from_slice(
                    bytes,
                    bincode::config::standard(),
                )?;

            results.push(event);
        }
    }

    Ok(results)
}

fn write_event(){
    //check if event_id exists
    //if yes -> check event_type; append the values
    //else -> append the new event
}
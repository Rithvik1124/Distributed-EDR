use redb::{Database, TableDefinition, 
            ReadableTable, ReadableDatabase};
use std::{sync::LazyLock, hash::{DefaultHasher, Hash, Hasher}};
use crate::telemetry::{AnalysisResult, BlockedIPStatus::NoIPMatched, FileHashStatus::NoHashMatched, SigmaStatus, TelemetryEvent, YaraStatus};
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

fn merge_analysis(
    old: &mut AnalysisResult,
    new: &AnalysisResult,
) {
    if new.is_mal {
        old.is_mal = true;
    }

    if new.sigma_results.status == SigmaStatus::SigmaHit {
        old.sigma_results = new.sigma_results.clone();
    }

    if new.yara_results.status == YaraStatus::YaraHit {
        old.yara_results = new.yara_results.clone();
    }

    //Needs a new struct and re-write in /node_roles/ioc/
    if !(new.ioc_results.file_hash_result.file_hash_status==NoHashMatched|| new.ioc_results.blocked_ip_result.status==NoIPMatched) {
        old.ioc_results = new.ioc_results.clone();
    }
}

    //check if event_id exists
    //if yes -> check event_type; append the values
    //else -> append the new event
pub fn write_event(event: TelemetryEvent) -> Result<(), Box<dyn std::error::Error>> {
    let event_id = calculate_hash(&event);

    let write_txn = DB.begin_write()?;

    {
        let mut events_table = write_txn.open_table(EVENTS_TABLE)?;

        // 1. Fetch existing event (if any)
        let existing_event: Option<TelemetryEvent> =
            match events_table.get(event_id)? {
                Some(v) => Some(
                    bincode::serde::decode_from_slice(
                        v.value(),
                        bincode::config::standard(),
                    )?.0
                ),
                None => None,
            };

        // 2. Merge or insert
        let final_event = if let Some(mut existing) = existing_event {
            // MERGE analysis results
            merge_analysis(
                &mut existing.analysis_result,
                &event.analysis_result,
            );

            existing
        } else {
            event
        };

        // 3. Encode final event
        let encoded = bincode::serde::encode_to_vec(
            &final_event,
            bincode::config::standard(),
        )?;

        // 4. Write back
        events_table.insert(event_id, encoded.as_slice())?;
    }

    write_txn.commit()?;

    Ok(())
}
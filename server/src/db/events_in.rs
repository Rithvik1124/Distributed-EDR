use redb::{Database, TableDefinition, ReadableTable, ReadableDatabase};
use serde::{Deserialize, Serialize};
//mod initialize_db;
use crate::telemetry::TelemetryEvent;
use std::hash::{DefaultHasher, Hash, Hasher};
const EVENTS_TABLE: TableDefinition<u64, &[u8]> = TableDefinition::new("events_in");
use std::sync::LazyLock;

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


pub fn write_event(event: TelemetryEvent) -> Result<(), Box<dyn std::error::Error>>{
    println!("Starting write");
    let event_id = calculate_hash(&event);
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
    // Ok(())

    let read_txn = DB.begin_read()?;
    println!("Opened DB");
    let table = read_txn.open_table(EVENTS_TABLE)?;
    // // Clone the bytes to own them outside the transaction scope.
    // // redb values borrow from the transaction and cannot outlive it.
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


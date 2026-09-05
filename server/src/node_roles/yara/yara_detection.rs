use std::{fs, io::Read, hash::{Hash, DefaultHasher, Hasher}};
use reqwest::blocking::Client;
use serde::Serialize;
use yara_x::{Scanner};
use crate::node_roles::yara::YARA_RULES;
use crate::telemetry::{
            TelemetryEvent,
            YaraEventResponse,
            YaraStatus::{YaraHit, NoRuleMatched},
            ResponseType::Yara,
            YaraConsensusPacket,
            YaraRequest,

};


pub fn match_yara_rule(req: YaraRequest) {
    // Read file bytes
    let event_id = req.event_id;
    
    let mut file = fs::File::open(&req.file_dir).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    // Build scanner
    let mut scanner = Scanner::new(&YARA_RULES);

    let results = scanner.scan(&data).unwrap();

    let mut rules_hit: Vec<String> = Vec::new();

    for rule in results.matching_rules() {
        rules_hit.push(rule.identifier().to_string());
    }

    let response = if !rules_hit.is_empty() {
        YaraEventResponse {
            response_type: Yara,
            status: YaraHit,
            rule_matched: rules_hit,
        }
    } else {
        YaraEventResponse {
            response_type: Yara,
            status: NoRuleMatched,
            rule_matched: rules_hit,
        }
    };

    // SEND TO CONSENSUS SERVER

    let packet = YaraConsensusPacket {
        event_id,
        response,
    };

    let client = Client::new();

    let _ = client
        .post("https://127.0.0.1:3000/consensus-check")
        .json(&packet)
        .send();
}

//Sends yara req to the ip(localhost rn) the ip sends the result back to https://<ip>/consensus-check(in src/node_roles/transport/), along with
//Needs xception handling - even though almost every everything needs xception handling(major bloat)
pub fn send_yara_search_req(event_id: u64, file_dir: String) {
    let client = Client::new();

    let req = YaraRequest {
        event_id,
        file_dir,
    };

    let _ = client
        .post("http://127.0.0.1:3000/yara-reqs")
        .json(&req)
        .send();
}

fn calculate_hash<T: Hash>(value: &T) -> u64 {
    let mut hasher = DefaultHasher::new();
    value.hash(&mut hasher);
    hasher.finish()
}

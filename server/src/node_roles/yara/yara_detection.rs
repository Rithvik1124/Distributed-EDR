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

pub fn match_yara_rule(file_dir: &str) -> YaraEventResponse {
    let mut file = fs::File::open(file_dir).unwrap();
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    let mut scanner = Scanner::new(&YARA_RULES);
    let results = scanner.scan(&data).unwrap();

    let rules_hit: Vec<String> = results
        .matching_rules()
        .map(|r| r.identifier().to_string())
        .collect();

    if !rules_hit.is_empty() {
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
    }
}


//send result to consensus
pub fn send_yara(event: TelemetryEvent) {
    let client = Client::new();

    let _ = client
        .post("http://127.0.0.1:3000/consensus-check")
        .json(&event)
        .send();
}


//handle yara request
pub fn handle_yara_request(req: YaraRequest) {
    let mut event: TelemetryEvent = req.event;
    let yara_result: YaraEventResponse =
        match_yara_rule(&event.filename);

    event.analysis_result.yara_results = yara_result;
    event.yara_check = true;
    send_yara(event);
}

//Sends yara req to the ip(localhost rn) the ip sends the result back to https://<ip>/consensus-check(in src/node_roles/transport/), along with
//Needs xception handling - even though almost every everything needs xception handling :(

//send yara file check request
pub fn send_yara_search_req(event_id: u64, event: TelemetryEvent) {
    let client = Client::new();

    let req = YaraRequest {
        event_id,
        event,
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

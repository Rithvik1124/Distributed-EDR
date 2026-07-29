use std::fs;
use serde_json::{json,Value};
use std::io::Read;
//use std::io::prelude::*;
use crate::detect::{SIGMA_RULES, YARA_RULES};
use crate::telemetry::{TelemetryEvent, DetectionResult};
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};
use yara_x;
// use yaml_rust::yaml::{Hash, Yaml};
// use yaml_rust::YamlLoader;

#[warn(unused_variables)]

pub fn match_yara_rule(file_dir: &str){
    let mut file = fs::File::open(file_dir).unwrap();    
    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();
    println!("Contents:{:?}",data);
    let mut scanner = yara_x::Scanner::new(&YARA_RULES);

    let results = scanner.scan(&data).unwrap();

    // Scan some data.
    //let results = scanner.scan(contents.as_bytes()).unwrap();

    if results.matching_rules().len() == 1{
        println!("Matches");
    }
}

pub fn match_sigma_rule(event: &TelemetryEvent)-> Vec<DetectionResult>{
    let mut detected: Vec<DetectionResult> = Vec::new();
    let mut sigma_event:Event = Event::new();
    sigma_event.insert("Image",event.filename.clone());
    sigma_event.insert("CommandLine",event.comm.clone());
    for rule in SIGMA_RULES.iter() {
    

    if !rule.is_match(&sigma_event) {
        //println!("No event found match {:?}", rule);
        continue;
    }
    let mut detect:DetectionResult = DetectionResult{
       rule_id : rule.id.clone().unwrap_or_default(),
       rule_name: rule.title.to_owned(),
    };
    detected.push(detect);
}
    return detected
}
// Rule { title: "Triple Cross eBPF Rootkit Install Commands", id: Some("22236d75-d5a0-4287-bf06-c93b1770860f"), 
// name: None, related: None, taxonomy: None, status: Some(Test), description: Some("Detects default install commands of the Triple Cross eBPF rootkit based on the \"deployer.sh\" script"), 
// license: None, author: Some("Nasreddine Bencherchali (Nextron Systems)"), 
// references: Some(["https://github.com/h3xduck/TripleCross/blob/1f1c3e0958af8ad9f6ebe10ab442e75de33e91de/apps/deployer.sh"]), 
// date: Some("2022-07-05"), modified: None, logsource: Logsource { category: Some("process_creation"), product: Some("linux"), service: 
// None, definition: None }, detection: Detection { selections: {"selection": Field([FieldGroup { fields: [Field { name: "CommandLine", 
// values: [WildcardPattern([Star, Pattern(['.', '/', 't', 'a', 'r', 'g', 'e', 't', '/', 'd', 'e', 'b', 'u', 'g', '/', 'e', 'd', 'r', '-', 'a', 'g', 'e', 'n', 't']), Star])], 
// modifier: Modifier { match_all: true, fieldref: false, cased: false, exists: None, match_modifier: Some(Contains), value_transformer: None } }, 
// Field { name: "CommandLine", 
// values: [WildcardPattern([Star, Pattern(['.', '/', 't', 'a', 'r', 'g', 'e', 't', '/', 'd', 'e', 'b', 'u', 'g', '/', 'e', 'd', 'r', '-', 'a', 'g', 'e', 'n', 't']), Star])], 
// modifier: Modifier { match_all: false, fieldref: false, cased: false, exists: None, match_modifier: Some(Contains), value_transformer: None } }] }])}, 
// condition: "selection", ast: Selection("selection") }, fields: None, 
// falsepositives: Some(["Unlikely"]), level: Some(High), tags: Some(["attack.stealth", "attack.t1014"]), custom_fields: {} }
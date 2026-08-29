use std::fs;
use serde::{Serialize, Deserialize};
use std::io::Read;
use crate::node_roles::yara::YARA_RULES;
use crate::telemetry::{YaraEventResponse, YaraStatus::{YaraHit, NoRuleMatched}};
use yara_x::{Scanner, Rules};



// !!! FIX THIS BOYYY

pub fn match_yara_rule(file_dir: &str) -> YaraEventResponse{
    let mut file = fs::File::open(file_dir).unwrap();

    let mut data = Vec::new();
    file.read_to_end(&mut data).unwrap();

    let mut scanner = yara_x::Scanner::new(&YARA_RULES);

    let results = scanner.scan(&data).unwrap();
    let mut rules_hit: Vec<String> = Vec::new();

    for rule in results.non_matching_rules() {
        rules_hit.push(rule.identifier().to_string());
    }

    if rules_hit.len() >=1{
        YaraEventResponse { status: YaraHit, rule_matched: rules_hit }
    }
    else {
        YaraEventResponse { status: NoRuleMatched, rule_matched: rules_hit }
    }
}


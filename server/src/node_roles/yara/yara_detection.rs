use std::fs;
use serde::{Serialize, Deserialize};
use std::io::Read;
use crate::node_roles::yara::{YARA_RULES, yara_detection::YaraStatus::{NoRuleMatched, YaraHit}};
use yara_x::{Scanner, Rules};

#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub enum YaraStatus {
    YaraHit,
    #[default]
    NoRuleMatched,
}
#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub struct YaraEventResponse{
    pub status: YaraStatus,
    pub rule_matched: Vec<String>,
}


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


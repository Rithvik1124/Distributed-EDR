use std::fs;
use serde_json::{json,Value};
use std::io::Read;
use crate::node_roles::sigma::SIGMA_RULES;
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};


pub fn match_sigma_rule(event: &Event) {
    for rule in SIGMA_RULES.iter() {
        if rule.is_match(event) {
            println!("MATCH: {}", rule.title);
        }
        else {
            println!("No event found match {:?}", &event)
        }
    }
}



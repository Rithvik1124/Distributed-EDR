use std::fs;
use serde_json::{json,Value};
use std::io::Read;
use crate::node_roles::sigma::SIGMA_RULES;
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};

enum SigmaStatus{
    SigmaHit,
    NoRuleMatched,
}

struct SigmaEventResponse<'a> {
    status: SigmaStatus,
    rule_matched: Option<&'a Rule>,
}

pub fn match_sigma_rule(event: &Event) -> SigmaEventResponse<'_> {
    if let Some(rule) = SIGMA_RULES.iter().find(|rule| rule.is_match(event)) {
        return SigmaEventResponse {
            status: SigmaStatus::SigmaHit,
            rule_matched: Some(rule),
        };
    }

    SigmaEventResponse {
        status: SigmaStatus::NoRuleMatched,
        rule_matched: None,
    }
}
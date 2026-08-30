use crate::node_roles::sigma::SIGMA_RULES;
use crate::telemetry::{SigmaEventResponse, SigmaStatus};
use sigma_rust::{Event, Rule};



pub fn match_sigma_rule(event: &Event) -> SigmaEventResponse {
    let rule_matched: Vec<String> = SIGMA_RULES
        .iter()
        .filter(|rule| rule.is_match(event))
        .filter_map(|rule| rule.id.clone())
        .collect();

    let status = if rule_matched.is_empty() {
        SigmaStatus::NoRuleMatched
    } else {
        SigmaStatus::SigmaHit
    };

    SigmaEventResponse {
        status,
        rule_matched,
    }
}

pub fn forward_result(result: SigmaEventResponse){
    
}
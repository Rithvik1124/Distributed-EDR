use crate::node_roles::sigma::SIGMA_RULES;
use crate::telemetry::{TelemetryEvent, SigmaEventResponse, SigmaStatus,ResponseType::Sigma};
use reqwest::blocking::Client;
use sigma_rust::{Event, Rule};
use crate::node_roles::cache::*;
use crate::handlers::hash_event;


fn telemetry_to_event(te: &TelemetryEvent) -> Event {
    Event::from([
        ("event_type", te.event_type.clone()),
        ("pid", te.pid.to_string()),
        ("ppid", te.ppid.to_string()),
        ("uid", te.uid.to_string()),
        ("gid", te.gid.to_string()),
        ("filename", te.filename.clone()),
        ("comm", te.comm.clone()),
        ("dst_ip", te.dst_ip.clone()),
    ])
}

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
        response_type:Sigma,
        status,
        rule_matched,
    }
}
 
// MAKE ANOTHER FUNCTION WHICH CHECKS CACHE AND DETERMINES WHETHER THE EVENT IS REDUNDANT OR NOT TO REMOVE UNNECESSARY CHECKS< YOU MIGHT HAVE TO REMOVE TIMESTAMP FROM THE HASHING THING
pub fn check_in_cache(event: &TelemetryEvent) -> SigmaEventResponse {
    let key = hash_event(event);

    // 1. cache hit → return cached analysis
    if let Some(cached) = get_sigma_cached_event(key) {
        return cached;
    }

    // 2. compute fresh result
    let sigma_input = telemetry_to_event(event);
    let result = match_sigma_rule(&sigma_input);

    // 3. cache ONLY if no match
    if matches!(result.status, crate::telemetry::SigmaStatus::NoRuleMatched) {
        cache_sigma_event(key, &result);
    }

    result
}

// Gets telemetry from /sigma-check then runs a check after checking the cache, then 
pub fn find_sigma_result(mut result: TelemetryEvent){
    let sigma_input = telemetry_to_event(&result);
    //replace match_sigma_rule with check_in_cache
    let sigma_result = check_in_cache(&result);
    result.analysis_result.sigma_results = sigma_result;
    result.sigma_check = true;
    send_sigma_result(result);

    //then send it to the consensus server.
    
}



pub fn send_sigma_result(event: TelemetryEvent) {
    let client = Client::new();

    let _ = client
        .post("http://127.0.0.1:3000/consensus-check")
        .json(&event)
        .send();
}


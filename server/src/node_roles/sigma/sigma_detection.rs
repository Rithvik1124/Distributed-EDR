use crate::node_roles::sigma::SIGMA_RULES;
use crate::telemetry::{TelemetryEvent, SigmaEventResponse, SigmaStatus,ResponseType::Sigma};
use sigma_rust::{Event, Rule};

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
pub fn check_in_cache(){
    //yabbadabbadoo
}
// Gets telemetry from /sigma-check then runs a check after checking the cache, then 
pub fn find_sigma_result(mut result: TelemetryEvent)-> TelemetryEvent{
    let sigma_input = telemetry_to_event(&result);
    let sigma_result = match_sigma_rule(&sigma_input);

    //Add a cache checing logix

    //send this result to server
    result.analysis_result.sigma_results = sigma_result;
    result
    
}
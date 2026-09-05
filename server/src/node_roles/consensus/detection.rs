use lru::LruCache;
use crate::node_roles::{consensus::*, transport::client::ServerClient};
use crate::telemetry::BlockedIPStatus::NoIPMatched;
use crate::telemetry::FileHashStatus::NoHashMatched;
use crate::telemetry::TelemetryEvent;
#[derive(Debug, PartialEq)]
enum Decision{
    Forward(TelemetryEvent),
    Log(TelemetryEvent),
    Drop(TelemetryEvent),
}

impl Decision{
    fn execute(self, server: &ServerClient) {
        match self {
            Decision::Log(event) => {
                log_event(&event);
            }

            Decision::Drop(event) => {
                drop_redundant_event(event);
            }

            Decision::Forward(event) => {
                server.send_event(&event);

            }
        }
    }
}


fn decide(
    event: &TelemetryEvent,
    cache: &mut LruCache<u64, ()>
) -> Decision{

    let sig = hash_event(event);

    if !event.analysis_result.yara_results.rule_matched.is_empty()
        || event.analysis_result.ioc_results.file_hash_result.file_hash_status==NoHashMatched|| event.analysis_result.ioc_results.blocked_ip_result.status==NoIPMatched
    {
        return Decision::Forward(event.clone());
    }

    if cache.contains(&sig) {
        return Decision::Drop(event.clone());
    }

    cache.put(sig, ());

    if event.comm.is_empty() || event.filename.is_empty() {
        return Decision::Log(event.clone());
    }

    Decision::Forward(event.clone())
}
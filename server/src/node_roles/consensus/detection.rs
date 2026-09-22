use lru::LruCache;
use crate::node_roles::{consensus::*, transport::client::ServerClient, cache::*};
use crate::telemetry::BlockedIPStatus::IPHit;
use crate::telemetry::FileHashStatus::HashHit;
use crate::telemetry::SigmaStatus::SigmaHit;
use crate::telemetry::TelemetryEvent;
use crate::telemetry::YaraStatus::YaraHit;
#[derive(Debug, PartialEq)]
pub enum Decision{
    Forward(TelemetryEvent),
    Log(TelemetryEvent),
    Drop(TelemetryEvent),
}

impl Decision{
    pub fn execute(self, server: &ServerClient) {
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


pub fn decide(
    event: &TelemetryEvent) -> Decision{

    let sig = hash_event(event);
    //wrong
    if get_consensus_cached_event(sig).is_some() {
        println!("X287 Drop event:\n");
        return Decision::Drop(event.clone());
    }

    if event.analysis_result.yara_results.status==YaraHit || event.analysis_result.ioc_results.file_hash_result.file_hash_status==HashHit|| 
    event.analysis_result.ioc_results.blocked_ip_result.status==IPHit || event.analysis_result.sigma_results.status==SigmaHit
    {
        println!("X187 Forward event:\n");
        return Decision::Forward(event.clone());
    }

    if event.comm.is_empty() || event.filename.is_empty() {
        println!("X387 Log event:\n");
        return Decision::Log(event.clone());
    }
    println!("X487 Nothing event:\n");
    Decision::Forward(event.clone())
}
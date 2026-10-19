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
    pub async fn execute(self, server: &ServerClient) {
        println!("Ran exec from consensus/");
        match self {
            Decision::Log(event) => {
                let _ = log_event(&event);
            }
            
            Decision::Drop(event) => {
                drop_redundant_event(event);
            }
            
            Decision::Forward(event) => {
                let _ = log_event(&event);
                let _ = server.send_event(&event).await;
                println!("Sent to server {:#?}",&event);
                
            }
            
            _ => {
                println!("X587 Matching self but nothing worked.");
                
            }
        }
    }
}


pub fn decide(
    event: &TelemetryEvent) -> Decision{

    let sig = hash_event(event);
    if get_consensus_cached_event(sig).is_some() {
        return Decision::Drop(event.clone());
    }

    if event.analysis_result.yara_results.status==YaraHit || event.analysis_result.ioc_results.file_hash_result.file_hash_status==HashHit|| 
    event.analysis_result.ioc_results.blocked_ip_result.status==IPHit || event.analysis_result.sigma_results.status==SigmaHit
    {
        return Decision::Forward(event.clone());
    }



    println!("X487 Nothing event:\n");
    Decision::Drop(event.clone())
}
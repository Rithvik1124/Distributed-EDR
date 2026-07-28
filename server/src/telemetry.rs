//because using TelemetryEvent separately in both main.rs and events.rs gave error
use std::hash::{ Hash, Hasher};
use serde::{Deserialize, Serialize};

#[derive(Serialize, Deserialize, Hash, Debug)]
// struct SigmaResults{
//     rule_id: String,
//     rule_name: String,
//     rule_triggers: String,
// }
// #[derive(Serialize, Deserialize, Hash, Debug)]

// struct YaraResults{
//     rule_id: String,
//     rule_name: String,
//     rule_triggers: String,
// }
// #[derive(Serialize, Deserialize, Hash, Debug)]

// struct IOCResults{
//     rule_id: String,
//     rule_name: String,
//     rule_triggers: String,
// }
//#[derive(Serialize, Deserialize)]

pub struct DetectionResult{
    pub rule_id: String,
    pub rule_name: String,
    //pub rule_reference: String,
}

#[derive(Serialize, Deserialize,Debug, Hash)]
pub struct AnalysisResult{
    pub is_mal: bool,
    pub sigma_results: Vec<DetectionResult>,
    pub yara_results: Vec<DetectionResult>,
    pub ioc_results: Vec<DetectionResult>,
}



#[derive(Serialize, Deserialize, Debug)]
pub struct TelemetryEvent {     
    pub event_type: String,         
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,
    pub tgid: u64,
    pub comm: String,
    pub filename: String,
    pub dst_ip: String, //max 15 bytes
    pub dst_port: String, //max 5 bytes
    pub time_stamp:String,
    pub analysis_result: AnalysisResult,
}

impl Hash for TelemetryEvent {
    fn hash<H: Hasher>(&self, state: &mut H) {
        self.event_type.hash(state);
        self.filename.hash(state);
        self.dst_ip.hash(state);
        self.dst_port.hash(state);
        self.pid.hash(state);
        self.ppid.hash(state);
        self.uid.hash(state);
        self.gid.hash(state);
        self.tgid.hash(state);
        self.comm.hash(state);
    }
}

// #[derive(Serialize, Deserialize, Hash, Debug)]
// pub struct FullEvent{
//     pub telemetry: TelemetryEvent,
//     pub sigma_results: Option<AnalysisResult>,
//     pub yara_results: Option<AnalysisResult>,
//     pub ioc_results: Option<AnalysisResult>,
//     pub time_stamp: String,
// }
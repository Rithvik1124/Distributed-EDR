//because using TelemetryEvent separately in both main.rs and events.rs gave error
use std::hash::{DefaultHasher, Hash, Hasher};
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

struct DetectionResult{
    rule_id: String,
    rule_name: String,
    rule_triggers: String,
}

#[derive(Serialize, Deserialize,Debug, Hash)]
struct AnalysisResult{
    is_mal: bool,
    detection_rule:String,
    sigma_results: Vec<DetectionResult>,
    yara_results: Vec<DetectionResult>,
    ioc_results: Vec<DetectionResult>,
}



#[derive(Serialize, Deserialize, Hash, Debug)]
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

// #[derive(Serialize, Deserialize, Hash, Debug)]
// pub struct FullEvent{
//     pub telemetry: TelemetryEvent,
//     pub sigma_results: Option<AnalysisResult>,
//     pub yara_results: Option<AnalysisResult>,
//     pub ioc_results: Option<AnalysisResult>,
//     pub time_stamp: String,
// }
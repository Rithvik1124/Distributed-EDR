use crate::handlers::*;
use plain::Plain;
use std::{default, fs, hash::{ Hash, Hasher}, net::IpAddr};
use serde::{Deserialize, Serialize};
use sigma_rust::Rule;


#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub enum ResponseType{
    Sigma,
    IOC,
    Yara,
    #[default]
    DefEvent,

}

#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub enum SigmaStatus {
    SigmaHit,
    #[default]
    NoRuleMatched,
}
#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub struct SigmaEventResponse{
    pub response_type: ResponseType,
    pub status: SigmaStatus,
    pub rule_matched: Vec<String>,
}

#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub enum YaraStatus {
    YaraHit,
    #[default]
    NoRuleMatched,
}
#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub struct YaraEventResponse{
    pub response_type: ResponseType,
    pub status: YaraStatus,
    pub rule_matched: Vec<String>,
}


//Needs change

#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]

pub enum FileHashStatus {
    HashHit,
    #[default]
    NoHashMatched,
}
#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]

pub enum BlockedIPStatus{
    IPHit,
    #[default]
    NoIPMatched,
}

#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]

pub struct FileHashResponse{
    pub file_hash_status: FileHashStatus,
    pub file_hash: String,

}
#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub struct BlockedIPResponse{
    pub status: BlockedIPStatus,
    pub mal_ip: Option<IpAddr>,
}


#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]

pub struct IOCEventResponse{
    pub file_hash_result: FileHashResponse,
    pub blocked_ip_result: BlockedIPResponse,
}


#[derive(Default, Serialize, Deserialize, Hash, Debug, Clone, PartialEq)]
pub struct AnalysisResult{
    pub is_mal: bool,
    pub sigma_results: SigmaEventResponse,
    pub yara_results: YaraEventResponse,
    pub ioc_results: IOCEventResponse,
}



#[derive(Default, Serialize, Deserialize, Debug, Clone, PartialEq)]
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
    pub ioc_check: bool,
    pub yara_check: bool,
    pub sigma_check: bool,
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

#[derive(Serialize, Deserialize, Hash, Debug)]
pub struct FullEvent{
    pub telemetry: TelemetryEvent,
    pub sigma_results: Option<AnalysisResult>,
    pub yara_results: Option<AnalysisResult>,
    pub ioc_results: Option<AnalysisResult>,
    pub time_stamp: String,
}

#[repr(C)]
#[derive(Clone, Copy, Debug,)]

pub struct GenEvent {
    pub event_type: u8,
    pub pid: u32,
    pub ppid: u32,
    pub uid: u32,
    pub gid: u32,

    pub tgid: u64,

    pub comm: [u8; 16],
    pub filename: [u8; 512],

    pub dst_ip: u32,
    pub dst_port: u16,

    pub time_stamp: u64,
} 


unsafe impl Plain for GenEvent {}

impl Default for GenEvent {
    fn default() -> Self {
        unsafe { std::mem::zeroed() }
    }
}


pub fn make_event(buff_event: &GenEvent, offset_ns: i128)-> TelemetryEvent{
    let mode :String= match buff_event.event_type {
        10 => "Execve".to_string(),
        11 => "Fork".to_string(),
        12 => "Exit".to_string(),
        13 => "Execveat".to_string(),
        20 => "Unlinkat".to_string(),
        21 => "Renameat".to_string(),
        22=> "Renameat2".to_string(),
        30 => "Connect".to_string(),
        31 => "Accept".to_string(),
        32 => "Bind".to_string(),
        40 => "Mount".to_string(),
        41 => "Unmount".to_string(),
        50 => "Chown".to_string(),
        51 => "Chmod".to_string(),  
        _=> "Unknown".to_string(), 
    };
    let mut event = TelemetryEvent::default();
    let cmdline = match fs::read(format!("/proc/{}/cmdline", buff_event.pid)) {
        Ok(bytes) => convert_result_to_string(&bytes),
        Err(_) => "cmdline expired".to_string(),
    };
        event.event_type = mode;
        event.pid = buff_event.pid;
        event.ppid = buff_event.ppid;
        event.uid = buff_event.uid;
        event.gid = buff_event.gid;
        event.tgid = buff_event.tgid;
        event.dst_ip = buff_event.dst_ip.to_string();
        event.dst_port = buff_event.dst_port.to_string();
        event.comm = cmdline;
        event.pid = buff_event.pid;
        event.filename = convert_result_to_string(&buff_event.filename);
        event.time_stamp = nanosec_to_timestamp(buff_event.time_stamp, offset_ns);
        
    event
    
    
}

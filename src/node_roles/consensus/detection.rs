use std::fs;
use serde_json::{json,Value};
use std::io::Read;
//use std::io::prelude::*;
use crate::detect::{SIGMA_RULES, YARA_RULES};
use crate::telemetry::{TelemetryEvent, DetectionResult};
use sigma_rust::{Event, Rule, event_from_json, rule_from_yaml};
use yara_x;

enum Action {
    Drop,
    Log,
    Forward,
}

#[derive(PartialEq, Debug)]

pub enum FileHashStatus {
    HashHit,
    NoHashMatched,
}

pub enum BlockedIPStatus{
    IPHit,
    NoIPMatched,
}

fn decide(event: &TelemetryEvent, cache: &mut LruCache) -> Action {

    let sig = hash(event);

    // 1. Strong signals always forward
    if !event.analysis_result.yara_results.is_empty()
        || !event.analysis_result.ioc_results.is_empty()
    {
        return Forward;
    }

    // 2. Redundancy check
    if cache.contains(&sig) {
        return Drop;
    }

    cache.insert(sig);

    // 3. Anomaly / novelty checks
    let anomalous =
        event.comm.is_empty()
        || event.filename.is_empty()
        || event.event_type == "Execveat";

    if anomalous {
        return Forward;
    }

    // 4. Default noise suppression
    Drop
}
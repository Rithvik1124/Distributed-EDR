use std::collections::HashSet;

/// Unified detection output from all engines
#[derive(Debug, Clone)]
pub enum Signal {
    Sigma { rule_id: String },
    IOC { kind: String, value: String },
    Yara { rule: String },
}

/// Final decision from consensus layer
#[derive(Debug, PartialEq)]
pub enum Decision {
    Forward,
    ForwardLowPriority,
    Drop,
}

/// Dedup key (prevents spam / replay storms)
fn event_signature(pid: u32, filename: &str, event_type: &str) -> String {
    format!("{pid}:{filename}:{event_type}")
}

/// Consensus engine state
pub struct ConsensusEngine {
    /// used for deduplication
    seen: HashSet<String>,
    /// how many recent events to keep (simple bounded memory)
    max_cache: usize,
}

impl ConsensusEngine {
    pub fn new(max_cache: usize) -> Self {
        Self {
            seen: HashSet::new(),
            max_cache,
        }
    }

    /// MAIN CONSENSUS FUNCTION
    pub fn decide(
        &mut self,
        pid: u32,
        filename: &str,
        event_type: &str,
        signals: Vec<Signal>,
    ) -> Decision {

        // -------------------------
        // 1. Deduplication layer
        // -------------------------
        let sig = event_signature(pid, filename, event_type);

        if self.seen.contains(&sig) {
            return Decision::Drop;
        }

        self.seen.insert(sig.clone());

        // naive bounded cleanup
        if self.seen.len() > self.max_cache {
            self.seen.clear();
        }

        // -------------------------
        // 2. Signal classification
        // -------------------------
        let mut has_ioc = false;
        let mut has_yara = false;
        let mut has_sigma = false;

        for s in &signals {
            match s {
                Signal::IOC { .. } => has_ioc = true,
                Signal::Yara { .. } => has_yara = true,
                Signal::Sigma { .. } => has_sigma = true,
            }
        }

        // -------------------------
        // 3. Decision rules (IMPORTANT PART)
        // -------------------------

        // RULE 1: strongest evidence wins immediately
        if has_ioc || has_yara {
            return Decision::Forward;
        }

        // RULE 2: only behavioral signals
        if has_sigma {
            return Decision::ForwardLowPriority;
        }

        // RULE 3: nothing meaningful
        Decision::Drop
    }
}
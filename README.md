[![Ask DeepWiki](https://deepwiki.com/badge.svg)](https://deepwiki.com/Rithvik1124/Distributed-EDR)
# Distributed EDR (Endpoint Detection & Response)

## Overview of what the project is meant to be:

This project is a **distributed Endpoint Detection and Response (EDR) system** designed to collect, analyze, and act on endpoint telemetry using a modular, multi-layer detection pipeline.

It focuses on building a lightweight agent that runs on endpoints, performs local detection using multiple rule engines, and coordinates decision-making through a consensus-based architecture to reduce noise and improve signal quality.

**The architecture is intentionally exploratory, focusing on validating system behavior under dynamic workloads rather than enforcing a fixed production-grade design.**

---

## Core Idea

Traditional EDR systems rely heavily on centralized analysis, which leads to:

- High server-side load
- Excessive telemetry noise
- Slow response to endpoint-level events

This project explores a **distributed model**, where:

- Endpoints perform local detection
- Multiple detection engines independently analyze events
- A consensus layer filters and decides what is meaningful
- Only relevant events are forwarded upstream
- Yes, sounds like a huge red flag, good way to get into systems and distributed architecture

---

## Architecture

The system is split into three main layers:

### 1. Telemetry Layer (src/main.rs, src/node_roles/telemetry/*, bpf/)

Responsible for collecting raw endpoint events such as:

- Process execution (`execve` events)
- File access and file creation
- Network activity
- System-level behavioral signals

This is the raw data source for all downstream analysis.

---

### 2. Detection Layer (src/node_roles/ioc/\*, src/node_roles/sigma/\* , src/node_roles/yara/\*)

Each event is processed through multiple independent detection engines:

#### IOC Engine
- Matches against known malicious indicators
- File hashes (SHA256)
- IP blocklists (e.g., threat intelligence feeds)
- Known suspicious artifacts

#### Sigma Engine
- Rule-based behavioral detection
- Detects patterns in process execution and system behavior

#### YARA Engine
- File-level pattern matching
- Used for malware and static analysis detection

Each engine outputs structured detection results attached to the telemetry event.

---

### 3. Consensus Layer (src/node_roles/consensus/*)

The consensus module is responsible for **final decision making**.

It does not perform detection itself. Instead, it:

- Aggregates outputs from IOC, Sigma, and YARA engines
- Removes redundant or duplicate events using LRU caching
- Applies deterministic decision rules

Final actions:

- **Forward** → send event to central server
- **Log** → store locally for audit or debugging
- **Drop** → discard redundant or low-value events

---

## Decision Model 

The system uses a deterministic rule-based model:

- Strong signals (IOC / YARA hits) → Forward immediately
- Behavioral signals (Sigma only) → Conditional forward or log
- Repeated events → Drop (deduplicated via LRU cache)
- Empty or incomplete telemetry → Log or Drop

No machine learning or probabilistic scoring is used.

---

## Design Goals

- **Low overhead**: minimal CPU usage on endpoints
- **Modular detection engines**: IOC, Sigma, YARA are independent
- **Deterministic behavior**: same input always produces same output
- **Noise reduction**: deduplication and filtering at the edge
- **Scalable architecture**: reduces server-side telemetry load

---

## Key Components

- Rust-based agent for userspace processing
- eBPF-based telemetry collection (kernel-level signals)
- LRU-based deduplication cache
- Rule-driven detection engines
- Consensus-based decision layer

---

## Current Status

The project is under active development and currently includes:

- Telemetry collection pipeline
- IOC detection (file hashes + IP blocklists)
- Sigma rule engine integration
- YARA scanning integration (in progress)
- Consensus decision engine (early stage)
- **CoordinationFabric** (in development): node cluster scheduling and coordination layer  
  https://github.com/Rithvik1124/CoordinationFabric
---

## Future Work

- Stronger consensus logic (multi-signal weighting)
- Dynamic role-based node assignment
- Secure event signing and integrity verification
- Performance optimizations for high-throughput environments
- Distributed coordination between endpoints

---

Would love to hear any advice to how to improve the project!


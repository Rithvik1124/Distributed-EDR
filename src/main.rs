mod telemetry;
mod handlers;
use core::time::Duration;
use std::{ mem::MaybeUninit, 
        time::{SystemTime, UNIX_EPOCH}, 
        sync::{atomic::{AtomicBool, Ordering}, Arc}};
use libbpf_rs::{RingBufferBuilder, skel::SkelBuilder as _, 
                skel::OpenSkel as _, MapCore,
                MapFlags, skel::Skel};
use structopt::StructOpt;
use trial::*;
use anyhow::{anyhow, bail, Context, Result};
use reqwest::Client;
use serde::{Deserialize, Serialize};
use tokio::sync::mpsc;
use libc::{clock_gettime, timespec, CLOCK_MONOTONIC};
use crate::telemetry::*;
// use crate::handlers::*;

mod trial {
    include!("trial.skel.rs");
}

// Timestamp doesnt work
#[derive(Debug, StructOpt)]
struct Command {
    /// verbose output
    #[structopt(long, short)]
    verbose: bool,
    /// glibc path
    #[structopt(long, short, default_value = "/lib/x86_64-linux-gnu/libc.so.6")]
    glibc: String,
    #[structopt(long, short)]
    /// pid to observe
    pid: Option<i32>,
    
}

fn bump_memlock_rlimit() -> Result<()> {
    let rlimit = libc::rlimit {
        rlim_cur: libc::RLIM_INFINITY,
        rlim_max: libc::RLIM_INFINITY,
    };

    let ret = unsafe { libc::setrlimit(libc::RLIMIT_MEMLOCK, &rlimit) };

    if ret != 0 {
        bail!("Failed to increase rlimit: {}", std::io::Error::last_os_error());
    }

    Ok(())
}
 


fn monotonic_to_unix_offset_ns() -> i128 {
    let unix_ns = SystemTime::now()
        .duration_since(UNIX_EPOCH)
        .unwrap()
        .as_nanos() as i128;

    let mut ts = timespec {
        tv_sec: 0,
        tv_nsec: 0,
    };

    unsafe {
        clock_gettime(CLOCK_MONOTONIC, &mut ts);
    }

    let mono_ns =
        ts.tv_sec as i128 * 1_000_000_000 +
        ts.tv_nsec as i128;

    unix_ns - mono_ns
}


#[tokio::main]
async fn main() -> Result<()> {
    // println!("Proc Event Stuff:\n");
    println!("My PID: {}",std::process::id() );
    let opts = Command::from_args();

    let unix_offset_ns = monotonic_to_unix_offset_ns();

    let client = Client::new();

    let (tx, mut rx) = mpsc::channel::<TelemetryEvent>(1024); // 1024 is the channel capacity, both want EVent here

    let http_client = client.clone();
    tokio::spawn(async move {
        while let Some(some_event) = rx.recv().await {
            if let Err(e) = http_client
                .post("http://127.0.0.1:3000/publish")
                .json(&some_event)
                .send()
                .await
            {
                eprintln!("Failed to send telemetry: {}", e);
            }
        }
    });

    let mut skel_builder = TrialSkelBuilder::default();

    if opts.verbose {
        skel_builder.obj_builder.debug(true);
    }

    bump_memlock_rlimit()?;
    let mut open_object = MaybeUninit::uninit();
    let open_skel = skel_builder.open(&mut open_object)?;

    // Sending userspace - ./target/debug/edr-agent PID to kernspace 'agent_tgid'
    let mut skel = open_skel.load()?;
    let key: u32 = 0;
    let value: u32 = std::process::id();
    skel.maps
    .agent_pid_map
    .update(&key.to_ne_bytes(), &value.to_ne_bytes(), MapFlags::ANY)?;
    skel.attach()?;
    let mut rb  = RingBufferBuilder::new();
        

    let tx = tx.clone();
    rb.add(&skel.maps.rb, move |data| {
    let mut event = GenEvent::default();
   
    if plain::copy_from_bytes(&mut event, data).is_err() {

        return 0;
    }

    let telemetry = make_event(&event, unix_offset_ns);

    if let Err(e) = tx.try_send(telemetry) {
        eprintln!("Telemetry queue full, dropping event: {}", e);
    }

    0
})?;
    let rb = rb.build()?;
    

    let running = Arc::new(AtomicBool::new(true));
    let r = running.clone();
    ctrlc::set_handler(move || {
        r.store(false, Ordering::SeqCst);
    })?;

    while running.load(Ordering::SeqCst) {
        rb.poll(Duration::from_millis(100))?;
    }


    Ok(())
}
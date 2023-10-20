use std::io::{prelude::*, stdin, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;
use std::time::Duration;

use anyhow::Context;
use clap::Parser;
use ktr_agent::controller::{Controller, ControllerConfig, ControllerResult, TraceId};
use ktr_lib::peeringdb::PeeringDbManager;
use ktr_lib::trace::TraceConfig;
use ktr_lib::traceroute_net::{interface_from_name, TracerouteChannel};
use serde::{Deserialize, Serialize};

static TRACE_CONFIG: TraceConfig = TraceConfig {
    max_hops: 64,
    wait_time_per_hop: Duration::from_millis(150),
    retry_frequency: Duration::from_secs(1),
    destination_timeout: Duration::from_secs(3),
    completion_timeout: Duration::from_secs(4),
    asn_cache_size: 8192,
};

struct InputLine(String);

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(transparent)]
struct CommandId(usize);

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
enum Command {
    #[serde(rename_all = "camelCase")]
    StartTrace { command_id: CommandId, ip: IpAddr },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
enum Output<'a> {
    StartedTrace {
        command_id: CommandId,
        trace_id: TraceId,
    },
    /// Pass through to a `ControllerResult`.
    #[serde(untagged)]
    ControllerResult(ControllerResult<'a>),
}

fn controller_thread(config: ControllerConfig, rx: Receiver<InputLine>) -> ! {
    let mut controller = Controller::new(config);

    fn output(output: &Output) {
        println!("{}", serde_json::to_string(&output).unwrap());
    }

    loop {
        match rx.try_recv() {
            Ok(line) => {
                let command = &mut serde_json::Deserializer::from_str(&line.0);
                let command = match serde_path_to_error::deserialize(command) {
                    Ok(command) => command,
                    Err(error) => {
                        eprintln!("Failed to parse command: {}", error);
                        continue;
                    }
                };
                match command {
                    Command::StartTrace { command_id, ip } => {
                        let trace_id = controller.start_trace(ip);
                        output(&Output::StartedTrace {
                            command_id,
                            trace_id,
                        });
                    }
                }
            }
            Err(mpsc::TryRecvError::Empty) => {}
            Err(mpsc::TryRecvError::Disconnected) => panic!("Main thread disconnected channel"),
        };

        if let Some(result) = controller.try_next() {
            output(&Output::ControllerResult(result));
        }
    }
}

#[derive(Parser, Debug)]
#[command(author, version)]
struct Args {
    /// Name of the network interface to use for traceroute
    #[arg(short = 'i', long)]
    interface_name: String,
    /// Path to the local PeeringDB SQLite database
    #[arg(short = 'd', long)]
    peeringdb_path: PathBuf,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let interface = interface_from_name(&args.interface_name)
        .with_context(|| format!("Interface {} does not exist", args.interface_name))?;
    let traceroute_channel = TracerouteChannel::from_interface(interface)
        .context("Failed to initialize traceroute networking (do you need to use sudo?)")?;
    let peeringdb = PeeringDbManager::connect(args.peeringdb_path)
        .context("Failed to open PeeringDB database")?;

    let config = ControllerConfig {
        traceroute_channel,
        peeringdb,
        trace_config: &TRACE_CONFIG,
    };

    let (tx, rx) = mpsc::channel::<InputLine>();
    let controller = thread::spawn(|| controller_thread(config, rx));

    for line in BufReader::new(stdin()).lines() {
        tx.send(InputLine(line?))?;
    }

    controller.join().expect("Joining thread failed");
    Ok(())
}

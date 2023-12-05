use std::io::{prelude::*, stdin, BufReader};
use std::net::IpAddr;
use std::path::PathBuf;
use std::sync::mpsc::{self, Receiver};
use std::thread;

use anyhow::Context;
use clap::Parser;
use ktr_agent::controller::{Controller, ControllerConfig, ControllerResult, TraceId};
use ktr_lib::peeringdb::{Network, PeeringDbManager};
use ktr_lib::trace::TraceConfig;
use ktr_lib::traceroute_net::{interface_from_name, TracerouteChannel};
use ktr_lib::whois_net::Asn;
use serde::{Deserialize, Serialize};

struct InputLine(String);

#[derive(Debug, Copy, Clone, Serialize, Deserialize)]
#[repr(transparent)]
struct CommandId(usize);

#[derive(Debug, Deserialize, Serialize)]
#[serde(tag = "kind")]
enum Command {
    #[serde(rename_all = "camelCase")]
    StartTrace { command_id: CommandId, ip: IpAddr },
    #[serde(rename_all = "camelCase")]
    LookupAsn { command_id: CommandId, asn: Asn },
}

#[derive(Debug, Serialize)]
#[serde(tag = "kind")]
enum Output<'a> {
    #[serde(rename_all = "camelCase")]
    StartedTrace {
        command_id: CommandId,
        trace_id: TraceId,
    },
    #[serde(rename_all = "camelCase")]
    LookupAsnResult {
        command_id: CommandId,
        network: Option<Network>,
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
                        eprintln!("  > {}", line.0);
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
                    Command::LookupAsn { command_id, asn } => {
                        let network = controller.lookup_asn(asn);
                        output(&Output::LookupAsnResult {
                            command_id,
                            network,
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
    /// Disable IPv6 support (IPv6 addresses will be soft, non-crashing errors)
    #[arg(long, default_value_t = false)]
    disable_ipv6: bool,
    /// The maximum number of hops
    #[arg(long, default_value_t = 64)]
    max_hops: u8,
    /// The maximum number of pending hops in a row before waiting for one to complete
    #[arg(long, default_value_t = 10)]
    max_sequential_pending: u8,
    /// How long to wait for a response from each hop before moving to the next
    #[arg(long, default_value = "150ms")]
    wait_time_per_hop: humantime::Duration,
    /// After all initial pings are sent, how long between retries
    #[arg(long, default_value = "1s")]
    retry_frequency: humantime::Duration,
    /// How long to wait to reach the destination before giving up
    #[arg(long, default_value = "500ms")]
    destination_timeout: humantime::Duration,
    /// After reaching the destination, how long to wait for a response from every
    /// hop before giving up
    #[arg(long, default_value = "3s")]
    completion_timeout: humantime::Duration,
    /// Size of the cache for IP to ASN WHOIS lookups
    #[arg(long, default_value_t = 8192)]
    asn_cache_size: usize,
}

fn main() -> anyhow::Result<()> {
    let args = Args::parse();

    let trace_config = TraceConfig {
        max_hops: args.max_hops,
        max_sequential_pending: args.max_sequential_pending,
        wait_time_per_hop: args.wait_time_per_hop.into(),
        retry_frequency: args.retry_frequency.into(),
        destination_timeout: args.destination_timeout.into(),
        completion_timeout: args.completion_timeout.into(),
        asn_cache_size: args.asn_cache_size,
    };
    let trace_config = Box::leak(Box::new(trace_config));

    let interface = interface_from_name(&args.interface_name)
        .with_context(|| format!("Interface {} does not exist", args.interface_name))?;
    let traceroute_channel = TracerouteChannel::from_interface(interface, !args.disable_ipv6)
        .context("Failed to initialize traceroute networking (do you need to use sudo?)")?;
    let peeringdb = PeeringDbManager::connect(args.peeringdb_path)
        .context("Failed to open PeeringDB database")?;

    let config = ControllerConfig {
        traceroute_channel,
        peeringdb,
        trace_config,
    };

    let (tx, rx) = mpsc::channel::<InputLine>();
    let controller = thread::spawn(|| controller_thread(config, rx));

    for line in BufReader::new(stdin()).lines() {
        tx.send(InputLine(line?))?;
    }

    controller.join().expect("Joining thread failed");
    Ok(())
}

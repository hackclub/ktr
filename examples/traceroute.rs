use std::net::ToSocketAddrs;
use std::time::Duration;

use ktr::peeringdb::PeeringDbManager;
use ktr::trace::{Hop, Trace, TraceConfig};
use ktr::traceroute_net::TracerouteChannel;
use pnet::datalink::{self, NetworkInterface};

fn main() {
    let usage = "usage: traceroute <interface> <peeringdb_path> <host_or_ip>";
    let interface_name = std::env::args().nth(1).expect(usage);
    let peeringdb_path = std::env::args().nth(2).expect(usage);
    let host_or_ip = std::env::args().nth(3).expect(usage);
    let ip = (host_or_ip.clone(), 80)
        .to_socket_addrs()
        .expect("failed to dns resolve host")
        .next()
        .expect("no dns results")
        .ip();

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .expect("interface not found");

    let mut traceroute_channel = TracerouteChannel::from_interface(interface).unwrap();
    let peeringdb = PeeringDbManager::connect(peeringdb_path).unwrap();

    let config = TraceConfig {
        max_hops: 20,
        wait_time_per_hop: Duration::from_millis(200),
        retry_frequency: Duration::from_secs(1),
        destination_timeout: Duration::from_secs(3),
        completion_timeout: Duration::from_secs(4),
    };
    let mut trace = Trace::new(ip, &config);

    loop {
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        println!("tracing {} ({})...", host_or_ip, ip);
        for (i, hop) in trace.hops().iter().enumerate() {
            let hop_text = match hop {
                Hop::Pending(_) => "loading...".to_string(),
                Hop::FindingAsn(ip, _) => format!("{} (loading asn...)", ip),
                Hop::Done { ip, network } => format!(
                    "{} ({})",
                    ip,
                    match network {
                        Some((asn, Some(network))) => format!("{:?}, {}", asn, network.name),
                        Some((asn, None)) => format!("{:?}", asn),
                        None => "AS???".to_string(),
                    }
                ),
                Hop::Unused => unreachable!(),
            };
            println!("{:3}. {}", i + 1, hop_text);
        }

        if let Some(reason) = trace.poll(&mut traceroute_channel, &peeringdb).unwrap() {
            println!("terminated: {:?}", reason);
            break;
        }
    }
}

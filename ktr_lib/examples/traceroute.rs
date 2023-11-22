use std::net::ToSocketAddrs;
use std::time::Duration;

use ktr_lib::peeringdb::PeeringDbManager;
use ktr_lib::trace::{DidUpdate, Hop, NetworkInfo, Trace, TraceConfig};
use ktr_lib::traceroute_net::{interface_from_name, TracerouteChannel};

fn main() {
    let usage = "usage: traceroute <interface> <peeringdb_path> <enable_ipv6> <host_or_ip>";
    let interface_name = std::env::args().nth(1).expect(usage);
    let peeringdb_path = std::env::args().nth(2).expect(usage);
    let enable_ipv6 = std::env::args().nth(3).expect(usage) == "true";
    let host_or_ip = std::env::args().nth(4).expect(usage);
    let ip = (host_or_ip.clone(), 80)
        .to_socket_addrs()
        .expect("failed to dns resolve host")
        .next()
        .expect("no dns results")
        .ip();

    let interface = interface_from_name(&interface_name).expect("interface not found");
    let mut traceroute_channel = TracerouteChannel::from_interface(interface, enable_ipv6).unwrap();
    let peeringdb = PeeringDbManager::connect(peeringdb_path).unwrap();

    let config = TraceConfig {
        max_hops: 32,
        max_sequential_pending: 10,
        wait_time_per_hop: Duration::from_millis(200),
        retry_frequency: Duration::from_secs(1),
        destination_timeout: Duration::from_secs(3),
        completion_timeout: Duration::from_secs(4),
        asn_cache_size: 10,
    };
    let mut trace = Trace::new(ip, &config);

    loop {
        let (did_update, termination_reason) =
            trace.poll(&mut traceroute_channel, &peeringdb).unwrap();

        if did_update == DidUpdate::Yes {
            print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
            println!("tracing {} ({})...", host_or_ip, ip);
            for (i, hop) in trace.hops().iter().enumerate() {
                let hop_text = match hop {
                    Hop::Pending { .. } => "loading...".to_string(),
                    Hop::FindingAsn { ip, .. } => format!("{} (loading asn...)", ip),
                    Hop::Done {
                        ip,
                        network_info,
                        hostname,
                        ..
                    } => format!(
                        "{} ({})",
                        hostname.as_ref().unwrap_or(&ip.to_string()),
                        match network_info {
                            Some(NetworkInfo {
                                asn,
                                network: Some(network),
                            }) => format!("{:?}, {}", asn, network.name),
                            Some(NetworkInfo { asn, network: None }) => format!("{:?}", asn),
                            None => "AS???".to_string(),
                        }
                    ),
                    Hop::Unused => unreachable!(),
                };
                println!("{:3}. {}", i + 1, hop_text);
            }
        }

        if let Some(termination_reason) = termination_reason {
            println!("terminated: {:?}", termination_reason);
            break;
        }
    }
}

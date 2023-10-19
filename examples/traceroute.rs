use std::time::Duration;

use ktr::trace::{Trace, TraceConfig};
use ktr::traceroute_net::TracerouteChannel;
use pnet::datalink::{self, NetworkInterface};

fn main() {
    let usage = "usage: traceroute <ip> <interface>";
    let ip = std::env::args().nth(1).expect(usage).parse().unwrap();
    let interface_name = std::env::args().nth(2).expect(usage);

    let interfaces = datalink::interfaces();
    let interface = interfaces
        .into_iter()
        .filter(|iface: &NetworkInterface| iface.name == interface_name)
        .next()
        .unwrap();

    let mut traceroute_channel = TracerouteChannel::from_interface(interface).unwrap();
    let config = TraceConfig {
        max_hops: 20,
        wait_time_per_hop: Duration::from_millis(200),
        retry_frequency: Duration::from_secs(1),
        destination_timeout: Duration::from_secs(3),
        completion_timeout: Duration::from_secs(2),
    };
    let mut trace = Trace::new(ip, &config);

    loop {
        print!("{esc}[2J{esc}[1;1H", esc = 27 as char);
        println!("tracing {}...", ip);
        for (i, hop) in trace.hops().iter().enumerate() {
            println!("{:3}. {:?}", i + 1, hop);
        }

        if let Some(reason) = trace.poll(&mut traceroute_channel).unwrap() {
            println!("terminated: {:?}", reason);
            break;
        }
    }
}

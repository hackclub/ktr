use std::time::Instant;

use ktr::whois_net::{AsnFinder, AsnResult};

fn main() {
    let usage = "usage: whois <ip>";
    let ip = std::env::args().nth(1).expect(usage).parse().unwrap();

    let start = Instant::now();
    let mut finder = AsnFinder::lookup(ip).unwrap();
    loop {
        match finder.poll().unwrap() {
            AsnResult::Found(asn) => {
                println!("found: {:?} after {:?}", asn, start.elapsed());
                break;
            }
            AsnResult::NotFound => {
                println!("didn't find any results after {:?}", start.elapsed());
                break;
            }
            AsnResult::Pending => {}
        }
    }
}

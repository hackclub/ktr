use ktr::{peeringdb::PeeringDbManager, whois_net::Asn};

fn main() {
    let usage = "usage: peeringdb <db_path> <asn>";
    let db_path = std::env::args().nth(1).expect(usage);
    let asn = Asn(std::env::args().nth(2).expect(usage).parse().expect(usage));

    let peeringdb = PeeringDbManager::connect(db_path).unwrap();
    let network = peeringdb.network_by_asn(asn).unwrap();
    println!("{:?}", network);
}

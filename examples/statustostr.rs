use pcap::*;

fn main() {
    let str = pcap_statustostr(-2);
    println!("{:?}", str)
}

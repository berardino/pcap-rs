use pcap::*;

fn main() {
    let str = pcap_strerror(1);
    println!("{:?}", str)
}

use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    println!("Device {}", name);
}

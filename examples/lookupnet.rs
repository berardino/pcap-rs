use pcap::*;

fn main() {
    match pcap_lookupnet("wlp2s0") {
        Ok(device) => {
            println!("{:#?}", device)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

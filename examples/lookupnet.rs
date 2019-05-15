use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_lookupnet(&name) {
        Ok(device) => {
            println!("{:#?}", device)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

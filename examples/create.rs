use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_create(&name) {
        Ok(handle) => {
            println!("{:#?}", handle);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

use pcap::*;

fn main() {
    match pcap_open_live("wlp2s0", 100, 0, 1000) {
        Ok(handle) => {
            println!("{:#?}", handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

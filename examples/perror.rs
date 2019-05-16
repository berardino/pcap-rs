use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 100, 0, 1000) {
        Ok(handle) => {
            let err = pcap_perror(&handle, "rust");
            println!("{:?}", err);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

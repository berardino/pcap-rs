use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_create(&name) {
        Ok(handle) => {
            let res = pcap_list_tstamp_types(&handle).unwrap();
            println!("{:#?}",res);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

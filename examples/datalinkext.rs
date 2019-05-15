use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 100, 0, 1000) {
        Ok(handle) => {
            let datalink = pcap_datalink_ext(&handle);
            let name = pcap_datalink_val_to_name(datalink).unwrap();
            let val = pcap_datalink_name_to_val(&name);
            let description = pcap_datalink_val_to_description(datalink).unwrap();
            println!("Datalink: {}, Name: {}, Val: {}, Description: {}",
                     datalink,
                     name,
                     val,
                     description);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

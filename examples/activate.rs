use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 100, 0, 1000) {
        Ok(handle) => {
            let activate_res = pcap_activate(&handle);
            println!("{:#?}, activate : {}", handle, activate_res);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

use pcap::*;

fn callback(capture: &PacketCapture) {
    println!("{:#?}", capture);
}

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 100, 0, 1000) {
        Ok(handle) => {
            pcap_loop(&handle, 10, callback);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

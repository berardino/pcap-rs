use pcap::*;

fn callback(capture: &PacketCapture) {
    println!("{:#?}", capture);
}

fn main() {
    match pcap_open_live("lo", 100, 0, 1000) {
        Ok(handle) => {
            pcap_dispatch(&handle, 10, callback);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

use pcap::*;

fn callback(capture: &PacketCapture) {
    println!("{:#?}", capture);
}

fn main() {
    match pcap_open_live("wlp2s0", 100, 0, 1000) {
        Ok(handle) => {
            pcap_loop(&handle, 10, callback);
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

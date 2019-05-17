use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 100, 0, 1000) {
        Ok(handle) => {
            let dump_handle = pcap_dump_open(&handle, "capture.pcap").unwrap();
            println!("{:#?}", dump_handle);
            pcap_loop(&handle, 100, |capture| {
                pcap_dump(&dump_handle, capture);
            });
            pcap_dump_close(&dump_handle);
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

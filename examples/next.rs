use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 1000, 1, 1000) {
        Ok(handle) => {
            for _ in 0..10 {
                let packet = pcap_next(&handle);
                packet.iter().for_each(|p| {
                    println!("{:#?}", p)
                });
                pcap_close(&handle)
            }
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

use pcap::*;

fn main() {
    match pcap_open_live("wlp2s0", 1000, 1, 1000) {
        Ok(handle) => {
            for _ in 0..10 {
                let packet = pcap_next(&handle);
                packet.iter().for_each(|p| {
                    println!("{:#?}", p)
                });
            }
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

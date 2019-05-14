use pcap::*;

fn main() {
    match pcap_open_live("wlp2s0", 1000, 1, 1000) {
        Ok(handle) => {
            while let res = pcap_next_ex(&handle) {
                match res {
                    Ok(packet) => {
                        println!("{:#?}", packet)
                    }
                    Err(err) => {
                        println!("{}", err)
                    }
                }
            }
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

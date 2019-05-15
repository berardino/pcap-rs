use pcap::*;

fn main() {
    let name = pcap_lookupdev().unwrap();
    match pcap_open_live(&name, 1000, 1, 1000) {
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
            pcap_close(&handle)
        }
        Err(err) => {
            println!("{}", err)
        }
    }
}

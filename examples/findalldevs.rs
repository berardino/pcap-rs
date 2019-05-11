use pcap::*;

fn main() {
    match pcap_findalldevs() {
        Ok(devices) => {
            devices.iter().for_each(|device| {
                println!("{:#?}", device)
            });
        }
        Err(err) => {
            panic!("{:?}", err);
        }
    }
}

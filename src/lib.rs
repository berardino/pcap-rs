use core::mem;
use std::ffi::CStr;
use std::ffi::CString;
use std::os::raw::c_char;
use std::ptr;

use libc;
use nix::sys::socket::Ipv4Addr;
use nix::sys::socket::SockAddr;

use self::Error::*;

mod raw;

#[derive(Debug)]
pub struct DeviceAddress {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

#[derive(Debug)]
pub struct NetworkAddress {
    pub addr: SockAddr,
    pub netmask: Option<SockAddr>,
    pub broadaddr: Option<SockAddr>,
    pub dstaddr: Option<SockAddr>,
}

#[derive(Debug)]
pub struct NetworkDevice {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<NetworkAddress>,
    pub flags: u32,
}

#[derive(Debug, PartialEq)]
pub enum Error {
    MalformedError(std::str::Utf8Error),
    PcapError(String),
}

fn to_string(ptr: *const ::std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() })
    }
}

unsafe fn parse_pcap_addr_t(addrs: *const raw::pcap_addr_t) -> Vec<NetworkAddress> {
    let mut addresses = Vec::new();
    let mut it = addrs;
    while !it.is_null() {
        let curr_addr = *it;
        SockAddr::from_libc_sockaddr(curr_addr.addr).map(|addr| {
            addresses.push(NetworkAddress {
                addr: addr,
                netmask: SockAddr::from_libc_sockaddr(curr_addr.netmask),
                broadaddr: SockAddr::from_libc_sockaddr(curr_addr.broadaddr),
                dstaddr: SockAddr::from_libc_sockaddr(curr_addr.dstaddr),
            })
        });
        it = curr_addr.next;
    }
    addresses
}

// DEPRECATED
pub fn pcap_lookupdev() -> Option<String> {
    unsafe {
        let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
        let ptr = errbuf.as_mut_ptr();
        let name = raw::pcap_lookupdev(ptr);
        to_string(name)
    }
}

pub fn pcap_lookupnet(
    name: &str
) -> Result<DeviceAddress, String> {
    let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
    let err_ptr = errbuf.as_mut_ptr();
    let mut netp: raw::bpf_u_int32 = 0;
    let mut maskp: raw::bpf_u_int32 = 0;
    let name_c = CString::new(name).unwrap();
    unsafe {
        if raw::pcap_lookupnet(name_c.as_ptr(), &mut netp, &mut maskp, err_ptr) == 0 {
            let netp_ptr: *const libc::in_addr = mem::transmute(&netp);
            let maskp_ptr: *const libc::in_addr = mem::transmute(&maskp);
            Ok(DeviceAddress {
                ip: Ipv4Addr(*netp_ptr),
                netmask: Ipv4Addr(*maskp_ptr),
            })
        } else {
            Err(to_string(err_ptr).unwrap())
        }
    }
}

/**

pub fn pcap_create(
    arg1: *const ::std::os::raw::c_char,
    arg2: *mut ::std::os::raw::c_char,
) -> *mut pcap_t {}

pub fn pcap_set_snaplen(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_promisc(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_can_set_rfmon(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_set_rfmon(arg1: *mut pcap_t, arg2: ::std::os::raw::c_int) -> ::std::os::raw::c_int {}

pub fn pcap_set_timeout(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_tstamp_type(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_immediate_mode(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_buffer_size(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_tstamp_precision(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_get_tstamp_precision(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_activate(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_list_tstamp_types(
    arg1: *mut pcap_t,
    arg2: *mut *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_free_tstamp_types(arg1: *mut ::std::os::raw::c_int) {}

pub fn pcap_tstamp_type_name_to_val(
    arg1: *const ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_tstamp_type_val_to_name(
    arg1: ::std::os::raw::c_int,
) -> *const ::std::os::raw::c_char {}

pub fn pcap_tstamp_type_val_to_description(
    arg1: ::std::os::raw::c_int,
) -> *const ::std::os::raw::c_char {}

pub fn pcap_open_live(
    arg1: *const ::std::os::raw::c_char,
    arg2: ::std::os::raw::c_int,
    arg3: ::std::os::raw::c_int,
    arg4: ::std::os::raw::c_int,
    arg5: *mut ::std::os::raw::c_char,
) -> *mut pcap_t {}

pub fn pcap_open_dead(arg1: ::std::os::raw::c_int, arg2: ::std::os::raw::c_int) -> *mut pcap_t {}

pub fn pcap_open_dead_with_tstamp_precision(
    arg1: ::std::os::raw::c_int,
    arg2: ::std::os::raw::c_int,
    arg3: u_int,
) -> *mut pcap_t {}

pub fn pcap_open_offline_with_tstamp_precision(
    arg1: *const ::std::os::raw::c_char,
    arg2: u_int,
    arg3: *mut ::std::os::raw::c_char,
) -> *mut pcap_t {}

pub fn pcap_open_offline(
    arg1: *const ::std::os::raw::c_char,
    arg2: *mut ::std::os::raw::c_char,
) -> *mut pcap_t {}

pub fn pcap_fopen_offline_with_tstamp_precision(
    arg1: *mut FILE,
    arg2: u_int,
    arg3: *mut ::std::os::raw::c_char,
) -> *mut pcap_t {}

pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut ::std::os::raw::c_char) -> *mut pcap_t {}

pub fn pcap_close(arg1: *mut pcap_t) {}

pub fn pcap_loop(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
    arg3: pcap_handler,
    arg4: *mut u_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_dispatch(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
    arg3: pcap_handler,
    arg4: *mut u_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_next(arg1: *mut pcap_t, arg2: *mut pcap_pkthdr) -> *const u_char {}

pub fn pcap_next_ex(
    arg1: *mut pcap_t,
    arg2: *mut *mut pcap_pkthdr,
    arg3: *mut *const u_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_breakloop(arg1: *mut pcap_t) {}

pub fn pcap_stats(arg1: *mut pcap_t, arg2: *mut pcap_stat) -> ::std::os::raw::c_int {}

pub fn pcap_setfilter(arg1: *mut pcap_t, arg2: *mut bpf_program) -> ::std::os::raw::c_int {}

pub fn pcap_setdirection(arg1: *mut pcap_t, arg2: pcap_direction_t) -> ::std::os::raw::c_int {}

pub fn pcap_getnonblock(
    arg1: *mut pcap_t,
    arg2: *mut ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_setnonblock(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
    arg3: *mut ::std::os::raw::c_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_inject(
    arg1: *mut pcap_t,
    arg2: *const ::std::os::raw::c_void,
    arg3: usize,
) -> ::std::os::raw::c_int {}

pub fn pcap_sendpacket(
    arg1: *mut pcap_t,
    arg2: *const u_char,
    arg3: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_statustostr(arg1: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char {}

pub fn pcap_strerror(arg1: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char {}

pub fn pcap_geterr(arg1: *mut pcap_t) -> *mut ::std::os::raw::c_char {}

pub fn pcap_perror(arg1: *mut pcap_t, arg2: *const ::std::os::raw::c_char) {}

pub fn pcap_compile(
    arg1: *mut pcap_t,
    arg2: *mut bpf_program,
    arg3: *const ::std::os::raw::c_char,
    arg4: ::std::os::raw::c_int,
    arg5: bpf_u_int32,
) -> ::std::os::raw::c_int {}

pub fn pcap_compile_nopcap(
    arg1: ::std::os::raw::c_int,
    arg2: ::std::os::raw::c_int,
    arg3: *mut bpf_program,
    arg4: *const ::std::os::raw::c_char,
    arg5: ::std::os::raw::c_int,
    arg6: bpf_u_int32,
) -> ::std::os::raw::c_int {}

pub fn pcap_freecode(arg1: *mut bpf_program) {}

pub fn pcap_offline_filter(
    arg1: *const bpf_program,
    arg2: *const pcap_pkthdr,
    arg3: *const u_char,
) -> ::std::os::raw::c_int {}

pub fn pcap_datalink(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_datalink_ext(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_list_datalinks(
    arg1: *mut pcap_t,
    arg2: *mut *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_datalink(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_free_datalinks(arg1: *mut ::std::os::raw::c_int) {}

pub fn pcap_datalink_name_to_val(arg1: *const ::std::os::raw::c_char) -> ::std::os::raw::c_int {}

pub fn pcap_datalink_val_to_name(arg1: ::std::os::raw::c_int) -> *const ::std::os::raw::c_char {}

pub fn pcap_datalink_val_to_description(
    arg1: ::std::os::raw::c_int,
) -> *const ::std::os::raw::c_char {}

pub fn pcap_snapshot(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_is_swapped(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_major_version(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_minor_version(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE {}

pub fn pcap_fileno(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

pub fn pcap_dump_open(
    arg1: *mut pcap_t,
    arg2: *const ::std::os::raw::c_char,
) -> *mut pcap_dumper_t {}

pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t {}

pub fn pcap_dump_open_append(
    arg1: *mut pcap_t,
    arg2: *const ::std::os::raw::c_char,
) -> *mut pcap_dumper_t {}

pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE {}

pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> ::std::os::raw::c_long {}

pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> ::std::os::raw::c_int {}

pub fn pcap_dump_close(arg1: *mut pcap_dumper_t) {}

pub fn pcap_dump(arg1: *mut u_char, arg2: *const pcap_pkthdr, arg3: *const u_char) {}

**/

pub fn pcap_findalldevs() -> Result<Vec<NetworkDevice>, Error> {
    unsafe {
        let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
        let ptr = errbuf.as_mut_ptr();
        let mut alldevsp: *mut raw::pcap_if_t = ptr::null_mut();
        if raw::pcap_findalldevs(&mut alldevsp, ptr) == raw::PCAP_ERROR {
            return Result::Err(PcapError(String::from("error")));
        }
        let mut curr_ptr = alldevsp;
        let mut devices = vec![];
        while !curr_ptr.is_null() {
            let curr = &*curr_ptr;
            let device = to_string(curr.name).map(|name| NetworkDevice {
                name,
                description: to_string(curr.description),
                addresses: parse_pcap_addr_t(curr.addresses),
                flags: curr.flags,
            });
            if (device.is_some()) {
                devices.push(device.unwrap());
            }
            curr_ptr = curr.next;
        }
        raw::pcap_freealldevs(alldevsp);
        Result::Ok(devices)
    }
}

/**
pub fn pcap_freealldevs(arg1: *mut pcap_if_t) {}

pub fn pcap_lib_version() -> *const ::std::os::raw::c_char {}

pub fn bpf_image(
    arg1: *const bpf_insn,
    arg2: ::std::os::raw::c_int,
) -> *mut ::std::os::raw::c_char {}

pub fn bpf_dump(arg1: *const bpf_program, arg2: ::std::os::raw::c_int) {}

pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}
**/
#[cfg(test)]
mod tests {
    #[test]
    fn it_works() {
        assert_eq!(2 + 2, 4);
    }
}

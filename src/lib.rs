use core::{fmt, mem, slice};
use std::{panic, ptr};
use std::ffi::CStr;
use std::ffi::CString;
use std::time::Duration;

use libc;
use nix::sys::socket::Ipv4Addr;
use nix::sys::socket::SockAddr;
use nix::sys::time::TimeVal;

mod raw;

#[derive(Debug)]
pub struct DeviceAddress {
    pub ip: Ipv4Addr,
    pub netmask: Ipv4Addr,
}

#[derive(Debug)]
pub struct Address {
    pub addr: SockAddr,
    pub netmask: Option<SockAddr>,
    pub broadaddr: Option<SockAddr>,
    pub dstaddr: Option<SockAddr>,
}

#[derive(Debug)]
pub struct Device {
    pub name: String,
    pub description: Option<String>,
    pub addresses: Vec<Address>,
    pub flags: u32,
}

#[derive(Debug)]
pub struct Handle<T> {
    handle: *const T
}

impl<T> Handle<T> {
    fn as_mut_ptr(&self) -> *mut T {
        self.handle as *mut T
    }
}

pub type DeviceHandle = Handle<raw::pcap_t>;
pub type DumperHandle = Handle<raw::pcap_dumper_t>;


#[repr(C)]
pub struct PacketHeader {
    pub ts: libc::timeval,
    pub caplen: u32,
    pub len: u32,
}

impl fmt::Debug for PacketHeader {
    fn fmt(&self, f: &mut fmt::Formatter) -> fmt::Result {
        write!(f,
               "PacketHeader {{ ts: {}, caplen: {}, len: {} }}",
               TimeVal::from(self.ts),
               self.caplen,
               self.len)
    }
}


#[derive(Debug)]
pub struct PacketCapture<'a> {
    pub header: &'a PacketHeader,
    pub packet: &'a [u8],
}


fn from_c_string(ptr: *const ::std::os::raw::c_char) -> Option<String> {
    if ptr.is_null() {
        None
    } else {
        Some(unsafe { CStr::from_ptr(ptr).to_string_lossy().into_owned() })
    }
}

unsafe fn parse_pcap_addr_t(addrs: *const raw::pcap_addr_t) -> Vec<Address> {
    let mut addresses = Vec::new();
    let mut it = addrs;
    while !it.is_null() {
        let curr_addr = *it;
        SockAddr::from_libc_sockaddr(curr_addr.addr).map(|addr| {
            addresses.push(Address {
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

#[deprecated(note = "This interface is obsoleted by pcap_findalldevs")]
pub fn pcap_lookupdev() -> Option<String> {
    unsafe {
        let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
        let ptr = errbuf.as_mut_ptr();
        let name = raw::pcap_lookupdev(ptr);
        from_c_string(name)
    }
}

pub fn pcap_lookupnet(
    device: &str
) -> Result<DeviceAddress, String> {
    let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
    let err_ptr = errbuf.as_mut_ptr();
    let mut netp: raw::bpf_u_int32 = 0;
    let mut maskp: raw::bpf_u_int32 = 0;
    let device_c = CString::new(device).unwrap();
    unsafe {
        if raw::pcap_lookupnet(device_c.as_ptr(), &mut netp, &mut maskp, err_ptr) == 0 {
            let netp_ptr: *const libc::in_addr = mem::transmute(&netp);
            let maskp_ptr: *const libc::in_addr = mem::transmute(&maskp);
            Ok(DeviceAddress {
                ip: Ipv4Addr(*netp_ptr),
                netmask: Ipv4Addr(*maskp_ptr),
            })
        } else {
            Err(from_c_string(err_ptr).unwrap())
        }
    }
}

pub fn pcap_lib_version() -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_lib_version())
    }
}

/**
pub fn pcap_freealldevs(arg1: *mut pcap_if_t) {}



pub fn bpf_image(
    arg1: *const bpf_insn,
    arg2: ::std::os::raw::c_int,
) -> *mut ::std::os::raw::c_char {}

pub fn bpf_dump(arg1: *const bpf_program, arg2: ::std::os::raw::c_int) {}

//TODO
pub fn pcap_get_selectable_fd(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}
**/

/**
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
) -> *mut pcap_t {

}

pub fn pcap_fopen_offline_with_tstamp_precision(
    arg1: *mut FILE,
    arg2: u_int,
    arg3: *mut ::std::os::raw::c_char,
) -> *mut pcap_t {}

pub fn pcap_fopen_offline(arg1: *mut FILE, arg2: *mut ::std::os::raw::c_char) -> *mut pcap_t {}
**/

pub fn pcap_close(handle: &DeviceHandle) {
    unsafe {
        raw::pcap_close(handle.as_mut_ptr())
    }
}


unsafe extern fn packet_capture_callback<F: Fn(&PacketCapture)>(user: *mut raw::u_char,
                                                                header: *const raw::pcap_pkthdr,
                                                                packet: *const raw::u_char) {
    let packet_capture = from_raw_packet_capture(packet, header);

    let cb_state_ptr = unsafe { &mut *(user as *mut CallbackState<F>) };
    match *cb_state_ptr {
        CallbackState::Callback(ref mut cb_ptr) => {
            let callback = cb_ptr as *mut F as *mut raw::u_char;
            panic::catch_unwind(|| {
                let callback = unsafe { &mut *(callback as *mut F) };
                packet_capture.iter().for_each(|p| callback(&p));
            });
        }
    }
}


pub fn pcap_create(
    source: &str
) -> Result<DeviceHandle, String> {
    let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
    let err_ptr = errbuf.as_mut_ptr();
    let device_c = CString::new(source).unwrap();
    unsafe {
        let handle_ptr = raw::pcap_create(device_c.as_ptr(), err_ptr);
        if handle_ptr.is_null() {
            Err(from_c_string(err_ptr).unwrap())
        } else {
            Ok(DeviceHandle { handle: handle_ptr })
        }
    }
}


pub fn pcap_set_snaplen(
    handle: &DeviceHandle,
    snaplen: i32,
) -> i32 {
    unsafe {
        raw::pcap_set_snaplen(handle.as_mut_ptr(), snaplen)
    }
}

pub fn pcap_set_promisc(
    handle: &DeviceHandle,
    promisc: i32,
) -> i32 {
    unsafe {
        raw::pcap_set_promisc(handle.as_mut_ptr(), promisc)
    }
}

pub fn pcap_can_set_rfmon(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_can_set_rfmon(handle.as_mut_ptr())
    }
}

pub fn pcap_set_rfmon(handle: &DeviceHandle, rfmon: i32) -> i32 {
    unsafe {
        raw::pcap_set_rfmon(handle.as_mut_ptr(), rfmon)
    }
}

pub fn pcap_set_timeout(
    handle: &DeviceHandle,
    timeout: Duration,
) -> i32 {
    unsafe {
        raw::pcap_set_timeout(handle.as_mut_ptr(), timeout.as_millis() as _)
    }
}

pub fn pcap_set_tstamp_type(
    handle: &DeviceHandle,
    tstamp_type: i32,
) -> i32 {
    unsafe {
        raw::pcap_set_tstamp_type(handle.as_mut_ptr(), tstamp_type)
    }
}

pub fn pcap_set_immediate_mode(
    handle: &DeviceHandle,
    immediate_mode: i32,
) -> i32 {
    unsafe {
        raw::pcap_set_immediate_mode(handle.as_mut_ptr(), immediate_mode)
    }
}

pub fn pcap_set_buffer_size(
    handle: &DeviceHandle,
    buffer_size: i32,
) -> i32 {
    unsafe {
        raw::pcap_set_buffer_size(handle.as_mut_ptr(), buffer_size)
    }
}


pub fn pcap_set_tstamp_precision(
    handle: &DeviceHandle,
    tstamp_precision: i32,
) -> i32 {
    unsafe {
        raw::pcap_set_tstamp_precision(handle.as_mut_ptr(), tstamp_precision)
    }
}

pub fn pcap_get_tstamp_precision(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_get_tstamp_precision(handle.as_mut_ptr())
    }
}


pub fn pcap_activate(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_activate(handle.as_mut_ptr())
    }
}

pub fn pcap_list_tstamp_types(handle: &DeviceHandle) -> Result<Vec<i32>, String> {
    let mut tstamp_types_ptr: *mut ::std::os::raw::c_int = ptr::null_mut();
    unsafe {
        let count = raw::pcap_list_tstamp_types(handle.as_mut_ptr(), &mut tstamp_types_ptr);
        if count == raw::PCAP_ERROR {
            return Err(pcap_geterr(handle).unwrap());
        }
        let tstamp_types: &[i32] = slice::from_raw_parts(tstamp_types_ptr, count as usize);
        raw::pcap_free_tstamp_types(tstamp_types_ptr);
        Result::Ok(Vec::from(tstamp_types))
    }
}

/**
pub fn pcap_free_tstamp_types(arg1: *mut ::std::os::raw::c_int) {}
**/
pub fn pcap_tstamp_type_name_to_val(name: &str) -> i32 {
    let name_c = CString::new(name).unwrap();
    unsafe {
        raw::pcap_tstamp_type_name_to_val(name_c.as_ptr())
    }
}

pub fn pcap_tstamp_type_val_to_name(val: i32) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_tstamp_type_val_to_name(val))
    }
}

pub fn pcap_tstamp_type_val_to_description(val: i32) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_tstamp_type_val_to_description(val))
    }
}


pub fn pcap_open_live(
    device: &str,
    snaplen: i32,
    promisc: i32,
    to_ms: i32,
) -> Result<DeviceHandle, String> {
    let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
    let err_ptr = errbuf.as_mut_ptr();
    let device_c = CString::new(device).unwrap();
    unsafe {
        let handle_ptr = raw::pcap_open_live(device_c.as_ptr(), snaplen, promisc, to_ms, err_ptr);
        if handle_ptr.is_null() {
            Err(from_c_string(err_ptr).unwrap())
        } else {
            Ok(DeviceHandle { handle: handle_ptr })
        }
    }
}

enum CallbackState<F: Fn(&PacketCapture)> {
    Callback(F),
}

//TODO: pass optional user data with the callback
pub fn pcap_loop<F: Fn(&PacketCapture)>(
    handle: &DeviceHandle,
    count: i32,
    callback: F,
) -> i32 {
    unsafe {
        let mut cb_state = CallbackState::Callback(callback);
        let cb_ptr = &mut cb_state as *mut _ as *mut raw::u_char;
        raw::pcap_loop(handle.as_mut_ptr(),
                       count,
                       Some(packet_capture_callback::<F>),
                       cb_ptr)
    }
}

//TODO: pass optional user data with the callback
pub fn pcap_dispatch<F: Fn(&PacketCapture)>(
    handle: &DeviceHandle,
    count: i32,
    callback: F,
) -> i32 {
    unsafe {
        let mut cb_state = CallbackState::Callback(callback);
        let cb_ptr = &mut cb_state as *mut _ as *mut raw::u_char;
        raw::pcap_dispatch(handle.as_mut_ptr(),
                           count,
                           Some(packet_capture_callback::<F>),
                           cb_ptr)
    }
}

unsafe fn from_raw_packet_capture<'a>(raw_packet: *const raw::u_char,
                                      raw_header: *const raw::pcap_pkthdr) -> Option<PacketCapture<'a>> {
    if raw_packet.is_null() {
        None
    } else {
        let header: &PacketHeader = mem::transmute(&*raw_header);
        let packet = core::slice::from_raw_parts(raw_packet, (&*header).len as _);
        Some(PacketCapture {
            header,
            packet,
        })
    }
}

pub fn pcap_next(handle: &DeviceHandle) -> Option<PacketCapture> {
    unsafe {
        let mut packet_header: raw::pcap_pkthdr = std::mem::zeroed();
        let packet_ptr = raw::pcap_next(handle.as_mut_ptr(), &mut packet_header);
        from_raw_packet_capture(packet_ptr, &packet_header)
    }
}

pub fn pcap_next_ex(
    handle: &DeviceHandle
) -> Result<PacketCapture, i32> {
    unsafe {
        let mut packet_ptr: *const raw::u_char = ptr::null_mut();
        let mut packet_header: *mut raw::pcap_pkthdr = ptr::null_mut();
        match raw::pcap_next_ex(handle.as_mut_ptr(), &mut packet_header, &mut packet_ptr) {
            1 => {
                Ok(from_raw_packet_capture(packet_ptr, packet_header).unwrap())
            }
            err => {
                Err(err)
            }
        }
    }
}

pub fn pcap_breakloop(handle: &DeviceHandle) {
    unsafe {
        raw::pcap_breakloop(handle.as_mut_ptr())
    }
}

/**

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
**/
pub fn pcap_statustostr(errnum: i32) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_statustostr(errnum))
    }
}

pub fn pcap_strerror(errnum: i32) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_strerror(errnum))
    }
}

pub fn pcap_geterr(handle: &DeviceHandle) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_geterr(handle.as_mut_ptr()))
    }
}

pub fn pcap_perror(handle: &DeviceHandle, prefix: &str) {
    let prefix_c = CString::new(prefix).unwrap();
    unsafe {
        raw::pcap_perror(handle.as_mut_ptr(), prefix_c.as_ptr())
    }
}

/**

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
**/

pub fn pcap_datalink(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_datalink(handle.as_mut_ptr())
    }
}

pub fn pcap_datalink_ext(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_datalink_ext(handle.as_mut_ptr())
    }
}

/**
pub fn pcap_list_datalinks(
    arg1: *mut pcap_t,
    arg2: *mut *mut ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_set_datalink(
    arg1: *mut pcap_t,
    arg2: ::std::os::raw::c_int,
) -> ::std::os::raw::c_int {}

pub fn pcap_free_datalinks(arg1: *mut ::std::os::raw::c_int) {}
**/

pub fn pcap_datalink_name_to_val(name: &str) -> i32 {
    let name_c = CString::new(name).unwrap();
    unsafe {
        raw::pcap_datalink_name_to_val(name_c.as_ptr())
    }
}

pub fn pcap_datalink_val_to_name(val: i32) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_datalink_val_to_name(val))
    }
}

pub fn pcap_datalink_val_to_description(
    val: i32,
) -> Option<String> {
    unsafe {
        from_c_string(raw::pcap_datalink_val_to_description(val))
    }
}


pub fn pcap_snapshot(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_snapshot(handle.as_mut_ptr())
    }
}

pub fn pcap_is_swapped(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_is_swapped(handle.as_mut_ptr())
    }
}

pub fn pcap_major_version(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_major_version(handle.as_mut_ptr())
    }
}

pub fn pcap_minor_version(handle: &DeviceHandle) -> i32 {
    unsafe {
        raw::pcap_minor_version(handle.as_mut_ptr())
    }
}

/**
pub fn pcap_file(arg1: *mut pcap_t) -> *mut FILE {}

pub fn pcap_fileno(arg1: *mut pcap_t) -> ::std::os::raw::c_int {}

**/
pub fn pcap_dump_open(
    handle: &DeviceHandle,
    fname: &str,
) -> Result<DumperHandle, String> {
    let fname_c = CString::new(fname).unwrap();
    unsafe {
        let handle_ptr = raw::pcap_dump_open(handle.as_mut_ptr(), fname_c.as_ptr());
        if handle_ptr.is_null() {
            Err(pcap_geterr(&handle).unwrap())
        } else {
            Ok(DumperHandle { handle: handle_ptr })
        }
    }
}

/**
pub fn pcap_dump_fopen(arg1: *mut pcap_t, fp: *mut FILE) -> *mut pcap_dumper_t {}

pub fn pcap_dump_open_append(
    arg1: *mut pcap_t,
    arg2: *const ::std::os::raw::c_char,
) -> *mut pcap_dumper_t {}

pub fn pcap_dump_file(arg1: *mut pcap_dumper_t) -> *mut FILE {}

pub fn pcap_dump_ftell(arg1: *mut pcap_dumper_t) -> ::std::os::raw::c_long {}

pub fn pcap_dump_flush(arg1: *mut pcap_dumper_t) -> ::std::os::raw::c_int {}

**/
pub fn pcap_dump_close(dumper: &DumperHandle) {
    unsafe {
        raw::pcap_dump_close(dumper.as_mut_ptr())
    }
}


pub fn pcap_dump(dumper: &DumperHandle, capture: &PacketCapture) {
    unsafe {
        raw::pcap_dump(dumper.as_mut_ptr() as _,
                       mem::transmute(capture.header),
                       capture.packet.as_ptr())
    }
}


pub fn pcap_findalldevs() -> Result<Vec<Device>, String> {
    unsafe {
        let mut errbuf = [0i8; raw::PCAP_ERRBUF_SIZE as usize];
        let err_ptr = errbuf.as_mut_ptr();
        let mut alldevsp: *mut raw::pcap_if_t = ptr::null_mut();
        if raw::pcap_findalldevs(&mut alldevsp, err_ptr) == raw::PCAP_ERROR {
            return Err(from_c_string(err_ptr).unwrap());
        }
        let mut curr_ptr = alldevsp;
        let mut devices = vec![];
        while !curr_ptr.is_null() {
            let curr = &*curr_ptr;
            let device = from_c_string(curr.name).map(|name| Device {
                name,
                description: from_c_string(curr.description),
                addresses: parse_pcap_addr_t(curr.addresses),
                flags: curr.flags,
            });
            if device.is_some() {
                devices.push(device.unwrap());
            }
            curr_ptr = curr.next;
        }
        raw::pcap_freealldevs(alldevsp);
        Result::Ok(devices)
    }
}

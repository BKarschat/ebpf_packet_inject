// remmeber no std code in kernel space
//

#![no_std]

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub src_ip: u32,
    pub dst_ip: u32,
    pub src_port: u16,
    pub dst_port: u16,
    pub match_bytes: [u8; 32],
    pub match_len: u8,
}

#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsConfig {
    pub pattern_len: u8,
    pub pattern: [u8; 32],
}

// no std in kernel space!
//

#![no_std]
#![no_main]

use core::mem;

use aya_ebpf::{
    bindings::xdp_action,
    macros::{map, xdp},
    maps::{ring_buf::RingBuf, HashMap},
    programs::XdpContext,
};

use aya_log_ebpf::info;
use xdp-data-structures::{DnsEvent, DnsConfig};
use network_types::{ eth::{EthHdr, EtherType},
                    ip::Ipv4Hdr, udp::UdpHdr, };

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONFIG: HashMap<u32, DnsConfig> = HashMap::<u32, DnsConfig>::with_max_entries(1, 0);

// load pattern data given by user at start
fn load_config() -> (u8, [u8; 32]) {
    let key: u32 = 0;
    match unsafe { CONFIG.get(&key) } {
        Some(cfg) => (cfg.pattern_len, cfg.pattern),
        None => (4, [0xde, 0xad, 0xbe, 0xef]), // default
    }
}

fn ptr_At<'a, T>(ctx: &XdpContext, offset: usize) -> Result<&'a T, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;
    let size = mem::size_of::<T>();
    if start + offset + size > end {
        return Err(());
    }
    let ptr = (start + offset) as *const T;
    // BPF Verifier for no OUT OF BOUNDS errors
    OK(unsafe {&*ptr})
}

#[xdp]
pub fn dns_xdp(ctx: XdpContext) -> u32 {
    match try_dns_xdp(ctx) {
        Ok(ret) => ret,
        Err(_) => xdp_action::XDP_PASS,
    }
}

fn try_dns_xdp(ctx: XdpContext) -> Result<u32, ()> {
    let eth = ptr_at::<EthHdr>(&ctx, 0)?;
    match eth.ether_type() {
        Ok(EtherType::Ipv4) => {}, // TODO
        _ => return Ok(xdp_action::XDP_PASS),
    }

    let ip = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    // TODO match different filter
    if ip.proto != 17 {
        return Ok(xdp_action::XDP_PASS);
    }
    
    let ip_hdr_len = (ip.ihl() * 4) as usize;
    let udp_offset = EthHdr::LEN + ip_hdr_len; // dynamic offset
    let udp = ptr_at::<UdpHdr>(&ctx, udp_offset)?;

    let src_port = u16::from_be(udp.source);
    let dst_port = u16::from_be(udp.dst);

    if src_port != 53 && dst_port != 53 {
        return Ok(xdp_action:: XDP_PASS);
    }

    let udp_hdr_len = mem::size_of::<UdpHdr>();
    let dns_offset = udp_offset + udp_hdr_len;

    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    //dynamic data input for pattern
    let (pattern_len, pattern) = load_config();
    let payload_offset = dns_offset + 12;
    let max_len = data_end - payload_offset;
    // way to static -> User Input
    //if dns_offset + 12 + 4 > data_end - data_start {
    //    return Ok(xdp_action::XDP_PASS);
    //}

    if max_len < pattern_len as usize {
        return Ok(xdp_action::XDP_PASS);
    }
    
    //let p = (data_start + dns_offset + 12) as *const u8;
    let payload = unsafe { core::slice::from_raw_parts((ctx.data() as usize + payload_offset) as *const u8, pattern_len as usize) };

    // byte for byte
    let mut match_ok = true;
    for i in 0..pattern_len as usize {
        if payload[i] != pattern[i] {
            match_ok = false;
            break;
        }
    }
    
    if !match_ok {
        return Ok(xdp_action::XDP_PASS);
    }

    //event with effective length
    if let Some(mut entry) = EVENTS.reserve::<DnsEvent>(0) {
        let src_ip = u32::from_be_bytes(ip.src_addr);
        let dst_ip = u32::from_be_bytes(ip.dst_addr);

        let event = DnsEvent {
            src_ip,
            dst_ip,
            src_port,
            dst_port,
            match_bytes: pattern,
            match_len: pattern_len,
        };

        unsafe {
            entry.write(&event);
    }
        entry.submit();
        info!(&ctx, "DNS match, event sent!");
    }
    Ok(xdp_action::XDP_PASS)
}

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
use network_types::{
    eth::{EthHdr, EtherType},
    ip::Ipv4Hdr,
    udp::UdpHdr,
};
use xdp_data_structures::{DnsConfig, DnsEvent};

#[map]
static EVENTS: RingBuf = RingBuf::with_byte_size(256 * 1024, 0);

#[map]
static CONFIG: HashMap<u32, DnsConfig> = HashMap::<u32, DnsConfig>::with_max_entries(1, 0);

#[inline(always)]
fn ptr_at<'a, T>(ctx: &XdpContext, offset: usize) -> Result<&'a T, ()> {
    let start = ctx.data() as usize;
    let end = ctx.data_end() as usize;
    let len = core::mem::size_of::<T>();

    if start + offset + len > end {
        return Err(());
    }
    // BPF Verifier for no OUT OF BOUNDS errors
    Ok(unsafe { &*((start + offset) as *const T) })
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
    if eth.ether_type != EtherType::Ipv4 as u16 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip = ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN)?;
    // TODO match different filter
    if ip.proto != 17 {
        return Ok(xdp_action::XDP_PASS);
    }

    let ip_hdr_len = (ip.ihl() * 4) as usize;
    let udp_offset = EthHdr::LEN + ip_hdr_len; // dynamic offset
    let udp = ptr_at::<UdpHdr>(&ctx, EthHdr::LEN + ip_hdr_len)?;

    let src_port = u16::from_be_bytes(udp.src);
    let dst_port = u16::from_be_bytes(udp.dst);

    if src_port != 53 && dst_port != 53 {
        return Ok(xdp_action::XDP_PASS);
    }

    let udp_hdr_len = mem::size_of::<UdpHdr>();
    let dns_offset = udp_offset + udp_hdr_len;
    let payload_offset = dns_offset + 12;

    let mut pattern = [0u8; 32];
    let mut plen: u8 = 4;
    pattern[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
    let key: u32 = 0;
    if let Some(cfg) = unsafe { CONFIG.get(&key) } {
        plen = cfg.pattern_len;
        pattern = cfg.pattern;
    }

    let pattern_len = plen as usize;
    if pattern_len == 0 || pattern_len > 32 {
        return Ok(xdp_action::XDP_PASS);
    }

    let data_start = ctx.data() as usize;
    let data_end = ctx.data_end() as usize;

    if data_start + payload_offset + pattern_len > data_end {
        return Ok(xdp_action::XDP_PASS);
    }

    // byte for byte
    let mut match_ok = true;
    for i in 0..32usize {
        if i >= pattern_len {
            break;
        }
        let addr = data_start + payload_offset + i;
        if addr >= data_end {
            return Ok(xdp_action::XDP_PASS);
        }
        if unsafe { *(addr as *const u8) } != pattern[i] {
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
            match_len: plen,
        };

        entry.write(event);
        entry.submit(0);
        info!(&ctx, "DNS match, event send!");
    }
    Ok(xdp_action::XDP_PASS)
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

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
    //info!(&ctx, "dns context");
    //return 0;
    let eth = match ptr_at::<EthHdr>(&ctx, 0) {
        Ok(v) => v,
        Err(_) => return xdp_action::XDP_PASS,
    };
    match eth.ether_type() {
        Ok(EtherType::Ipv4) => {}
        _ => return xdp_action::XDP_PASS,
    }

    let ip = match ptr_at::<Ipv4Hdr>(&ctx, EthHdr::LEN) {
        Ok(v) => v,
        Err(_) => return xdp_action::XDP_PASS,
    };

    // TODO match different filter
    if ip.proto != 17 {
        return xdp_action::XDP_PASS;
    }

    const UDP_OFFSET: usize = 34;
    const DNS_OFFSET: usize = 42;
    const PAYLOAD_OFFSET: usize = 54;

    // UDP
    let udp = match ptr_at::<UdpHdr>(&ctx, UDP_OFFSET) {
        Ok(v) => v,
        Err(_) => return xdp_action::XDP_PASS,
    };

    let src_port = u16::from_be_bytes(udp.src);
    let dst_port = u16::from_be_bytes(udp.dst);
    if src_port != 53 && dst_port != 53 {
        return xdp_action::XDP_PASS;
    }

    // Manuelles loaden des pattern mit default Werten
    let key: u32 = 0;
    let (plen, pattern, mode) = match unsafe { CONFIG.get(&key) } {
        Some(cfg) => (cfg.pattern_len, cfg.pattern, cfg.mode), // cfg.pattern ist [u8; 32]
        None => {
            let mut p = [0u8; 32];
            p[0] = 0xde;
            p[1] = 0xad;
            p[2] = 0xbe;
            p[3] = 0xef;
            (4u8, p, 0u8)
        }
    };

    let pattern_len = plen as usize;
    //let payload_offset = (dns_offset + 12) & 0x1ff;

    // Vergleich — pattern liegt auf dem Stack, ptr_at bleibt inline
    let mut match_ok = true;
    for i in 0..32usize {
        if i >= pattern_len {
            break;
        }
        let byte: u8 = match ptr_at::<u8>(&ctx, PAYLOAD_OFFSET + i) {
            Ok(v) => *v,
            Err(_) => return xdp_action::XDP_PASS,
        };
        if byte != pattern[i] {
            match_ok = false;
            break;
        }
    }

    if !match_ok {
        return xdp_action::XDP_PASS;
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
            was_dropped: mode,
        };

        entry.write(event);
        entry.submit(0);
        info!(&ctx, "DNS match, event send, packet drop!");
    }
    // Drop packet!
    if mode == 1 {
        return xdp_action::XDP_DROP;
    } else {
        xdp_action::XDP_PASS
    }
}

#[panic_handler]
fn panic(_info: &core::panic::PanicInfo) -> ! {
    loop {}
}

use std::(net::Ipv4Addr, time::Duration);

use anyhow::Result;
use aya::{
    include_bytes_aligened,
    maps::ring_buf::RingBuf,
    programs::{Xdp, XdpFlags},
    Ebpf,
};
use clap::Parser;
use xdp-data-structures::{DnsEvent, DnsConfig};
use log::info;
use tokio::signal;

#[derive(Debug, Parser)]
#[command(name = "xdp-user")]
#[command(about = "DNS XDP filter with config", long_about = None)]

#[derive(Debug, clap::Subcommand)]
enum Command {
    Run {
        #[arg(short, long, default_value = "enp0s3")]
        iface: String,
    },
    //
    //hot reload of pattern

    SetPattern {
        #[arg(short, long)]
        pattern: String,
        #[arg(short, long)]
        pattern_len: Option<usize>,
    },
}

#[derive(Debug, Parser)]
struct Opt {
    #[command(subcommand)]
    cmd: Command,
    //#[arg(short, long, default_value = "enp0s3")]
    //    iface: String,

        //pattern as hex
    //#[arg(short, long)]
    //    pattern: String,

        //pattern length
    //#[arg(short, long)]
    //    pattern_len: Option<usize>,
}


fn parse_pattern (pattern_str: &str, len: Option<usize>) -> Result<DnsConfig> {
    let clean = pattern_str.replace(":", "").replace("-", "").replace(" ", "");

    let byte_len = clean.len() / 2;
    let effective_len = len.unwrap_op(byte_len);

    if effective_len == 0 || effective_len > 32 {
        anyhow::bail!(" Pattern length has to be 1 - 32 byte!");
    }

    let mut pattern = [0u8; 32];
    for (i, chunk) in clean.as_byte().array_chunks().take(32).enumerate() {
        pattern[i] = u8::from_str_radix(
            core::str::from_utf8(chunk).unwrap(), 16)?;
    }

    Ok(DnsConfig {
        pattern_len: effective_len as u8,
        pattern,
    })
}

fn set_pattern(pattern_str: &str, len: Option<usize>) -> Result <()> {
    let cfg = parse_pattern(pattern_str, len)?;
    let mut bpf = Ebpf::load{include_bytes_aligned! (
    "../../target/bpfel-unknown-none/release/dns-xdp-ebpf" ) };
    
    // do not attach, just get the map
    let mut config_map: HashMap<_, u32, DnsConfig> = HashMap::try_from(bpf.map_mut("CONFIG")?)?;
    let key: u32 = 0;
    config_map.insert(key, cfg, 0)?;
    info!("init pattern");

}


#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();
    
    let opt = Opt::parse();
    match opt.cmd {
        Command::Run {iface} => run_deamon(&iface).await?,
        Command::SetPattern {pattern, pattern_len } =>  { set_pattern(&pattern, pattern_len)},
    }

    {
        let mut config_map: HashMap<_, u32, DnsConfig> =
            HashMap::try_from(bpf.map_mut("CONFIG")?)?;
        let key: u32 = 0;
        let cfg = DnsConfig { pattern };
        config_map.insert(key, cfg, 0)?;
        info!("Config map initialisiert");
    }
    let pattern_config = parse_pattern(&opt.pattern, opt.pattern_len)?;
    config_map.insert(key, pattern_config, 0)?;


    let mut bpf = Ebpf::load(include_bytes_aligned!("../../target/bpfel-unkown-none/release/xdp-ebpf"))?;

    let program: &mut Xdp = bpf.program_mut("dns_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(&opt.iface, XdpFlags::default())?;
    info!("XDP program attached on {]", opt.iface);

    let mut ring_buf = RingBuf::try_from(bpf.map_mut("EVENTS")?)?;
    let mut async_rb = aya::maps::ring_buf::RingBufAsync::new(ring_buf)?;

    info!("Waiting for DNS events ..");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info(" Ctrl-C recieved, abort");
                break;
            }
            res = async_rb.next() => {
                match res {
                    Ok (data) => {
                        if data.len() != core::mem::size_of<DnsEvent>() {
                            continue;
                        }
                        let event: &DnsEvent = unsafe {
                            &*(data.as_ptr() as *const DnsEvent)
                        };

                        let src = Ipv4Addr::from(event.src_ip);
                        let dst = Ipv4Addr::from(event.dst_ip);

                        info!( "Match from {}:{}, bytes={:02x?}",
                            src, event.src_port, dst, event.dst_port, event.match_bytes, );
info!(
    "Match (len={}): {}:{} -> {}:{}, bytes={:02x?}",
    event.match_len,
    src, event.src_port, dst, event.dst_port,
    &event.match_bytes[0..event.match_len as usize]
);
                        //TODO do more!

                    }
                    Err(e) => {
                        eprintln!("ringbuf error: {e}");
                        tokio::time::sleep(Duration::from_millis(100)).await;
                    }
                }
            }
        }
    }
    Ok(())
}

use std::net::Ipv4Addr;

use anyhow::Result;
use aya::{
    include_bytes_aligned,
    maps::{ring_buf::RingBuf, HashMap},
    programs::{Xdp, XdpFlags},
    Ebpf,
};

use clap::Parser;
use log::info;
use tokio::signal;
use xdp_data_structures::{DnsConfig, DnsEvent};

#[derive(Debug, Parser)]
#[command(name = "xdp-user")]
#[command(about = "DNS XDP filter with config", long_about = None)]
struct Opt {
    #[command(subcommand)]
    cmd: Command,
}
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

fn parse_pattern(pattern_str: &str, len: Option<usize>) -> Result<DnsConfig> {
    let clean = pattern_str
        .replace(":", "")
        .replace("-", "")
        .replace(" ", "");

    let byte_len = clean.len() / 2;
    let effective_len = len.unwrap_or(byte_len);

    if effective_len == 0 || effective_len > 32 {
        anyhow::bail!(" Pattern length has to be 1 - 32 byte!");
    }

    let mut pattern = [0u8; 32];
    for (i, chunk) in clean.as_bytes().chunks(2).take(32).enumerate() {
        //    for (i, chunk) in clean.as_bytes().array_chunks().take(32).enumerate() {
        pattern[i] = u8::from_str_radix(core::str::from_utf8(chunk).unwrap(), 16)?;
    }

    Ok(DnsConfig {
        pattern_len: effective_len as u8,
        pattern,
    })
}

fn set_pattern(pattern_str: &str, len: Option<usize>) -> Result<()> {
    let cfg = parse_pattern(pattern_str, len)?;
    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libxdp_ebpf.so"
    ))?;

    // do not attach, just get the map
    let mut config_map: HashMap<_, u32, DnsConfig> = HashMap::try_from(
        bpf.map_mut("CONFIG")
            .ok_or(anyhow::anyhow!("CONFIG map not found"))?,
    )?;
    let key: u32 = 0;
    config_map.insert(key, cfg, 0)?;
    info!("init pattern");
    Ok(())
}

#[tokio::main]
async fn main() -> Result<()> {
    env_logger::init();

    let opt = Opt::parse();
    match opt.cmd {
        Command::Run { iface } => run_daemon(&iface).await?,
        Command::SetPattern {
            pattern,
            pattern_len,
        } => set_pattern(&pattern, pattern_len)?,
    }
    Ok(())
}

async fn run_daemon(iface: &str) -> Result<()> {
    use tokio::io::unix::AsyncFd;

    let mut bpf = Ebpf::load(include_bytes_aligned!(
        "../../target/bpfel-unknown-none/release/libxdp_ebpf.so"
    ))?;

    let mut config_map: HashMap<_, u32, DnsConfig> = HashMap::try_from(
        bpf.map_mut("CONFIG")
            .ok_or(anyhow::anyhow!("CONFIG map not found"))?,
    )?;
    let key: u32 = 0;
    let default_cfg = DnsConfig {
        pattern_len: 4,
        pattern: {
            let mut p = [0u8; 32];
            p[..4].copy_from_slice(&[0xde, 0xad, 0xbe, 0xef]);
            p
        },
    };
    config_map.insert(key, default_cfg, 0)?;
    info!("Config map initialisiert");

    let program: &mut Xdp = bpf.program_mut("dns_xdp").unwrap().try_into()?;
    program.load()?;
    program.attach(iface, XdpFlags::default())?;
    info!("XDP program attached on {}", iface);

    let ring_buf = RingBuf::try_from(
        bpf.map_mut("EVENTS")
            .ok_or(anyhow::anyhow!("EVENTS not found"))?,
    )?;
    let mut async_fd = AsyncFd::new(ring_buf)?;

    info!("Waiting for DNS events ..");

    loop {
        tokio::select! {
            _ = signal::ctrl_c() => {
                info!("Ctrl-C received, abort");
                break;
            }
            guard = async_fd.readable_mut() => {
                let mut guard = guard?;
                let rb = guard.get_inner_mut();
                while let Some(item) = rb.next() {
                    let data: &[u8] = &item;
                    if data.len() != core::mem::size_of::<DnsEvent>() { continue; }
                    let event: &DnsEvent = unsafe {
                        &*(data.as_ptr() as *const DnsEvent)
                    };
                    let src = Ipv4Addr::from(event.src_ip);
                    let dst = Ipv4Addr::from(event.dst_ip);
                    info!(
                        "Match (len={}): {}:{} -> {}:{}, bytes={:02x?}",
                        event.match_len,
                        src, event.src_port,
                        dst, event.dst_port,
                        &event.match_bytes[0..event.match_len as usize]
                    );
                }
                guard.clear_ready();
            }
        }
    }
    Ok(())
}

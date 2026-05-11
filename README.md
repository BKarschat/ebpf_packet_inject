# ebpf_packet_inject

> Deep packet inspection via eBPF — written in Rust, running at the speed of the wire.

`ebpf_packet_inject` hooks into the Linux **XDP layer** to inspect, match, and drop packets before they ever reach the kernel network stack. A userspace process receives structured events via a **BPF ring buffer** whenever a configurable byte pattern is found in the DNS payload — no listening socket, no open port required.

---

## How it works

A normal incoming packet travels through the following stages in Linux:

```
NIC  (physical layer)
  ↓
XDP-Hook  ← this program runs here
  ↓
Kernel TCP/IP Stack
  ↓
Socket Buffer
  ↓
Userspace  (dig, browser, etc.)
```

This program attaches at the **XDP hook** — the earliest possible interception point, running directly in the NIC driver context before any memory allocation for the packet occurs. When a DNS packet matches the configured pattern, it is **dropped immediately** (`XDP_DROP`) and a `DnsEvent` is written into a **BPF ring buffer**. The userspace daemon reads this event asynchronously via `tokio` and logs the source IP, destination IP, ports, and the matching bytes.

No ports are opened. No sockets are bound. The bytes arrive, get inspected, and either pass silently or trigger an event — all before the kernel even knows the packet existed.

---

## Architecture

The workspace contains three crates that each own a distinct responsibility:

```
ebpf_packet_inject/
├── dns-xdp-ebpf/        # eBPF kernel program  (no_std, bpfel-unknown-none)
├── xdp-user-space/      # async userspace daemon (tokio)
└── xdp-data-structures/ # shared types: DnsEvent, DnsConfig
```

### `dns-xdp-ebpf` — kernel space (`no_std`)

- Parses Ethernet → IPv4 → UDP headers with strict bounds checking accepted by the BPF verifier
- Clamps the IPv4 IHL field to the valid range `[20, 60]` to keep all offsets as **bounded scalars** — a requirement for the verifier to accept the program
- Skips all non-UDP (`proto != 17`) and non-DNS (`port != 53`) packets via early `XDP_PASS` returns
- Reads up to **32 bytes** of the DNS payload (skipping the 12-byte DNS header) and compares them byte-by-byte against the pattern stored in the `CONFIG` BPF HashMap
- On a match: writes a `DnsEvent` into the `EVENTS` ring buffer, then returns `XDP_PASS`
- Falls back to the hardcoded default pattern `0xdeadbeef` if no config entry is present in the map

### `xdp-user-space` — userspace daemon (async Tokio)

Built with: `aya`, `tokio`, `clap`, `log` / `env_logger`

- Loads the compiled eBPF ELF, initialises the `CONFIG` HashMap with the user-supplied hex pattern, and attaches the XDP program to the target interface
- Polls the `EVENTS` ring buffer in an async `tokio::select!` loop and logs every `DnsEvent`
- Supports a **`setpattern` subcommand** that rewrites the `CONFIG` map **while the XDP program is already running** — no restart required, no traffic interruption

### `xdp-data-structures` — shared types (`no_std`)

Defines the `#[repr(C)]` structs used by both the kernel program and userspace daemon:

```rust
// Emitted by the eBPF program into the ring buffer on every pattern match
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsEvent {
    pub srcip:      u32,       // source IPv4 address (big-endian)
    pub dstip:      u32,       // destination IPv4 address (big-endian)
    pub srcport:    u16,       // source UDP port
    pub dstport:    u16,       // destination UDP port
    pub matchbytes: [u8; 4],   // the first 4 matched bytes for quick inspection
    pub matchlen:   u8,        // effective match length (1–32)
}

// Stored in the CONFIG BPF HashMap (key = 0)
#[repr(C)]
#[derive(Clone, Copy)]
pub struct DnsConfig {
    pub patternlen: u8,        // number of bytes to match (1–32)
    pub pattern:    [u8; 32],  // the pattern itself, zero-padded
}
```

`DnsEvent` is the hook point for anything you want to do with the matched packet downstream — log it, forward it, write it to a database, trigger a side-effect. The `TODO do more!` in the userspace loop is intentional.

---

## BPF Maps

| Map | Type | Purpose |
|-----|------|---------|
| `CONFIG` | `HashMap<u32, DnsConfig>` | Holds the active pattern (up to 32 bytes) and its effective length. Writable from userspace at any time. |
| `EVENTS` | `RingBuf` | Lock-free, ordered, zero-copy event queue from kernel to userspace. 256 KB capacity. |

---

## Modes
| Mode | `DnsConfig.mode` | XDP action on match | Use case |
|------|------------------|---------------------|----------|
|`observed` | `0` | `XDP_PASS -- packet contunues to kernel, event emitted | Passive monitoring, debugging` |
| `block` | `1` | `XDP_DROP` -- packet discarded immediately, event emitted | Active blocking, filtering | 

---

## XDP Actions

| Action | What happens |
|--------|-------------|
| `XDP_PASS` | Packet continues normally into the kernel stack |
| `XDP_DROP` | Packet is discarded immediately — no memory allocated, zero kernel overhead |
| `XDP_TX` | Packet is sent back out through the same NIC |
| `XDP_REDIRECT` | Packet is forwarded to another NIC or socket |

Currently the program uses `XDP_PASS` on all non-matching packets. `XDP_DROP` and `XDP_TX` are architectural next steps — see the Roadmap below.

---

## Getting started

### Prerequisites

- Linux kernel **5.15+** (XDP + ring buffer support)
- `clang`, `llvm`, `libbpf-dev`, matching kernel headers
- Root / `CAP_NET_ADMIN` capability to attach XDP programs

### Installation

Run the setup script to install the full Rust nightly toolchain, the BPF cross-compilation target, `bpf-linker`, and all system dependencies in one step:

```bash
bash setup.sh
```

What `setup.sh` does, step by step:

```bash
# 1. Install Rust nightly with rust-src component
rustup toolchain install nightly --component rust-src
rustup default nightly

# 2. Add the BPF cross-compilation target
rustup target add bpfel-unknown-none

# 3. Install bpf-linker (links eBPF ELF objects)
cargo install bpf-linker

# 4. Install system dependencies
sudo apt install -y libbpf-dev linux-headers-$(uname -r) clang llvm

# 5. Test-build the eBPF crate
cd dns-xdp-ebpf
RUSTFLAGS="-C panic=abort" cargo build --release --target bpfel-unknown-none
```

### Build

```bash
cargo build --release
```

The workspace builds all three crates. The eBPF ELF is embedded into the userspace binary at compile time via `include_bytes_aligned!` — the final binary is fully self-contained and requires no external `.o` files at runtime.

---

## Usage

### Observe mode (default)

Attach the XDP filter and log matching packets without dropping them:

```bash
sudo RUST_LOG=info ./target/release/xdp-user-space run \
  --iface enp5s0 \
  --pattern "0377777706676f6f676c65"
  -- mode observed
```

### Block mode

Drop matching packets immediately and log the event:

```bash
sudo RUST_LOG=info ./target/release/xdp-user-space run \
  --iface enp5s0 \
  --pattern "0377777706676f6f676c65"
  -- mode block 
```

Then trigger a match:

```bash
dig www.google.com
```

The daemon logs every matched packet:

```
INFO  Match from 192.168.1.10:54312 → 8.8.8.8:53  bytes: [03 77 77 77 06 67 6f 6f 67 6c 65]
INFO  Match len - 11 | 192.168.1.10:54312 → 8.8.8.8:53
```

### Hot-reload the pattern

Update the pattern **while the XDP program is already running** — no restart, no packet loss:

```bash
# Switch to block mode with a new pattern
sudo ./target/release/xdp-user-space setpattern \
  --pattern "deadbeef" \
  --mode block

# Switch back to observe mode and change pattern
sudo ./target/release/xdp-user-space setpattern \
  --pattern "beefdead" \
  --mode observed
```

The tool opens the existing `CONFIG` BPF map and overwrites the entry. The kernel-side program picks up the new value on the very next packet.

### Pattern format

Patterns are supplied as hex strings. The `0x` prefix, dashes, and spaces are stripped automatically:

| Input | Bytes matched |
|-------|--------------|
| `"deadbeef"` | `0xDE 0xAD 0xBE 0xEF` — the default fallback |
| `"0xde-ad-be-ef"` | same |
| `"0377777706676f6f676c65"` | DNS-encoded `www.google` |
| `"03 77 77 77 07 65 78 61 6d 70 6c 65"` | DNS-encoded `www.example` |

Use `--patternlen` to match only a prefix of a longer hex string. Maximum pattern length is **32 bytes**. If no `--pattern` flag is supplied, the daemon loads the hardcoded fallback `0xdeadbeef` (4 bytes).

> **Note:** At the current state the program only inspects packets on **port 53 (DNS)**. Other protocols are passed through unconditionally.

---

## Security notice

This program requires **root privileges** or `CAP_NET_ADMIN` and attaches directly to a network interface via XDP. It is intended for use in controlled environments — your own machines, lab setups, or dedicated test interfaces. Do not attach it to production interfaces or shared infrastructure without understanding the implications. Misconfigured patterns can silently drop legitimate traffic.

---

## Roadmap

- [ ] Pattern matching on other ports (HTTP, TLS SNI, custom UDP/TCP)
- [ ] Multiple simultaneous patterns via a `HashMap<u32, DnsConfig>`
- [ ] `XDP_TX` response injection (e.g. NXDOMAIN spoofing without a resolver)
- [ ] Raw byte extraction from arbitrary payload offsets into `DnsEvent`
- [ ] Structured output (JSON / NDJSON) for downstream pipeline integration

---

## License

Licensed under either of

- Apache License, Version 2.0 ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
- MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted for inclusion in the work by you, as defined in the Apache-2.0 license, shall be dual licensed as above, without any additional terms or conditions.

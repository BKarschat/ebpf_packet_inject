# ebpf_packet_inject
Deep packet inspection via eBPF with Rust

This is the normal process for an incoming packet in linux:

NIC (physical layer)
  ↓
XDP-Hook  ← where this program is running
  ↓
Kernel TCP/IP Stack
  ↓
Socket Buffer
  ↓
Userspace (dig, Browser etc.)

So the idea is to get bytes into a linux environment without any listening Port or something.
The packet gets dropped and a user process gets an event via ring buffer.

To trigger the event you are able to set a pattern for the dns payload.
If the pattern is found the packets get dropped and the user process gets an event. 

You can change the pattern as the programm is running with the "setpattern" mode. This changes the BPF map while the program on xdp-hook level is running.

Later on other ports etc. will be supported and you are able to read in bytes from the packet. 

Maye there will be more options to do things with the packet.
There are these XDP-actions available:
| Action       | What is happenig                                |
| ------------ | ----------------------------------------------- |
| XDP_PASS     | Pass packet normal to the Kernel                |
| XDP_DROP     | Drop packet immediatly no memory is used        |
| XDP_TX       | Send packet back to the NIC                     |
| XDP_REDIRECT | Send packet to other NIC or socket              |


## Usage

You can use a default value like 0xdeadbeef in your dns packet.
Please be aware, at the current state we are just checking the port == 53.

If you want to test, here is an example:

sudo RUST_LOG=info ./target/release/xdp-user-space run --iface enp5s0 --pattern "0377777706676f6f676c65"

Just use dig www.google.com to trigger the event!

## License

Licensed under either of

 * Apache License, Version 2.0, ([LICENSE-APACHE](LICENSE-APACHE) or http://www.apache.org/licenses/LICENSE-2.0)
 * MIT license ([LICENSE-MIT](LICENSE-MIT) or http://opensource.org/licenses/MIT)

at your option.

### Contribution

Unless you explicitly state otherwise, any contribution intentionally submitted
for inclusion in the work by you, as defined in the Apache-2.0 license, shall be
dual licensed as above, without any additional terms or conditions.

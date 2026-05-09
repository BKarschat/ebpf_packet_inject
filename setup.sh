#!/bin/bash
set -e

echo "1. Nightly + BPF-Target..."
rustup toolchain install nightly --component rust-src
rustup default nightly
rustup target add bpfel-unknown-none

echo "2. BPF-Linker..."
cargo install bpf-linker

echo "3. System deps..."
sudo apt update
sudo apt install -y libbpf-dev linux-headers-$(uname -r) clang llvm

echo "4. Test build..."
cd dns-xdp-ebpf
RUSTFLAGS="-C panic=abort" cargo build --release --target bpfel-unknown-none
cd ..

echo "✅ Fertig! Starte mit: sudo ./dns-xdp-user/target/release/dns-xdp-user run --iface eth1"


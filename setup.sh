#!/bin/bash
set -e

echo "==> Checking for nightly toolchain..."
rustup toolchain install nightly
rustup override set nightly

echo "==> Installing rust-src (required for build-std)"
rustup component add rust-src --toolchain nightly

echo "==> Installing bpf-linker..."
cargo install bpf-linker

echo "==> Building eBPF kernel program..."
cargo +nightly build \
  --package xdp-ebpf \
  --target bpfel-unknown-none \
  -Z build-std=core \
  --release

echo "==> Building user-space program..."
cargo build \
  --package xdp-user-space \
  --release

echo ""
echo "==> Build successful!"
echo ""
echo "Usage:"
echo "  sudo ./target/release/xdp-user-space run --iface <interface>"
echo "  sudo ./target/release/xdp-user-space set-pattern --pattern 'de:ad:be:ef'"
echo ""
echo "Available interfaces:"
ip link show | grep -E '^[0-9]+:' | awk '{print "  " $2}' | tr -d ':'

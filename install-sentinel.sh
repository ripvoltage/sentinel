#!/bin/bash
set -e

echo "Compiling Sentinel eBPF probe..."
cd ebpf-programs
cargo +nightly-2026-05-15 build -Z build-std=core --target bpfel-unknown-none --release
cd ..

echo "Installing eBPF object to /usr/lib/sentinel/..."
sudo mkdir -p /usr/lib/sentinel
sudo cp ebpf-programs/target/bpfel-unknown-none/release/sentinel-ebpf /usr/lib/sentinel/sentinel-ebpf.o

echo "Compiling Sentinel Daemon..."
cargo build --release -p sentinel-daemon

echo ""
echo "✅ Sentinel installed successfully!"
echo "You can now run the daemon using: ./run-sentinel.sh"

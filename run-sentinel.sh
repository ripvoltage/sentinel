#!/bin/bash
set -e

echo "Starting Sentinel Anti-Ransomware Daemon..."
sudo RUST_LOG=info ./target/release/sentinel-daemon

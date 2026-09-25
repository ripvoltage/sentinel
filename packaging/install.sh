#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (e.g. sudo ./install.sh)" >&2
    exit 1
fi

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"

echo "Installing Sentinel Anti-Ransomware..."

install -d /usr/local/bin
install -m 755 "${SCRIPT_DIR}/bin/sentinel" /usr/local/bin/sentinel
if [ -f "${SCRIPT_DIR}/bin/canary_tester" ]; then
    install -m 755 "${SCRIPT_DIR}/bin/canary_tester" /usr/local/bin/canary_tester
fi

install -d /var/log/ransomware-detector
install -d /usr/lib/sentinel
if [ -f "${SCRIPT_DIR}/bin/sentinel-ebpf.o" ]; then
    install -m 644 "${SCRIPT_DIR}/bin/sentinel-ebpf.o" /usr/lib/sentinel/sentinel-ebpf.o
fi

if [ -f "${SCRIPT_DIR}/systemd/sentinel.service" ] && command -v systemctl >/dev/null 2>&1; then
    install -m 644 "${SCRIPT_DIR}/systemd/sentinel.service" /etc/systemd/system/sentinel.service
    systemctl daemon-reload
    echo "Systemd service installed: /etc/systemd/system/sentinel.service"
    echo "To enable and start the daemon, run:"
    echo "  sudo systemctl enable --now sentinel"
else
    echo "Installed binary: /usr/local/bin/sentinel"
    echo "To run manually:"
    echo "  sudo sentinel"
fi

echo "Installation complete."

#!/bin/bash
set -e

if [ "$(id -u)" -ne 0 ]; then
    echo "Error: This script must be run as root (e.g. sudo ./uninstall.sh)" >&2
    exit 1
fi

echo "Uninstalling Sentinel Anti-Ransomware..."

if command -v systemctl >/dev/null 2>&1; then
    systemctl stop sentinel.service 2>/dev/null || true
    systemctl disable sentinel.service 2>/dev/null || true
    rm -f /etc/systemd/system/sentinel.service
    systemctl daemon-reload
fi

rm -f /usr/local/bin/sentinel
rm -f /usr/local/bin/canary_tester

echo "Uninstallation complete. Note: /var/log/ransomware-detector/ preserved for audit records."

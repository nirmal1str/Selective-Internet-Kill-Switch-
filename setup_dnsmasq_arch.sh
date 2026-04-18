#!/usr/bin/env bash
set -euo pipefail

if [[ "${EUID}" -ne 0 ]]; then
  echo "Run this with sudo: sudo ./setup_dnsmasq_arch.sh"
  exit 1
fi

if ! command -v dnsmasq >/dev/null 2>&1; then
  pacman -S --needed dnsmasq
fi

mkdir -p /etc/dnsmasq.d

if [[ ! -f /etc/dnsmasq.conf.aegis.bak ]]; then
  cp /etc/dnsmasq.conf /etc/dnsmasq.conf.aegis.bak
fi

if ! grep -q '^conf-dir=/etc/dnsmasq.d' /etc/dnsmasq.conf; then
  printf '\n# Aegis Selective Internet Kill Switch\nconf-dir=/etc/dnsmasq.d,*.conf\n' >> /etc/dnsmasq.conf
fi

touch /etc/dnsmasq.d/aegis-block.conf

systemctl enable --now dnsmasq
systemctl restart dnsmasq

echo "dnsmasq is ready for Aegis."
echo "Make sure your system resolver points to 127.0.0.1 for DNS sinkhole rules to affect browser traffic."

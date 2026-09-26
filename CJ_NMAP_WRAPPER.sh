#!/bin/sh
set -eu

real_nmap="${CJ_NMAP_REAL:-/usr/bin/nmap}"

if [ ! -x "$real_nmap" ]; then
  echo "CJ-Netlink: real Nmap binary not found at $real_nmap" >&2
  echo "Run cj-kali-setup to install Nmap." >&2
  exit 127
fi

auto_connect=0
if [ "$(id -u)" = "0" ]; then
  auto_connect=1
  for arg in "$@"; do
    case "$arg" in
      -sS|-sT|-sA|-sF|-sN|-sX|-sM|-sW|-sU|-sY|-sZ|-sO|-sn|-sL|-O|--traceroute|--iflist|--version|-V|-h|--help|--script-help|--script-updatedb|-PE|-PP|-PM|-PO*|-PU*|-PA*|-PS*|-PY*)
        auto_connect=0
        break
        ;;
    esac
  done
fi

if [ "$auto_connect" -eq 1 ]; then
  exec "$real_nmap" -sT "$@"
fi

exec "$real_nmap" "$@"

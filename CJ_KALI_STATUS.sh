#!/bin/sh

full=0
case "${1:-}" in
  "")
    ;;
  -f|--full)
    full=1
    ;;
  -h|--help)
    echo "usage: cj-kali-status [--full]"
    echo "  default  concise iPhone networking/tool status"
    echo "  --full   include all interfaces, routes, listeners, and Nmap iflist"
    exit 0
    ;;
  *)
    echo "usage: cj-kali-status [--full]" >&2
    exit 2
    ;;
esac

echo "CJ-Netlink compatibility status"
echo "=============================="
echo

echo "[system]"
uname -a 2>/dev/null || true
printf "Alpine: "
cat /etc/alpine-release 2>/dev/null || echo "unknown"
echo

echo "[active routes]"
if command -v ip >/dev/null 2>&1; then
  printf "IPv4: "
  ip route get 1.1.1.1 2>/dev/null || echo "unavailable"
  printf "IPv6: "
  ip -6 route get 2606:4700:4700::1111 2>/dev/null || echo "unavailable"
  echo
  echo "Defaults:"
  ip -4 route 2>/dev/null | grep '^default' || true
  ip -6 route 2>/dev/null | grep '^default' || true
else
  /bin/busybox route -n 2>/dev/null || true
fi
echo

echo "[socket summary]"
if command -v ss >/dev/null 2>&1; then
  ss -s 2>/dev/null || true
else
  echo "ss not installed"
fi
echo

echo "[Nmap mode]"
if [ "$(command -v nmap 2>/dev/null || true)" = "/usr/local/bin/nmap" ] && [ -x /usr/bin/cj-nmap-wrapper ]; then
  echo "CJ-Netlink connect-scan default wrapper active"
else
  echo "system Nmap command active"
fi
if command -v nmap >/dev/null 2>&1; then
  if [ -f /usr/share/nmap/nse_main.lua ]; then
    echo "NSE: ready"
  else
    echo "NSE: nse_main.lua missing"
  fi
fi
echo

echo "[tooling]"
for tool in nmap ip ss ssh python3 git curl wget nc openssl; do
  if command -v "$tool" >/dev/null 2>&1; then
    printf "%-9s %s\n" "$tool" "installed"
  else
    printf "%-9s %s\n" "$tool" "not installed"
  fi
done
echo

extended_present=0
for tool in socat tcpdump tmux tree lsof rsync strace mtr whois; do
  if command -v "$tool" >/dev/null 2>&1; then
    extended_present=1
    break
  fi
done
if [ "$extended_present" -eq 1 ]; then
  echo "[extended tooling]"
  for tool in socat tcpdump tmux tree lsof rsync strace mtr whois; do
    if command -v "$tool" >/dev/null 2>&1; then
      printf "%-9s %s\n" "$tool" "installed"
    else
      printf "%-9s %s\n" "$tool" "not installed"
    fi
  done
  echo
fi

if [ "$full" -eq 1 ]; then
  echo "[interfaces]"
  if command -v ip >/dev/null 2>&1; then
    ip addr 2>/dev/null || true
  else
    /bin/busybox ifconfig -a 2>/dev/null || true
  fi
  echo

  echo "[IPv4 routes]"
  if command -v ip >/dev/null 2>&1; then
    ip -4 route 2>/dev/null || true
  else
    /bin/busybox route -n 2>/dev/null || true
  fi
  echo

  echo "[IPv6 routes]"
  if command -v ip >/dev/null 2>&1; then
    ip -6 route 2>/dev/null || true
  fi
  echo

  echo "[TCP listeners]"
  if command -v ss >/dev/null 2>&1; then
    ss -ltnp 2>/dev/null || true
  fi
  echo

  if command -v nmap >/dev/null 2>&1; then
    echo "[Nmap interfaces/routes]"
    nmap --iflist 2>&1 || true
    echo
  fi
fi

echo "Status complete."

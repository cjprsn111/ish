#!/bin/sh

echo "CJ-Netlink compatibility status"
echo "=============================="
echo

echo "[system]"
uname -a 2>/dev/null || true
printf "Alpine: "
cat /etc/alpine-release 2>/dev/null || echo "unknown"
echo

echo "[interfaces]"
if command -v ip >/dev/null 2>&1; then
  ip -brief addr 2>/dev/null || ip addr 2>/dev/null || true
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

echo "[route lookup]"
if command -v ip >/dev/null 2>&1; then
  ip route get 1.1.1.1 2>/dev/null || true
else
  echo "iproute2 not installed"
fi
echo

echo "[socket summary]"
if command -v ss >/dev/null 2>&1; then
  ss -s 2>/dev/null || true
  echo
  ss -ltnp 2>/dev/null || true
else
  echo "ss not installed"
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

if command -v nmap >/dev/null 2>&1; then
  echo "[Nmap NSE]"
  if [ -f /usr/share/nmap/nse_main.lua ]; then
    echo "nse_main.lua present"
  else
    echo "nse_main.lua missing"
  fi
  echo

  echo "[Nmap interfaces/routes]"
  nmap --iflist 2>&1 || true
  echo
fi

echo "Status complete."

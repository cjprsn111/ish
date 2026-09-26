#!/bin/sh
set -eu

if [ "$(id -u)" != "0" ]; then
  echo "CJ Kali setup must be run as root inside iSH." >&2
  exit 1
fi

release="$(cat /etc/alpine-release 2>/dev/null || true)"
case "$release" in
  [0-9]*.[0-9]*)
    alpine_minor="$(printf '%s\n' "$release" | awk -F. '{print $1 "." $2}')"
    ;;
  *)
    echo "Unable to determine Alpine release from /etc/alpine-release." >&2
    exit 1
    ;;
esac

repo_file=/etc/apk/repositories
backup_file=/etc/apk/repositories.cj-backup

if [ -f "$repo_file" ] && grep -q 'apk\.ish\.app' "$repo_file"; then
  if [ ! -f "$backup_file" ]; then
    cp "$repo_file" "$backup_file"
    echo "Saved original repositories to $backup_file"
  fi
  printf '%s\n' \
    "https://dl-cdn.alpinelinux.org/alpine/v${alpine_minor}/main" \
    "https://dl-cdn.alpinelinux.org/alpine/v${alpine_minor}/community" \
    > "$repo_file"
  echo "Using official Alpine v${alpine_minor} repositories."
fi

update_ok=0
for attempt in 1 2 3; do
  echo "Refreshing Alpine indexes (attempt $attempt/3)..."
  if apk update; then
    update_ok=1
    break
  fi
  echo "Repository refresh was incomplete; retrying in 2 seconds..."
  sleep 2
done

if [ "$update_ok" -ne 1 ]; then
  echo "WARNING: repository refresh did not fully succeed."
  echo "Continuing with any usable cached indexes; package installation will be retried."
fi

install_group() {
  group_name="$1"
  shift

  attempt=1
  while [ "$attempt" -le 3 ]; do
    echo "Installing $group_name (attempt $attempt/3)..."
    if apk add "$@"; then
      return 0
    fi
    attempt=$((attempt + 1))
    if [ "$attempt" -le 3 ]; then
      echo "$group_name was incomplete; retrying in 3 seconds..."
      sleep 3
    fi
  done

  echo "Failed to install $group_name after 3 attempts." >&2
  return 1
}

install_group "network toolkit" \
  bind-tools \
  curl \
  iproute2 \
  iproute2-ss \
  netcat-openbsd \
  nmap \
  nmap-scripts \
  openssh-client \
  openssl \
  wget

install_group "shell and scripting toolkit" \
  bash \
  coreutils \
  findutils \
  gawk \
  git \
  grep \
  jq \
  less \
  nano \
  procps \
  py3-pip \
  python3 \
  sed \
  vim

if [ -x /usr/bin/cj-nmap-wrapper ]; then
  mkdir -p /usr/local/bin
  cp /usr/bin/cj-nmap-wrapper /usr/local/bin/nmap
  chmod 0755 /usr/local/bin/nmap
  echo "Installed CJ-Netlink Nmap compatibility wrapper."
fi

missing=0
for tool in nmap ip ss ssh python3 git curl wget nc openssl; do
  if ! command -v "$tool" >/dev/null 2>&1; then
    echo "Missing required command after setup: $tool" >&2
    missing=1
  fi
done
if [ ! -f /usr/share/nmap/nse_main.lua ]; then
  echo "Missing Nmap NSE runtime: /usr/share/nmap/nse_main.lua" >&2
  missing=1
fi
if [ "$missing" -ne 0 ]; then
  echo "Setup is incomplete. Run cj-kali-setup again when the network is stable." >&2
  exit 1
fi

echo
echo "CJ Kali-like userspace toolkit installed."
echo "Network/kernel features are still limited by the iOS sandbox."
echo
printf 'ip:      '; ip -V 2>/dev/null || true
printf 'nmap:    '; nmap --version 2>/dev/null | head -1 || true
printf 'python:  '; python3 --version 2>/dev/null || true
printf 'ssh:     '; ssh -V 2>&1 | head -1 || true
printf 'curl:    '; curl --version 2>/dev/null | head -1 || true

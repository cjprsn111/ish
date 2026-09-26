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

install_toolkit() {
  apk add \
  bash \
  bind-tools \
  coreutils \
  curl \
  findutils \
  gawk \
  git \
  grep \
  iproute2 \
  iproute2-ss \
  jq \
  less \
  nano \
  netcat-openbsd \
  nmap \
  nmap-scripts \
  openssh-client \
  openssl \
  procps \
  py3-pip \
  python3 \
  sed \
  vim \
  wget
}

install_ok=0
for attempt in 1 2 3; do
  echo "Installing CJ Kali-like toolkit (attempt $attempt/3)..."
  if install_toolkit; then
    install_ok=1
    break
  fi
  echo "Package installation was incomplete; retrying in 3 seconds..."
  sleep 3
done

if [ "$install_ok" -ne 1 ]; then
  echo "CJ Kali-like toolkit installation did not complete after 3 attempts." >&2
  echo "Run cj-kali-setup again when the network is stable." >&2
  exit 1
fi

if [ -x /usr/bin/cj-nmap-wrapper ]; then
  mkdir -p /usr/local/bin
  cp /usr/bin/cj-nmap-wrapper /usr/local/bin/nmap
  chmod 0755 /usr/local/bin/nmap
  echo "Installed CJ-Netlink Nmap compatibility wrapper."
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

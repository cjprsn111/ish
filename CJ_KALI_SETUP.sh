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

apk update

apk add --no-cache \
  bash \
  bind-tools \
  coreutils \
  curl \
  findutils \
  gawk \
  git \
  grep \
  iproute2 \
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

echo
echo "CJ Kali-like userspace toolkit installed."
echo "Network/kernel features are still limited by the iOS sandbox."
echo
printf 'ip:      '; ip -V 2>/dev/null || true
printf 'nmap:    '; nmap --version 2>/dev/null | head -1 || true
printf 'python:  '; python3 --version 2>/dev/null || true
printf 'ssh:     '; ssh -V 2>&1 | head -1 || true
printf 'curl:    '; curl --version 2>/dev/null | head -1 || true

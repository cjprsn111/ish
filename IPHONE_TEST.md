# CJ-Netlink iPhone Test Checklist

This checklist is for the unsigned CJ-Netlink iPhone candidate produced by `.github/workflows/ios-test-build.yml`.

## Before installation

The GitHub Actions artifact must contain:

- `CJ-Netlink-iSH-unsigned.ipa`
- `CJ-Netlink-iSH-unsigned.ipa.sha256`
- `CJ-Netlink-build-info.txt`
- `CJ_KALI_SETUP.sh`
- `CJ_KALI_STATUS.sh`
- `CJ_NMAP_WRAPPER.sh`

The workflow verifies that both the main iSH executable and the File Provider extension are arm64-only and that the app is unsigned. The IPA must be signed with a valid Apple development/distribution identity before iOS will install it.

## First launch

After signing and installing the candidate on an iPhone:

1. Launch iSH and confirm the Alpine shell reaches a prompt.
2. Confirm normal filesystem access and basic commands still work.
3. Run `cj-kali-status` and confirm the bundled compatibility helper starts normally.
4. Record the CJ-Netlink commit from `CJ-Netlink-build-info.txt` so results can be tied to the exact source revision.

## Networking smoke test

Inside iSH, run the one-time toolkit bootstrap first:

```sh
cj-kali-setup
```

The bootstrap installs iproute2, Nmap, the Nmap NSE script package, SSH, Git, Python, curl/wget, netcat, OpenSSL, and other common command-line tools. It also applies the official Alpine mirror workaround automatically when the bundled iSH repository is the active source.

Then run:

```sh
cj-kali-status
ip addr
ip link
ip -4 route
ip -6 route
ip route get 1.1.1.1
ip route get 127.0.0.1
ip -6 route get ::1
```

If the bundled `apk.ish.app` repository stalls at `APKINDEX.tar.gz` and the bootstrap cannot recover automatically, preserve the original repository list and use the matching official Alpine v3.19 repositories for the test session:

```sh
cp /etc/apk/repositories /etc/apk/repositories.cj-backup
printf '%s\n' \
  'https://dl-cdn.alpinelinux.org/alpine/v3.19/main' \
  'https://dl-cdn.alpinelinux.org/alpine/v3.19/community' \
  > /etc/apk/repositories
apk update
```

Expected behavior:

- `ip addr` and `ip link` complete without Netlink or ioctl compatibility errors.
- IPv4 and IPv6 route dumps do not mix address families.
- Route lookups return the queried destination plus a usable `dev` and `src` where a route exists.
- Loopback lookups resolve through `lo`.

## Nmap interface and TCP-connect smoke test

Run:

```sh
test -f /usr/share/nmap/nse_main.lua
nmap -d --iflist
nmap -sT -Pn -n -p 22,80,443 127.0.0.1
```

`nmap -d --iflist` should enumerate the real iPhone interfaces instead of reporting `getinterfaces_dnet: intf_loop() failed`. It should also show connected routes and a host-selected default route when the host has one.

The `nse_main.lua` check verifies that `-sC`/default NSE scripts are available instead of failing during script-engine initialization. After `cj-kali-setup`, CJ-Netlink installs an Nmap wrapper in `/usr/local/bin/nmap` that adds `-sT` only when root-mode Nmap would otherwise silently choose its raw SYN default. Explicit scan modes such as `-sS`, `-sU`, or `-sT` are left untouched. The TCP-connect scan must complete without `socket_bindtodevice` compatibility errors. Port state depends on services and iOS policy on the installed device, so the key device-test requirement is that the scan completes normally and reports the host.

## Validated cellular checkpoint

Validated on a non-jailbroken iPhone over cellular/5G:

- `ip route get 1.1.1.1` selects the active `pdp_ip0` cellular interface and a matching real source address.
- IPv4 and IPv6 default routes are exposed through the host-selected active interface without inventing gateway data.
- `nmap --iflist` enumerates the real iOS interfaces and sees the host-selected default route.
- `nmap -sT -sV -sC -Pn -n -p 22,80,443 127.0.0.1` completes successfully, confirming TCP-connect scanning, service detection, and NSE script loading together.
- `ss -ltnp` maps a guest BusyBox listener back to its guest PID and file descriptor through the CJ-Netlink procfs socket tables.

The next candidate also removes the noisy `NETLINK_SOCK_DIAG` open warning, reports TCP listeners as `LISTEN`, and installs the CJ Nmap wrapper so commands that would otherwise silently choose root-mode SYN scanning default to `-sT` on stock iOS.

## Real-device observations to capture

Record:

- Output from each `ip` command above.
- Any warnings printed to stderr.
- Interface names and addresses exposed by iOS.
- Whether a default route/gateway is shown.
- Nmap completion and any socket errors.
- Whether behavior changes between Wi-Fi and cellular.

For a cellular-focused validation, turn Wi-Fi off and confirm:

```sh
ip route get 1.1.1.1
```

selects the active `pdp_ip*` interface and a matching source address. A point-to-point cellular route does not require a traditional `via <gateway>` value; do not treat a missing gateway as a failure unless iOS actually exposes one.

Do not use this test build to scan systems you do not own or have permission to test.

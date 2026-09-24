# CJ-Netlink iPhone Test Checklist

This checklist is for the unsigned CJ-Netlink iPhone candidate produced by `.github/workflows/ios-test-build.yml`.

## Before installation

The GitHub Actions artifact must contain:

- `CJ-Netlink-iSH-unsigned.ipa`
- `CJ-Netlink-iSH-unsigned.ipa.sha256`
- `CJ-Netlink-build-info.txt`

The workflow verifies that both the main iSH executable and the File Provider extension are arm64-only and that the app is unsigned. The IPA must be signed with a valid Apple development/distribution identity before iOS will install it.

## First launch

After signing and installing the candidate on an iPhone:

1. Launch iSH and confirm the Alpine shell reaches a prompt.
2. Confirm normal filesystem access and basic commands still work.
3. Record the CJ-Netlink commit from `CJ-Netlink-build-info.txt` so results can be tied to the exact source revision.

## Networking smoke test

Inside iSH, run:

```sh
apk update
apk add iproute2 nmap

ip addr
ip link
ip -4 route
ip -6 route
ip route get 1.1.1.1
ip route get 127.0.0.1
ip -6 route get ::1
```

Expected behavior:

- `ip addr` and `ip link` complete without Netlink or ioctl compatibility errors.
- IPv4 and IPv6 route dumps do not mix address families.
- Route lookups return the queried destination plus a usable `dev` and `src` where a route exists.
- Loopback lookups resolve through `lo`.

## Nmap TCP-connect smoke test

Run:

```sh
nmap -sT -Pn -n -p 22,80,443 127.0.0.1
```

The scan must complete without `socket_bindtodevice` compatibility errors. Port state depends on services running inside the installed image, so the key device-test requirement is that the scan completes normally and reports the host.

## Real-device observations to capture

Record:

- Output from each `ip` command above.
- Any warnings printed to stderr.
- Interface names and addresses exposed by iOS.
- Whether a default route/gateway is shown.
- Nmap completion and any socket errors.
- Whether behavior changes between Wi-Fi and cellular.

Do not use this test build to scan systems you do not own or have permission to test.

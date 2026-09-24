# CJ Netlink Development

This branch is a development experiment to add virtual Linux `NETLINK_ROUTE` support to iSH so standard Linux networking tools can work against an iOS/Darwin host without a native Linux Netlink socket.

## Current milestone

The virtual route socket now covers `RTM_GETLINK`, `RTM_GETADDR`, connected `RTM_GETROUTE` dumps, host-selected IPv4/IPv6 default-route synthesis, IPv4/IPv6 family filtering, and IPv4/IPv6 route lookups with destination, output-interface, and preferred-source attributes. Multipart dumps use a Linux-compatible `NLMSG_DONE` status payload.

Compatibility shims cover the interface transmit-queue ioctl used by `ip`, `SIOCGIFNAME` index-to-name translation used by musl/iproute2, and Linux `SO_BINDTODEVICE`. Apple hosts translate interface binding to the platform per-family socket option when available.

Netlink E2E validates both BusyBox `ip` and full iproute2, including `ip addr`, `ip link`, IPv4/IPv6 route dumps, synthesized IPv4 default-route output, public IPv4 route lookup, IPv4 loopback lookup, IPv6 loopback lookup, interface-name resolution, repeated request stress, Nmap TCP-connect scanning, and repeated Nmap socket lifecycle stress.

The CJ-Netlink iPhone Candidate workflow also builds an unsigned arm64 iPhone IPA, verifies the main app and File Provider binaries are arm64-only, verifies the bundle is unsigned before handoff, records build metadata/checksums, and uploads the candidate artifact. See `IPHONE_TEST.md` for the real-device checklist.

## Remaining work

- Validate host-backed interface, default-route, route-lookup, and Nmap behavior on a real iPhone/iOS runtime over Wi-Fi and cellular.
- Improve route-dump fidelity with gateway reporting where Darwin/iOS exposes it safely and consistently.
- Continue rtnetlink error/edge-case compatibility and regression coverage.
- Sign/sideload a validated candidate for real-device testing without modifying `master`.

Keep changes isolated on `CJ-Netlink`, preserve the latest green baseline, and validate source changes with Netlink E2E, the iPhone candidate build when source changes affect the app, and full cross-platform CI.

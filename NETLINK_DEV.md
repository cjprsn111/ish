# CJ Netlink Development

This branch is a development experiment to add virtual Linux `NETLINK_ROUTE` support to iSH so standard Linux networking tools can work against an iOS/Darwin host without a native Linux Netlink socket.

## Current milestone

The virtual route socket now covers `RTM_GETLINK`, family-aware `RTM_GETADDR` dumps, connected `RTM_GETROUTE` dumps, host-selected IPv4/IPv6 default-route synthesis, IPv4/IPv6 route-family filtering, and IPv4/IPv6 route lookups with destination, output-interface, and preferred-source attributes. On Darwin/iOS, default-route synthesis can also read the public PF_ROUTE/sysctl routing ABI and attach the real gateway when the operating system exposes one.

Multipart dumps use a Linux-compatible `NLMSG_DONE` status payload. Valid Netlink requests that fail at the protocol layer now return Linux-style `NLMSG_ERROR` responses; unsupported rtnetlink mutations are accepted by sendmsg and rejected asynchronously with the expected `RTNETLINK answers: Not supported` behavior.

Compatibility shims cover the interface transmit-queue ioctl used by `ip`, `SIOCGIFNAME` index-to-name translation used by musl/iproute2, and Linux `SO_BINDTODEVICE`. Apple hosts translate interface binding to the platform per-family socket option when available.

Netlink E2E validates both BusyBox `ip` and full iproute2, including `ip addr`, explicit IPv4/IPv6 address dumps, `ip link`, IPv4/IPv6 route dumps, synthesized IPv4 default-route output, public IPv4 route lookup, IPv4 loopback lookup, IPv6 loopback lookup, real interface-name resolution, Linux-style mutation error handling, repeated request stress, Nmap TCP-connect scanning, and repeated Nmap socket lifecycle stress.

The CJ-Netlink iPhone Candidate workflow builds an unsigned arm64 iPhone IPA, verifies the main app and File Provider binaries are arm64-only, verifies the bundle is unsigned before handoff, records build metadata/checksums, and uploads the candidate artifact. See `IPHONE_TEST.md` for the real-device checklist.

## Remaining work

- Validate host-backed interface, gateway, default-route, route-lookup, and Nmap behavior on a real iPhone/iOS runtime over Wi-Fi and cellular.
- Confirm the Darwin PF_ROUTE gateway parser against real iPhone route-table records; gracefully omitting `RTA_GATEWAY` remains the fallback when iOS does not expose a usable gateway.
- Continue rtnetlink ACK/error/edge-case compatibility and regression coverage.
- Expand Nmap/network-tool testing beyond the current TCP-connect smoke path where iOS sandbox restrictions allow it.
- Sign/sideload a validated candidate for real-device testing without modifying `master`.

Keep changes isolated on `CJ-Netlink`, preserve the latest green baseline, and validate source changes with Netlink E2E, the iPhone candidate build when source changes affect the app, and full cross-platform CI.

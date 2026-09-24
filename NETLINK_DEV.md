# CJ Netlink Development

This branch is a development experiment to add virtual Linux `NETLINK_ROUTE` support to iSH so standard Linux networking tools can work against an iOS/Darwin host without a native Linux Netlink socket.

## Current milestone

The virtual route socket now covers `RTM_GETLINK`, `RTM_GETADDR`, connected `RTM_GETROUTE` dumps, IPv4/IPv6 family filtering, and IPv4/IPv6 route lookups with destination, output-interface, and preferred-source attributes. Multipart dumps use a Linux-compatible `NLMSG_DONE` status payload.

Compatibility shims also cover the interface transmit-queue ioctl used by `ip` and Linux `SO_BINDTODEVICE`, with Apple hosts translating interface binding to the platform per-family socket option when available.

Netlink E2E validates both BusyBox `ip` and full iproute2, including `ip addr`, `ip link`, `ip route`, `ip -4 route`, `ip -6 route`, public IPv4 route lookup, IPv4 loopback lookup, IPv6 loopback lookup, repeated request stress, Nmap TCP-connect scanning, and repeated Nmap socket lifecycle stress.

## Remaining work

- Validate the host-backed interface and route representation on a real iPhone/iOS runtime.
- Improve route-dump fidelity beyond connected routes, including default-route/gateway reporting where it can be represented safely on Darwin/iOS.
- Continue rtnetlink error/edge-case compatibility and regression coverage.
- Produce and validate an installable iPhone test candidate without modifying `master`.

Keep changes isolated on `CJ-Netlink`, preserve the latest green baseline, and validate source changes with Netlink E2E plus full cross-platform CI.

# CJ Netlink Development

This branch is a development experiment to add virtual Linux NETLINK_ROUTE support to iSH so Linux networking tools can progress beyond AF_NETLINK socket creation on iOS.

Current milestone: RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, IPv4/IPv6 route lookups, and repeated Nmap TCP-connect scans are covered by the Netlink E2E workflow. Continue compatibility hardening while preserving the green baseline.

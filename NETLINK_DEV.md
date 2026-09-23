# CJ Netlink Development

This branch is a development experiment to add virtual Linux NETLINK_ROUTE support to iSH so Linux networking tools can progress beyond AF_NETLINK socket creation on iOS.

Current milestone: RTM_GETLINK, RTM_GETADDR, RTM_GETROUTE, IPv4/IPv6 route lookups, and repeated Nmap TCP-connect scans are covered by the Netlink E2E workflow. Continue compatibility hardening while preserving the green baseline.

Next route-query compatibility fix: `netlink_build_route_query()` already parses the request's `RTA_DST` into `dst` and preserves `rtm_dst_len`, but its `RTM_NEWROUTE` reply currently emits only `RTA_OIF` and `RTA_PREFSRC`. Add the queried destination back as `RTA_DST` before those attributes, then tighten Netlink E2E to require `ip route get 1.1.1.1`, `127.0.0.1`, and `ip -6 route get ::1` to echo their requested destination instead of accepting the current `0/32` or `0/128` display. Keep this change isolated from route dumps and preserve the green Nmap stress baseline.

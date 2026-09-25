#include <arpa/inet.h>
#include <fcntl.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <netinet/tcp.h>
#include <poll.h>
#include <string.h>
#include <sys/ioctl.h>
#include <sys/socket.h>
#include <sys/stat.h>
#include <sys/un.h>
#ifdef __APPLE__
#include <net/if_dl.h>
#include <sys/sysctl.h>
#else
#include <linux/if_link.h>
#include <netpacket/packet.h>
#endif
#include "kernel/calls.h"
#include "fs/fd.h"
#include "fs/inode.h"
#include "fs/path.h"
#include "fs/real.h"
#include "fs/sock.h"
#include "debug.h"

#define SOCKET_TYPE_MASK 0xf
#define SO_BINDTODEVICE_ 25

const struct fd_ops socket_fdops;

static lock_t peer_lock = LOCK_INITIALIZER;
static lock_t socket_inode_lock = LOCK_INITIALIZER;
static ino_t socket_inode_next = 0x100000;

static int is_netlink_route(const struct fd *fd) {
    return fd->socket.domain == AF_NETLINK_ && fd->socket.protocol == NETLINK_ROUTE_;
}

#define NL_ALIGN(n) (((n) + 3u) & ~3u)

struct netlink_builder {
    uint8_t *data;
    size_t len;
    size_t cap;
};

static int netlink_reserve(struct netlink_builder *b, size_t need) {
    if (need <= b->cap)
        return 0;
    size_t cap = b->cap ? b->cap : 1024;
    while (cap < need)
        cap *= 2;
    uint8_t *data = realloc(b->data, cap);
    if (data == NULL)
        return _ENOMEM;
    b->data = data;
    b->cap = cap;
    return 0;
}

static size_t netlink_start_msg(struct netlink_builder *b, uint16_t type,
        uint16_t flags, uint32_t seq, size_t payload_len) {
    size_t start = NL_ALIGN(b->len);
    size_t raw_len = sizeof(struct nlmsghdr_) + payload_len;
    size_t end = start + NL_ALIGN(raw_len);
    if (netlink_reserve(b, end) < 0)
        return SIZE_MAX;
    memset(b->data + b->len, 0, end - b->len);
    struct nlmsghdr_ *hdr = (void *) (b->data + start);
    hdr->len = raw_len;
    hdr->type = type;
    hdr->flags = flags;
    hdr->seq = seq;
    hdr->pid = 0;
    b->len = end;
    return start;
}

static void *netlink_payload(struct netlink_builder *b, size_t start) {
    return b->data + start + sizeof(struct nlmsghdr_);
}

static int netlink_add_attr(struct netlink_builder *b, size_t start,
        uint16_t type, const void *data, size_t data_len) {
    struct nlmsghdr_ *hdr = (void *) (b->data + start);
    size_t pos = start + NL_ALIGN(hdr->len);
    size_t attr_len = sizeof(struct rtattr_) + data_len;
    size_t end = pos + NL_ALIGN(attr_len);
    int err = netlink_reserve(b, end);
    if (err < 0)
        return err;
    memset(b->data + b->len, 0, end - b->len);
    struct rtattr_ *attr = (void *) (b->data + pos);
    attr->len = attr_len;
    attr->type = type;
    memcpy(attr + 1, data, data_len);
    hdr = (void *) (b->data + start);
    // Linux advances nlmsg_len to the aligned end of each rtattr. The rtattr
    // itself keeps its unaligned payload length in rta_len.
    hdr->len = end - start;
    b->len = end;
    return 0;
}

static void netlink_clear_response(struct fd *fd) {
    free(fd->socket.netlink_response);
    fd->socket.netlink_response = NULL;
    fd->socket.netlink_response_len = 0;
    fd->socket.netlink_pending = 0;
}

static int netlink_commit_response(struct fd *fd, struct netlink_builder *b) {
    // Linux route-netlink replies come from kernel pid 0 in sockaddr_nl, but
    // nlmsg_pid identifies the destination port ID. BusyBox/iproute2 checks
    // that this matches the value returned by getsockname().
    size_t off = 0;
    while (off + sizeof(struct nlmsghdr_) <= b->len) {
        struct nlmsghdr_ *hdr = (void *) (b->data + off);
        if (hdr->len < sizeof(*hdr) || off + hdr->len > b->len)
            break;
        hdr->pid = fd->socket.netlink_pid != 0
            ? fd->socket.netlink_pid : (uint32_t) current->pid;
        off += NL_ALIGN(hdr->len);
    }

    netlink_clear_response(fd);
    fd->socket.netlink_response = b->data;
    fd->socket.netlink_response_len = b->len;
    fd->socket.netlink_pending = b->len != 0;
    b->data = NULL;
    b->len = b->cap = 0;
    return 0;
}

static int netlink_add_done(struct netlink_builder *b, uint32_t seq) {
    // Linux rtnetlink terminates multipart dumps with NLMSG_DONE carrying
    // a 32-bit status value. BusyBox tolerates a header-only DONE message,
    // but full iproute2 treats it as a truncated dump.
    size_t start = netlink_start_msg(b, NLMSG_DONE_, NLM_F_MULTI_, seq,
            sizeof(int32_t));
    if (start == SIZE_MAX)
        return _ENOMEM;
    *(int32_t *) netlink_payload(b, start) = 0;
    return 0;
}

static int netlink_add_error(struct netlink_builder *b,
        const struct nlmsghdr_ *request, int error) {
    // Linux NLMSG_ERROR carries a signed errno followed by the header of the
    // request that caused it. A zero errno is an ACK; negative values are
    // normal Netlink errors such as -EOPNOTSUPP.
    size_t payload_len = sizeof(int32_t) + sizeof(struct nlmsghdr_);
    size_t start = netlink_start_msg(b, NLMSG_ERROR_, 0, request->seq,
            payload_len);
    if (start == SIZE_MAX)
        return _ENOMEM;

    uint8_t *payload = netlink_payload(b, start);
    int32_t nlerr = error;
    memcpy(payload, &nlerr, sizeof(nlerr));
    memcpy(payload + sizeof(nlerr), request, sizeof(*request));
    return 0;
}

static uint32_t netlink_linux_if_flags(unsigned host_flags) {
    uint32_t flags = 0;
#ifdef IFF_UP
    if (host_flags & IFF_UP) flags |= 0x1;
#endif
#ifdef IFF_BROADCAST
    if (host_flags & IFF_BROADCAST) flags |= 0x2;
#endif
#ifdef IFF_LOOPBACK
    if (host_flags & IFF_LOOPBACK) flags |= 0x8;
#endif
#ifdef IFF_POINTOPOINT
    if (host_flags & IFF_POINTOPOINT) flags |= 0x10;
#endif
#ifdef IFF_RUNNING
    if (host_flags & IFF_RUNNING) flags |= 0x40;
#endif
#ifdef IFF_NOARP
    if (host_flags & IFF_NOARP) flags |= 0x80;
#endif
#ifdef IFF_PROMISC
    if (host_flags & IFF_PROMISC) flags |= 0x100;
#endif
#ifdef IFF_ALLMULTI
    if (host_flags & IFF_ALLMULTI) flags |= 0x200;
#endif
#ifdef IFF_MULTICAST
    if (host_flags & IFF_MULTICAST) flags |= 0x1000;
#endif
    return flags;
}

static size_t netlink_hwaddr(struct ifaddrs *ifap, const char *name,
        uint8_t *addr, size_t cap) {
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || strcmp(ifa->ifa_name, name) != 0)
            continue;
#ifdef __APPLE__
        if (ifa->ifa_addr->sa_family == AF_LINK) {
            struct sockaddr_dl *sdl = (void *) ifa->ifa_addr;
            size_t len = sdl->sdl_alen;
            if (len > cap) len = cap;
            memcpy(addr, LLADDR(sdl), len);
            return len;
        }
#else
        if (ifa->ifa_addr->sa_family == AF_PACKET) {
            struct sockaddr_ll *sll = (void *) ifa->ifa_addr;
            size_t len = sll->sll_halen;
            if (len > cap) len = cap;
            memcpy(addr, sll->sll_addr, len);
            return len;
        }
#endif
    }
    return 0;
}

static int netlink_link_mtu(struct ifaddrs *ifap, const char *name,
        uint32_t *mtu) {
#ifdef __APPLE__
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || strcmp(ifa->ifa_name, name) != 0 ||
                ifa->ifa_data == NULL)
            continue;
        const struct if_data *data = ifa->ifa_data;
        if (data->ifi_mtu != 0) {
            *mtu = data->ifi_mtu;
            return 1;
        }
    }
#else
    int fd = socket(AF_INET, SOCK_DGRAM, 0);
    if (fd >= 0) {
        struct ifreq ifr = {};
        strncpy(ifr.ifr_name, name, sizeof(ifr.ifr_name) - 1);
        if (ioctl(fd, SIOCGIFMTU, &ifr) == 0 && ifr.ifr_mtu > 0) {
            *mtu = (uint32_t) ifr.ifr_mtu;
            close(fd);
            return 1;
        }
        close(fd);
    }
#endif
    return 0;
}

static int netlink_link_stats(struct ifaddrs *ifap, const char *name,
        struct rtnl_link_stats_ *stats) {
    memset(stats, 0, sizeof(*stats));

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || strcmp(ifa->ifa_name, name) != 0 ||
                ifa->ifa_data == NULL)
            continue;
#ifdef __APPLE__
        struct if_data *data = ifa->ifa_data;
        stats->rx_packets = data->ifi_ipackets;
        stats->tx_packets = data->ifi_opackets;
        stats->rx_bytes = data->ifi_ibytes;
        stats->tx_bytes = data->ifi_obytes;
        stats->rx_errors = data->ifi_ierrors;
        stats->tx_errors = data->ifi_oerrors;
        stats->rx_dropped = data->ifi_iqdrops;
        stats->multicast = data->ifi_imcasts;
        stats->collisions = data->ifi_collisions;
        return 1;
#else
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET)
            continue;
        const struct rtnl_link_stats *data = ifa->ifa_data;
        stats->rx_packets = data->rx_packets;
        stats->tx_packets = data->tx_packets;
        stats->rx_bytes = data->rx_bytes;
        stats->tx_bytes = data->tx_bytes;
        stats->rx_errors = data->rx_errors;
        stats->tx_errors = data->tx_errors;
        stats->rx_dropped = data->rx_dropped;
        stats->tx_dropped = data->tx_dropped;
        stats->multicast = data->multicast;
        stats->collisions = data->collisions;
        stats->rx_length_errors = data->rx_length_errors;
        stats->rx_over_errors = data->rx_over_errors;
        stats->rx_crc_errors = data->rx_crc_errors;
        stats->rx_frame_errors = data->rx_frame_errors;
        stats->rx_fifo_errors = data->rx_fifo_errors;
        stats->rx_missed_errors = data->rx_missed_errors;
        stats->tx_aborted_errors = data->tx_aborted_errors;
        stats->tx_carrier_errors = data->tx_carrier_errors;
        stats->tx_fifo_errors = data->tx_fifo_errors;
        stats->tx_heartbeat_errors = data->tx_heartbeat_errors;
        stats->tx_window_errors = data->tx_window_errors;
        stats->rx_compressed = data->rx_compressed;
        stats->tx_compressed = data->tx_compressed;
        return 1;
#endif
    }
    return 0;
}

static unsigned netlink_prefix_bits(const uint8_t *mask, size_t len) {
    unsigned bits = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t b = mask[i];
        for (int bit = 7; bit >= 0; bit--) {
            if (b & (1u << bit))
                bits++;
            else
                return bits;
        }
    }
    return bits;
}

static int netlink_build_links(struct netlink_builder *b, uint32_t seq) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    unsigned seen[128];
    size_t seen_count = 0;
    int err = 0;
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL)
            continue;
        unsigned index = if_nametoindex(ifa->ifa_name);
        if (index == 0)
            continue;
        int duplicate = 0;
        for (size_t i = 0; i < seen_count; i++)
            if (seen[i] == index)
                duplicate = 1;
        if (duplicate)
            continue;
        if (seen_count < sizeof(seen) / sizeof(seen[0]))
            seen[seen_count++] = index;

        size_t start = netlink_start_msg(b, RTM_NEWLINK_, NLM_F_MULTI_, seq,
                sizeof(struct ifinfomsg_));
        if (start == SIZE_MAX) { err = _ENOMEM; break; }
        struct ifinfomsg_ *info = netlink_payload(b, start);
        info->family = 0;
        info->type = (ifa->ifa_flags & IFF_LOOPBACK) ? ARPHRD_LOOPBACK_ :
                     (ifa->ifa_flags & IFF_POINTOPOINT) ? ARPHRD_NONE_ :
                     ARPHRD_ETHER_;
        info->index = index;
        info->flags = netlink_linux_if_flags(ifa->ifa_flags);
        info->change = 0xffffffffu;

        err = netlink_add_attr(b, start, IFLA_IFNAME_,
                ifa->ifa_name, strlen(ifa->ifa_name) + 1);
        if (err < 0) break;

        uint32_t mtu;
        if (netlink_link_mtu(ifap, ifa->ifa_name, &mtu)) {
            err = netlink_add_attr(b, start, IFLA_MTU_, &mtu, sizeof(mtu));
            if (err < 0) break;
        }

        uint8_t operstate = (ifa->ifa_flags & IFF_UP)
            ? ((ifa->ifa_flags & IFF_RUNNING) ? 6 : 0)
            : 2;
        err = netlink_add_attr(b, start, IFLA_OPERSTATE_,
                &operstate, sizeof(operstate));
        if (err < 0) break;

        uint8_t hw[32];
        size_t hwlen = netlink_hwaddr(ifap, ifa->ifa_name, hw, sizeof(hw));
        if (hwlen != 0) {
            err = netlink_add_attr(b, start, IFLA_ADDRESS_, hw, hwlen);
            if (err < 0) break;

            if (ifa->ifa_flags & IFF_BROADCAST) {
                uint8_t broadcast[32];
                memset(broadcast, 0xff, hwlen);
                err = netlink_add_attr(b, start, IFLA_BROADCAST_,
                        broadcast, hwlen);
                if (err < 0) break;
            }
        }

        struct rtnl_link_stats_ stats;
        if (netlink_link_stats(ifap, ifa->ifa_name, &stats)) {
            err = netlink_add_attr(b, start, IFLA_STATS_, &stats, sizeof(stats));
            if (err < 0) break;
        }
    }
    freeifaddrs(ifap);
    return err;
}

static int netlink_build_addrs(struct netlink_builder *b, uint32_t seq,
        uint8_t requested_family) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();
    int err = 0;

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_name == NULL)
            continue;
        int family = ifa->ifa_addr->sa_family;
        if (family != AF_INET && family != AF_INET6)
            continue;
        unsigned index = if_nametoindex(ifa->ifa_name);
        if (index == 0)
            continue;

        size_t addr_len = family == AF_INET ? 4 : 16;
        const void *addr;
        const void *mask = NULL;
        uint8_t fake_family = family == AF_INET ? AF_INET_ : AF_INET6_;
        if (requested_family != 0 && requested_family != fake_family)
            continue;
        uint8_t scope = RT_SCOPE_UNIVERSE_;
        if (family == AF_INET) {
            struct sockaddr_in *sin = (void *) ifa->ifa_addr;
            addr = &sin->sin_addr;
            if (ifa->ifa_netmask)
                mask = &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;
            uint32_t host = ntohl(sin->sin_addr.s_addr);
            if ((host >> 24) == 127)
                scope = RT_SCOPE_HOST_;
            else if ((host >> 16) == 0xa9fe)
                scope = RT_SCOPE_LINK_;
        } else {
            struct sockaddr_in6 *sin6 = (void *) ifa->ifa_addr;
            addr = &sin6->sin6_addr;
            if (ifa->ifa_netmask)
                mask = &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
            if (IN6_IS_ADDR_LOOPBACK(&sin6->sin6_addr))
                scope = RT_SCOPE_HOST_;
            else if (IN6_IS_ADDR_LINKLOCAL(&sin6->sin6_addr))
                scope = RT_SCOPE_LINK_;
        }

        size_t start = netlink_start_msg(b, RTM_NEWADDR_, NLM_F_MULTI_, seq,
                sizeof(struct ifaddrmsg_));
        if (start == SIZE_MAX) { err = _ENOMEM; break; }
        struct ifaddrmsg_ *info = netlink_payload(b, start);
        info->family = fake_family;
        info->prefixlen = mask ? netlink_prefix_bits(mask, addr_len) : addr_len * 8;
        info->scope = scope;
        info->index = index;

        err = netlink_add_attr(b, start, IFA_ADDRESS_, addr, addr_len);
        if (err < 0) break;
        err = netlink_add_attr(b, start, IFA_LOCAL_, addr, addr_len);
        if (err < 0) break;
        err = netlink_add_attr(b, start, IFA_LABEL_,
                ifa->ifa_name, strlen(ifa->ifa_name) + 1);
        if (err < 0) break;

        if (family == AF_INET && ifa->ifa_broadaddr &&
                (ifa->ifa_flags & IFF_BROADCAST)) {
            struct sockaddr_in *bcast = (void *) ifa->ifa_broadaddr;
            err = netlink_add_attr(b, start, IFA_BROADCAST_,
                    &bcast->sin_addr, sizeof(bcast->sin_addr));
            if (err < 0) break;
        }
    }

    freeifaddrs(ifap);
    return err;
}

static int netlink_probe_route(uint8_t fake_family, const void *dst,
        unsigned *ifindex, uint8_t *src) {
    int family = fake_family == AF_INET_ ? AF_INET :
                 fake_family == AF_INET6_ ? AF_INET6 : -1;
    if (family < 0)
        return _EAFNOSUPPORT;

    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return errno_map();

    struct sockaddr_storage target = {};
    socklen_t target_len;
    if (family == AF_INET) {
        struct sockaddr_in *sin = (void *) &target;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(9);
        memcpy(&sin->sin_addr, dst, 4);
        target_len = sizeof(*sin);
    } else {
        struct sockaddr_in6 *sin6 = (void *) &target;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(9);
        memcpy(&sin6->sin6_addr, dst, 16);
        target_len = sizeof(*sin6);
    }

    if (connect(fd, (void *) &target, target_len) < 0) {
        int err = errno_map();
        close(fd);
        return err;
    }

    struct sockaddr_storage local = {};
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (void *) &local, &local_len) < 0) {
        int err = errno_map();
        close(fd);
        return err;
    }
    close(fd);

    size_t addr_len = family == AF_INET ? 4 : 16;
    const void *local_addr = family == AF_INET
        ? (const void *) &((struct sockaddr_in *) &local)->sin_addr
        : (const void *) &((struct sockaddr_in6 *) &local)->sin6_addr;
    memcpy(src, local_addr, addr_len);

    *ifindex = 0;
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) == 0) {
        for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
            if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != family)
                continue;
            const void *candidate = family == AF_INET
                ? (const void *) &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr
                : (const void *) &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            if (memcmp(candidate, local_addr, addr_len) == 0) {
                *ifindex = if_nametoindex(ifa->ifa_name);
                break;
            }
        }
        freeifaddrs(ifap);
    }
    return *ifindex == 0 ? _ENODEV : 0;
}

#ifdef __APPLE__
// iPhoneOS does not expose <net/route.h> to applications, but the routing
// sysctl uses this stable Darwin routing-message ABI.
#define DARWIN_RTM_VERSION 5
#define DARWIN_RTF_GATEWAY 0x2
#define DARWIN_RTF_HOST 0x4
#define DARWIN_RTAX_DST 0
#define DARWIN_RTAX_GATEWAY 1
#define DARWIN_RTAX_MAX 8

struct darwin_rt_metrics {
    uint32_t locks;
    uint32_t mtu;
    uint32_t hopcount;
    int32_t expire;
    uint32_t recvpipe;
    uint32_t sendpipe;
    uint32_t ssthresh;
    uint32_t rtt;
    uint32_t rttvar;
    uint32_t pksent;
    uint32_t state;
    uint32_t filler[3];
};

struct darwin_rt_msghdr {
    uint16_t msglen;
    uint8_t version;
    uint8_t type;
    uint16_t index;
    int32_t flags;
    int32_t addrs;
    int32_t pid;
    int32_t seq;
    int32_t error;
    int32_t use;
    uint32_t inits;
    struct darwin_rt_metrics metrics;
};

#define ROUTE_SA_ROUNDUP(len) ((len) > 0 ? (1 + (((len) - 1) | (sizeof(long) - 1))) : sizeof(long))

static int netlink_host_default_gateway(uint8_t fake_family, unsigned ifindex,
        uint8_t *gateway) {
    int family = fake_family == AF_INET_ ? AF_INET :
                 fake_family == AF_INET6_ ? AF_INET6 : -1;
    if (family < 0)
        return _EAFNOSUPPORT;

    int mib[6] = {CTL_NET, PF_ROUTE, 0, family, NET_RT_DUMP, 0};
    size_t len = 0;
    if (sysctl(mib, 6, NULL, &len, NULL, 0) < 0)
        return errno_map();

    uint8_t *buf = malloc(len);
    if (buf == NULL)
        return _ENOMEM;
    if (sysctl(mib, 6, buf, &len, NULL, 0) < 0) {
        int err = errno_map();
        free(buf);
        return err;
    }

    int result = _ENOENT;
    for (uint8_t *p = buf; p + sizeof(struct darwin_rt_msghdr) <= buf + len; ) {
        struct darwin_rt_msghdr *rtm = (void *) p;
        if (rtm->msglen < sizeof(*rtm) || p + rtm->msglen > buf + len)
            break;
        p += rtm->msglen;

        if (rtm->version != DARWIN_RTM_VERSION ||
                (rtm->flags & DARWIN_RTF_GATEWAY) == 0 ||
                (rtm->flags & DARWIN_RTF_HOST) != 0 ||
                (ifindex != 0 && rtm->index != ifindex))
            continue;

        struct sockaddr *addrs[DARWIN_RTAX_MAX] = {};
        struct sockaddr *sa = (void *) (rtm + 1);
        uint8_t *end = (uint8_t *) rtm + rtm->msglen;
        for (int i = 0; i < DARWIN_RTAX_MAX; i++) {
            if ((rtm->addrs & (1 << i)) == 0)
                continue;
            if ((uint8_t *) sa + 2 > end)
                break;
            addrs[i] = sa;
            size_t step = ROUTE_SA_ROUNDUP(sa->sa_len);
            if (step == 0 || (uint8_t *) sa + step > end) {
                sa = NULL;
                break;
            }
            sa = (void *) ((uint8_t *) sa + step);
        }
        if (sa == NULL || addrs[DARWIN_RTAX_DST] == NULL ||
                addrs[DARWIN_RTAX_GATEWAY] == NULL)
            continue;

        bool is_default = false;
        if (family == AF_INET &&
                addrs[DARWIN_RTAX_DST]->sa_family == AF_INET &&
                addrs[DARWIN_RTAX_GATEWAY]->sa_family == AF_INET) {
            const struct sockaddr_in *dst = (const void *) addrs[DARWIN_RTAX_DST];
            const struct sockaddr_in *gw = (const void *) addrs[DARWIN_RTAX_GATEWAY];
            is_default = dst->sin_addr.s_addr == INADDR_ANY;
            if (is_default) {
                memcpy(gateway, &gw->sin_addr, 4);
                result = 0;
                break;
            }
        } else if (family == AF_INET6 &&
                addrs[DARWIN_RTAX_DST]->sa_family == AF_INET6 &&
                addrs[DARWIN_RTAX_GATEWAY]->sa_family == AF_INET6) {
            const struct sockaddr_in6 *dst = (const void *) addrs[DARWIN_RTAX_DST];
            const struct sockaddr_in6 *gw = (const void *) addrs[DARWIN_RTAX_GATEWAY];
            static const struct in6_addr zero = IN6ADDR_ANY_INIT;
            is_default = memcmp(&dst->sin6_addr, &zero, sizeof(zero)) == 0;
            if (is_default) {
                memcpy(gateway, &gw->sin6_addr, 16);
                result = 0;
                break;
            }
        }
    }

    free(buf);
    return result;
}
#else
static int netlink_host_default_gateway(uint8_t fake_family, unsigned ifindex,
        uint8_t *gateway) {
    (void) fake_family;
    (void) ifindex;
    (void) gateway;
    return _EOPNOTSUPP;
}
#endif

static int netlink_add_default_route(struct netlink_builder *b, uint32_t seq,
        uint8_t family) {
    uint8_t probe_dst[16] = {};
    size_t addr_len;

    if (family == AF_INET_) {
        const uint8_t public_v4[4] = {1, 1, 1, 1};
        memcpy(probe_dst, public_v4, sizeof(public_v4));
        addr_len = sizeof(public_v4);
    } else if (family == AF_INET6_) {
        if (inet_pton(AF_INET6, "2606:4700:4700::1111", probe_dst) != 1)
            return _EINVAL;
        addr_len = 16;
    } else {
        return 0;
    }

    unsigned index = 0;
    uint8_t src[16] = {};
    if (netlink_probe_route(family, probe_dst, &index, src) < 0)
        return 0;

    size_t start = netlink_start_msg(b, RTM_NEWROUTE_, NLM_F_MULTI_, seq,
            sizeof(struct rtmsg_));
    if (start == SIZE_MAX)
        return _ENOMEM;

    struct rtmsg_ *route = netlink_payload(b, start);
    route->family = family;
    route->dst_len = 0;
    route->table = RT_TABLE_MAIN_;
    route->protocol = RTPROT_BOOT_;
    route->scope = RT_SCOPE_UNIVERSE_;
    route->type = RTN_UNICAST_;

    int err = netlink_add_attr(b, start, RTA_OIF_, &index, sizeof(index));
    if (err < 0)
        return err;
    err = netlink_add_attr(b, start, RTA_PREFSRC_, src, addr_len);
    if (err < 0)
        return err;

    uint8_t gateway[16] = {};
    if (netlink_host_default_gateway(family, index, gateway) == 0) {
        err = netlink_add_attr(b, start, RTA_GATEWAY_, gateway, addr_len);
        if (err < 0)
            return err;
    }
    return 0;
}

static int netlink_route_is_onlink(uint8_t fake_family, unsigned ifindex,
        const uint8_t *src, const uint8_t *dst) {
    int family = fake_family == AF_INET_ ? AF_INET :
                 fake_family == AF_INET6_ ? AF_INET6 : -1;
    if (family < 0)
        return 0;

    size_t addr_len = family == AF_INET ? 4 : 16;
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return 0;

    int onlink = 0;
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL ||
                ifa->ifa_addr->sa_family != family ||
                if_nametoindex(ifa->ifa_name) != ifindex)
            continue;

        const uint8_t *addr;
        const uint8_t *mask;
        if (family == AF_INET) {
            addr = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            mask = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;
        } else {
            addr = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            mask = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
        }
        if (memcmp(addr, src, addr_len) != 0)
            continue;

        onlink = 1;
        for (size_t i = 0; i < addr_len; i++) {
            if ((src[i] & mask[i]) != (dst[i] & mask[i])) {
                onlink = 0;
                break;
            }
        }
        if (onlink)
            break;
    }

    freeifaddrs(ifap);
    return onlink;
}

static int netlink_build_route_query(struct netlink_builder *b,
        const struct nlmsghdr_ *request, const uint8_t *request_data,
        size_t request_len) {
    if (request_len < sizeof(*request) + sizeof(struct rtmsg_))
        return _EINVAL;
    const struct rtmsg_ *req = (const void *) (request_data + sizeof(*request));
    size_t addr_len = req->family == AF_INET_ ? 4 :
                      req->family == AF_INET6_ ? 16 : 0;
    if (addr_len == 0)
        return _EAFNOSUPPORT;

    uint8_t dst[16] = {};
    size_t off = sizeof(*request) + sizeof(*req);
    while (off + sizeof(struct rtattr_) <= request->len && off + sizeof(struct rtattr_) <= request_len) {
        const struct rtattr_ *attr = (const void *) (request_data + off);
        if (attr->len < sizeof(*attr) || off + attr->len > request_len)
            break;
        if (attr->type == RTA_DST_ && attr->len >= sizeof(*attr) + addr_len)
            memcpy(dst, attr + 1, addr_len);
        off += NL_ALIGN(attr->len);
    }

    unsigned index = 0;
    uint8_t src[16] = {};
    int probe = netlink_probe_route(req->family, dst, &index, src);

    size_t start = netlink_start_msg(b, RTM_NEWROUTE_, 0, request->seq,
            sizeof(struct rtmsg_));
    if (start == SIZE_MAX)
        return _ENOMEM;
    struct rtmsg_ *route = netlink_payload(b, start);
    route->family = req->family;
    route->dst_len = req->dst_len;
    route->table = RT_TABLE_MAIN_;
    route->protocol = RTPROT_BOOT_;
    route->scope = RT_SCOPE_UNIVERSE_;
    route->type = probe < 0 ? RTN_UNREACHABLE_ : RTN_UNICAST_;

    if (probe >= 0) {
        int err = netlink_add_attr(b, start, RTA_DST_, dst, addr_len);
        if (err < 0) return err;
        err = netlink_add_attr(b, start, RTA_OIF_, &index, sizeof(index));
        if (err < 0) return err;
        err = netlink_add_attr(b, start, RTA_PREFSRC_, src, addr_len);
        if (err < 0) return err;

        if (!netlink_route_is_onlink(req->family, index, src, dst)) {
            uint8_t gateway[16] = {};
            if (netlink_host_default_gateway(req->family, index, gateway) == 0) {
                err = netlink_add_attr(b, start, RTA_GATEWAY_,
                        gateway, addr_len);
                if (err < 0) return err;
            }
        }
    }
    return 0;
}

static int netlink_build_route_dump(struct netlink_builder *b, uint32_t seq,
        uint8_t requested_family) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();
    int err = 0;

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_addr == NULL || ifa->ifa_netmask == NULL || ifa->ifa_name == NULL)
            continue;
        int family = ifa->ifa_addr->sa_family;
        uint8_t fake_family = family == AF_INET ? AF_INET_ :
                              family == AF_INET6 ? AF_INET6_ : 0;
        if (fake_family == 0 || (requested_family != 0 && requested_family != fake_family))
            continue;
        unsigned index = if_nametoindex(ifa->ifa_name);
        if (index == 0)
            continue;

        size_t addr_len = family == AF_INET ? 4 : 16;
        uint8_t network[16] = {};
        const uint8_t *addr;
        const uint8_t *mask;
        if (family == AF_INET) {
            addr = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr;
            mask = (const uint8_t *) &((struct sockaddr_in *) ifa->ifa_netmask)->sin_addr;
        } else {
            addr = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
            mask = (const uint8_t *) &((struct sockaddr_in6 *) ifa->ifa_netmask)->sin6_addr;
        }
        for (size_t i = 0; i < addr_len; i++)
            network[i] = addr[i] & mask[i];
        unsigned prefix = netlink_prefix_bits(mask, addr_len);

        size_t start = netlink_start_msg(b, RTM_NEWROUTE_, NLM_F_MULTI_, seq,
                sizeof(struct rtmsg_));
        if (start == SIZE_MAX) { err = _ENOMEM; break; }
        struct rtmsg_ *route = netlink_payload(b, start);
        route->family = fake_family;
        route->dst_len = prefix;
        route->table = RT_TABLE_MAIN_;
        route->protocol = RTPROT_KERNEL_;
        route->scope = (ifa->ifa_flags & IFF_LOOPBACK) ? RT_SCOPE_HOST_ : RT_SCOPE_LINK_;
        route->type = RTN_UNICAST_;

        if (prefix != 0) {
            err = netlink_add_attr(b, start, RTA_DST_, network, addr_len);
            if (err < 0) break;
        }
        err = netlink_add_attr(b, start, RTA_OIF_, &index, sizeof(index));
        if (err < 0) break;
        err = netlink_add_attr(b, start, RTA_PREFSRC_, addr, addr_len);
        if (err < 0) break;
    }
    freeifaddrs(ifap);

    if (err >= 0 && (requested_family == 0 || requested_family == AF_INET_))
        err = netlink_add_default_route(b, seq, AF_INET_);
    if (err >= 0 && (requested_family == 0 || requested_family == AF_INET6_))
        err = netlink_add_default_route(b, seq, AF_INET6_);

    return err;
}

static int netlink_handle_request(struct fd *fd, const void *data, size_t len) {
    if (len < sizeof(struct nlmsghdr_))
        return _EINVAL;
    const struct nlmsghdr_ *request = data;
    if (request->len < sizeof(*request) || request->len > len)
        return _EINVAL;

    struct netlink_builder b = {};
    int err;
    switch (request->type) {
        case RTM_GETLINK_:
            err = netlink_build_links(&b, request->seq);
            if (err >= 0) err = netlink_add_done(&b, request->seq);
            break;
        case RTM_GETADDR_: {
            // RTM_GETADDR dump requests carry struct ifaddrmsg; its first byte
            // is the requested address family. AF_UNSPEC (0) means all.
            uint8_t requested_family = request->len > sizeof(*request)
                ? *((const uint8_t *) data + sizeof(*request)) : 0;
            err = netlink_build_addrs(&b, request->seq, requested_family);
            if (err >= 0) err = netlink_add_done(&b, request->seq);
            break;
        }
        case RTM_GETROUTE_: {
            if ((request->flags & NLM_F_DUMP_) != 0) {
                // rtnetlink dump requests use struct rtgenmsg, whose only
                // payload field is the one-byte address family.
                uint8_t requested_family = request->len > sizeof(*request)
                    ? *((const uint8_t *) data + sizeof(*request)) : 0;
                err = netlink_build_route_dump(&b, request->seq, requested_family);
                if (err >= 0) err = netlink_add_done(&b, request->seq);
            } else {
                err = netlink_build_route_query(&b, request, data, len);
            }
            break;
        }
        case RTM_GETNEIGH_:
            // iOS does not provide a stable public ARP/NDP table API for apps.
            // Return a valid empty multipart dump rather than making common
            // Linux tools fail. Point lookups remain explicitly unsupported.
            if ((request->flags & NLM_F_DUMP_) != 0)
                err = netlink_add_done(&b, request->seq);
            else
                err = _EOPNOTSUPP;
            break;
        default:
            err = _EOPNOTSUPP;
            break;
    }

    if (err < 0) {
        // Once a valid Netlink request has reached the route family, Linux
        // reports protocol errors asynchronously with NLMSG_ERROR. Keep the
        // send/write successful so userspace receives the error on recvmsg().
        free(b.data);
        b.data = NULL;
        b.len = b.cap = 0;
        int build_err = netlink_add_error(&b, request, err);
        if (build_err < 0)
            return build_err;
    } else if ((request->flags & NLM_F_ACK_) != 0 &&
            (request->flags & NLM_F_DUMP_) == 0) {
        int build_err = netlink_add_error(&b, request, 0);
        if (build_err < 0) {
            free(b.data);
            return build_err;
        }
    }
    fd->socket.netlink_seq = request->seq;
    return netlink_commit_response(fd, &b);
}

static ssize_t netlink_take_response(struct fd *fd, void *buf, size_t size) {
    if (!fd->socket.netlink_pending || fd->socket.netlink_response == NULL)
        return _EAGAIN;
    size_t copy_len = size < fd->socket.netlink_response_len
        ? size : fd->socket.netlink_response_len;
    memcpy(buf, fd->socket.netlink_response, copy_len);
    netlink_clear_response(fd);
    return copy_len;
}

static fd_t sock_fd_create(int sock_fd, int domain, int type, int protocol) {
    struct fd *fd = adhoc_fd_create(&socket_fdops);
    if (fd == NULL)
        return _ENOMEM;
    fd->stat.mode = S_IFSOCK | 0666;
    lock(&socket_inode_lock);
    fd->stat.inode = ++socket_inode_next;
    unlock(&socket_inode_lock);
    fd->real_fd = sock_fd;
    fd->socket.domain = domain;
    fd->socket.type = type & SOCKET_TYPE_MASK;
    fd->socket.protocol = protocol;
    if (domain == AF_LOCAL_) {
        cond_init(&fd->socket.unix_got_peer);
        list_init(&fd->socket.unix_scm);
    }
    return f_install(fd, type & ~SOCKET_TYPE_MASK);
}

int_t sys_socket(dword_t domain, dword_t type, dword_t protocol) {
    STRACE("socket(%d, %d, %d)", domain, type, protocol);

    // Darwin/iOS has no Linux AF_NETLINK. Keep NETLINK_ROUTE virtual inside
    // iSH so Linux userspace can still use its normal Netlink API.
    if (domain == AF_NETLINK_) {
        int base_type = type & SOCKET_TYPE_MASK;
        if (protocol != NETLINK_ROUTE_ ||
                (base_type != SOCK_RAW_ && base_type != SOCK_DGRAM_))
            return _EINVAL;
        return sock_fd_create(-1, domain, type, protocol);
    }

    int real_domain = sock_family_to_real(domain);
    if (real_domain < 0)
        return _EINVAL;
    int real_type = sock_type_to_real(type, protocol);
    if (real_type < 0)
        return _EINVAL;

    // this hack makes mtr work
    if (type == SOCK_RAW_ && protocol == IPPROTO_RAW)
        protocol = IPPROTO_ICMP;

    int sock = socket(real_domain, real_type, protocol);
    if (sock < 0)
        return errno_map();

#ifdef __APPLE__
    if (domain == AF_INET_ && type == SOCK_DGRAM_) {
        // in some cases, such as ICMP, datagram sockets on mac can default to
        // including the IP header like raw sockets
        int one = 1;
        setsockopt(sock, IPPROTO_IP, IP_STRIPHDR, &one, sizeof(one));
    }
#endif

    fd_t f = sock_fd_create(sock, domain, type, protocol);
    if (f < 0)
        close(sock);
    return f;
}

static void inode_release_if_exist(struct inode_data *inode) {
    if (inode != NULL)
        inode_release(inode);
}

static struct fd *sock_getfd(fd_t sock_fd) {
    struct fd *sock = f_get(sock_fd);
    if (sock == NULL || sock->ops != &socket_fdops)
        return NULL;
    return sock;
}

static uint32_t unix_socket_next_id(void) {
    static uint32_t next_id = 0;
    static lock_t next_id_lock = LOCK_INITIALIZER;
    lock(&next_id_lock);
    uint32_t id = ++next_id;
    unlock(&next_id_lock);
    return id;
}

static int unix_socket_get(const char *path_raw, struct fd *bind_fd, uint32_t *socket_id) {
    char path[MAX_PATH];
    int err = path_normalize(AT_PWD, path_raw, path, N_SYMLINK_FOLLOW);
    if (err < 0)
        return err;
    struct mount *mount = find_mount_and_trim_path(path);
    struct statbuf stat;
    err = mount->fs->stat(mount, path, &stat);

    // If bind was called, there are some funny semantics.
    if (bind_fd != NULL) {
        // If the file exists, fail.
        if (err == 0) {
            err = _EADDRINUSE;
            goto out;
        }
        // If the file can't be found, try to create it as a socket.
        if (err < 0) {
            mode_t_ mode = 0777;
            struct fs_info *fs = current->fs;
            lock(&fs->lock);
            mode &= ~fs->umask;
            unlock(&fs->lock);
            err = mount->fs->mknod(mount, path, S_IFSOCK | mode, 0);
            if (err < 0)
                goto out;
            err = mount->fs->stat(mount, path, &stat);
            if (err < 0)
                goto out;
        }
    }

    // If something other than bind was called, just do the obvious thing and
    // fail if stat failed.
    if (bind_fd == NULL && err < 0)
        goto out;

    if (!S_ISSOCK(stat.mode)) {
        err = _ENOTSOCK;
        goto out;
    }

    // Look up the socket ID for the inode number.
    struct inode_data *inode = inode_get(mount, stat.inode);
    lock(&inode->lock);
    if (inode->socket_id == 0)
        inode->socket_id = unix_socket_next_id();
    unlock(&inode->lock);
    *socket_id = inode->socket_id;

    mount_release(mount);
    if (bind_fd != NULL)
        bind_fd->socket.unix_name_inode = inode;
    else
        inode_release(inode);
    return 0;

out:
    mount_release(mount);
    return err;
}

// Dan Bernstein's simple and decently effective hash function
static uint32_t str_hash(const char *str) {
    uint32_t hash = 5381;
    for (int i = 0; str[i] != '\0'; i++) {
        hash = 33 * hash ^ str[i];
    }
    return hash;
}

// The abstract socket namespace is a lot simpler than it sounds: if the first
// byte of the path is a null byte, then it gets looked up in this hashtable
// instead of the filesystem.

struct unix_abstract {
    unsigned refcount;
    uint32_t hash;
    uint32_t socket_id;
    struct list links;
};
#define ABSTRACT_HASH_SIZE 1024
static struct list abstract_hash[ABSTRACT_HASH_SIZE];
static lock_t unix_abstract_lock = LOCK_INITIALIZER;

static int unix_abstract_get(const char *name, struct fd *bind_fd, uint32_t *socket_id) {
    uint32_t hash = str_hash(name);
    lock(&unix_abstract_lock);
    struct unix_abstract *sock_tmp;
    struct unix_abstract *sock = NULL;
    struct list *bucket = &abstract_hash[hash % ABSTRACT_HASH_SIZE];
    if (list_null(bucket))
        list_init(bucket);
    list_for_each_entry(bucket, sock_tmp, links) {
        if (sock_tmp->hash == hash) {
            sock = sock_tmp;
            break;
        }
    }

    if (bind_fd != NULL && sock != NULL) {
        unlock(&unix_abstract_lock);
        return _EEXIST;
    }
    if (bind_fd == NULL && sock == NULL) {
        unlock(&unix_abstract_lock);
        return _ENOENT;
    }

    if (sock == NULL) {
        sock = malloc(sizeof(struct unix_abstract));
        sock->refcount = 0;
        sock->hash = hash;
        sock->socket_id = unix_socket_next_id();
        list_add(bucket, &sock->links);
    }

    sock->refcount++;
    unlock(&unix_abstract_lock);
    *socket_id = sock->socket_id;
    if (bind_fd != NULL)
        bind_fd->socket.unix_name_abstract = sock;
    return 0;
}

static void unix_abstract_release(struct unix_abstract *name) {
    lock(&unix_abstract_lock);
    if (--name->refcount == 0) {
        list_remove(&name->links);
        free(name);
    }
    unlock(&unix_abstract_lock);
}

const char *sock_tmp_prefix = "/tmp/ishsock";

static int sockaddr_read_bind(addr_t sockaddr_addr, void *sockaddr, uint_t *sockaddr_len, struct fd *bind_fd) {
    // Make sure we can read things without overflowing buffers
    if (*sockaddr_len < 2)
        return _EINVAL;
    if (*sockaddr_len > sizeof(struct sockaddr_max_))
        return _EINVAL;

    if (user_read(sockaddr_addr, sockaddr, *sockaddr_len))
        return _EFAULT;
    struct sockaddr *real_addr = sockaddr;
    struct sockaddr_ *fake_addr = sockaddr;
    real_addr->sa_family = sock_family_to_real(fake_addr->family);

    switch (real_addr->sa_family) {
        case PF_INET:
            if (*sockaddr_len < sizeof(struct sockaddr_in))
                return _EINVAL;
            break;
        case PF_INET6:
            if (*sockaddr_len < sizeof(struct sockaddr_in6))
                return _EINVAL;
            break;

        case PF_LOCAL: {
            // First pull out the path, being careful to not overflow anything.
            char path[SOCKADDR_DATA_MAX + 1];
            size_t path_size = *sockaddr_len - offsetof(struct sockaddr_, data);
            memcpy(path, fake_addr->data, path_size);
            path[path_size] = '\0';

            uint32_t socket_id;
            int err;
            if (path_size == 0) {
                return _ENOENT;
            } else if (path[0] != '\0') {
                STRACE(" unix socket %s", path);
                err = unix_socket_get(path, bind_fd, &socket_id);
            } else {
                STRACE(" unix abstract socket %s", path + 1);
                err = unix_abstract_get(path + 1, bind_fd, &socket_id);
            }
            if (err < 0)
                return err;
            if (bind_fd != NULL) {
                bind_fd->socket.unix_name_len = path_size;
                memcpy(bind_fd->socket.unix_name, path, path_size);
            }

            struct sockaddr_un *real_addr_un = sockaddr;
            size_t path_len = sprintf(real_addr_un->sun_path, "%s%d.%u", sock_tmp_prefix, getpid(), socket_id);
            // The call to real bind will fail if the backing socket already
            // exists from a previous run or something. We already checked that
            // the fake file doesn't exist in unix_socket_get, so try a simple
            // solution.
            if (bind_fd != NULL)
                unlink(real_addr_un->sun_path);
            *sockaddr_len = offsetof(struct sockaddr_un, sun_path) + path_len;
            break;
        }
        default:
            return _EINVAL;
    }
    return 0;
}

static int sockaddr_read(addr_t sockaddr_addr, void *sockaddr, uint_t *sockaddr_len) {
    struct inode_data *inode = NULL;
    int err = sockaddr_read_bind(sockaddr_addr, sockaddr, sockaddr_len, NULL);
    inode_release_if_exist(inode);
    return err;
}

static int sockaddr_write(addr_t sockaddr_addr, void *sockaddr, uint_t buffer_len, uint_t *sockaddr_len) {
    struct sockaddr *real_addr = sockaddr;
    struct sockaddr_ *fake_addr = sockaddr;
    fake_addr->family = sock_family_from_real(real_addr->sa_family);
    switch (fake_addr->family) {
        case PF_LOCAL_: {
            // Most callers of sockaddr_write use it to return a peer name, and
            // since we don't know the peer name in this case, just return the
            // default peer name, which is the null address.
            static struct sockaddr_ unix_domain_null = {.family = PF_LOCAL_};
            sockaddr = &unix_domain_null;
            *sockaddr_len = sizeof(unix_domain_null);
            break;
        }
        case PF_INET_:
        case PF_INET6_:
            break;
        default:
            return _EINVAL;
    }

    if (buffer_len > *sockaddr_len)
        buffer_len = *sockaddr_len;
    // The address is supposed to be truncated if the specified length is too
    // short, instead of returning an error.
    if (user_write(sockaddr_addr, sockaddr, buffer_len))
        return _EFAULT;
    return 0;
}

int_t sys_bind(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len) {
    STRACE("bind(%d, 0x%x, %d)", sock_fd, sockaddr_addr, sockaddr_len);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;

    if (is_netlink_route(sock)) {
        if (sockaddr_len < sizeof(struct sockaddr_nl_))
            return _EINVAL;
        struct sockaddr_nl_ nl;
        if (user_read(sockaddr_addr, &nl, sizeof(nl)))
            return _EFAULT;
        if (nl.family != AF_NETLINK_)
            return _EINVAL;
        sock->socket.netlink_pid = nl.pid != 0 ? nl.pid : current->pid;
        sock->socket.netlink_groups = nl.groups;
        return 0;
    }

    struct sockaddr_max_ sockaddr;
    struct inode_data *inode = NULL;
    int err = sockaddr_read_bind(sockaddr_addr, &sockaddr, &sockaddr_len, sock);
    if (err < 0)
        return err;

    err = bind(sock->real_fd, (void *) &sockaddr, sockaddr_len);
    if (err < 0) {
        inode_release_if_exist(sock->socket.unix_name_inode);
        if (sock->socket.unix_name_abstract != NULL)
            unix_abstract_release(sock->socket.unix_name_abstract);
        return errno_map();
    }
    sock->socket.unix_name_inode = inode;
    return 0;
}

static void fill_cred(struct ucred_ *cred) {
    cred->pid = current->pid;
    cred->uid = current->euid;
    cred->gid = current->egid;
}

static int sock_map_connect_error(struct fd *sock, int host_error) {
#ifdef __APPLE__
    // Darwin can report EPERM when a sandbox or network policy denies an
    // Internet connection. Linux applications generally handle this class of
    // connect denial as EACCES; Nmap, for example, classifies EACCES as an
    // administratively filtered connection but treats EPERM as an unknown
    // socket error. Keep EPERM unchanged for non-Internet sockets.
    if ((sock->socket.domain == AF_INET_ || sock->socket.domain == AF_INET6_) &&
            host_error == EPERM)
        return _EACCES;
#endif
    return err_map(host_error);
}

int_t sys_connect(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len) {
    STRACE("connect(%d, 0x%x, %d)", sock_fd, sockaddr_addr, sockaddr_len);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;

    if (is_netlink_route(sock)) {
        if (sockaddr_len < sizeof(struct sockaddr_nl_))
            return _EINVAL;
        struct sockaddr_nl_ nl;
        if (user_read(sockaddr_addr, &nl, sizeof(nl)))
            return _EFAULT;
        return nl.family == AF_NETLINK_ ? 0 : _EINVAL;
    }

    struct sockaddr_max_ sockaddr;
    int err = sockaddr_read(sockaddr_addr, &sockaddr, &sockaddr_len);
    if (err < 0)
        return err;

    err = connect(sock->real_fd, (void *) &sockaddr, sockaddr_len);
    if (err < 0)
        return sock_map_connect_error(sock, errno);

    if (sock->socket.domain == AF_LOCAL_) {
        fill_cred(&sock->socket.unix_cred);
        assert(sock->socket.unix_peer == NULL);
        // Send a pointer to ourselves to the other end so they can set up the peer pointers.
        ssize_t res = write(sock->real_fd, &sock, sizeof(struct fd *));
        if (res == sizeof(struct fd *)) {
            // Wait for acknowledgement that it happened.
            lock(&peer_lock);
            while (sock->socket.unix_peer == NULL)
                wait_for_ignore_signals(&sock->socket.unix_got_peer, &peer_lock, NULL);
            unlock(&peer_lock);
        }
    }

    return err;
}

int_t sys_listen(fd_t sock_fd, int_t backlog) {
    STRACE("listen(%d, %d)", sock_fd, backlog);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    int err = listen(sock->real_fd, backlog);
    if (err < 0)
        return errno_map();
    sockrestart_begin_listen(sock);
    return err;
}

int_t sys_accept(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr) {
    STRACE("accept(%d, 0x%x, 0x%x)", sock_fd, sockaddr_addr, sockaddr_len_addr);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    dword_t sockaddr_len = 0;
    if (sockaddr_addr != 0) {
        if (user_get(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;
    }

    char sockaddr[sockaddr_len];
    int client;
    do {
        sockrestart_begin_listen_wait(sock);
        errno = 0;
        client = accept(sock->real_fd,
                sockaddr_addr != 0 ? (void *) sockaddr : NULL,
                sockaddr_addr != 0 ? &sockaddr_len : NULL);
        sockrestart_end_listen_wait(sock);
    } while (sockrestart_should_restart_listen_wait() && errno == EINTR);
    if (client < 0)
        return errno_map();

    if (sockaddr_addr != 0) {
        int err = sockaddr_write(sockaddr_addr, sockaddr, sizeof(sockaddr), &sockaddr_len);
        if (err < 0)
            return client;
        if (user_put(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;
    }

    fd_t client_f = sock_fd_create(client,
            sock->socket.domain, sock->socket.type, sock->socket.protocol);
    if (client_f < 0)
        close(client);

    if (sock->socket.domain == AF_LOCAL_) {
        lock(&peer_lock);
        struct fd *client_fd = f_get(client_f);
        fill_cred(&client_fd->socket.unix_cred);
        struct fd *peer;
        ssize_t res = read(client, &peer, sizeof(peer));
        if (res == sizeof(peer)) {
            client_fd->socket.unix_peer = peer;
            peer->socket.unix_peer = client_fd;
            notify(&peer->socket.unix_got_peer);
        }
        unlock(&peer_lock);
    }

    return client_f;
}

static void copy_unix_name(char *sockaddr, dword_t *sockaddr_len, struct fd *sock) {
    struct sockaddr_ *fake_addr = (void *) sockaddr;
    fake_addr->family = PF_LOCAL_;

    size_t data_len = *sockaddr_len - offsetof(struct sockaddr_, data);
    size_t name_len = sock->socket.unix_name_len;
    if (name_len > data_len)
        name_len = data_len;
    memset(fake_addr->data, 0, data_len);
    memcpy(fake_addr->data, sock->socket.unix_name, name_len);
    *sockaddr_len = offsetof(struct sockaddr_, data) + name_len;
}

int_t sys_getsockname(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr) {
    STRACE("getsockname(%d, 0x%x, 0x%x)", sock_fd, sockaddr_addr, sockaddr_len_addr);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    dword_t sockaddr_len;
    if (user_get(sockaddr_len_addr, sockaddr_len))
        return _EFAULT;

    if (is_netlink_route(sock)) {
        struct sockaddr_nl_ nl = {
            .family = AF_NETLINK_,
            .pid = sock->socket.netlink_pid != 0 ? sock->socket.netlink_pid : current->pid,
            .groups = sock->socket.netlink_groups,
        };
        dword_t copy_len = sockaddr_len < sizeof(nl) ? sockaddr_len : sizeof(nl);
        if (user_write(sockaddr_addr, &nl, copy_len))
            return _EFAULT;
        sockaddr_len = sizeof(nl);
        if (user_put(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;
        return 0;
    }

    char sockaddr[sockaddr_len];

    // if this is a unix socket, return the same string passed to bind
    if (sock->socket.domain == PF_LOCAL_) {
        copy_unix_name(sockaddr, &sockaddr_len, sock);
        if (user_write(sockaddr_addr, sockaddr, sizeof(sockaddr)))
            return _EFAULT;
        if (user_put(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;
        return 0;
    }

    int res = getsockname(sock->real_fd, (void *) sockaddr, &sockaddr_len);
    if (res < 0)
        return errno_map();

    int err = sockaddr_write(sockaddr_addr, sockaddr, sizeof(sockaddr), &sockaddr_len);
    if (err < 0)
        return err;
    if (user_put(sockaddr_len_addr, sockaddr_len))
        return _EFAULT;
    return res;
}

int_t sys_getpeername(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr) {
    STRACE("getpeername(%d, 0x%x, 0x%x)", sock_fd, sockaddr_addr, sockaddr_len_addr);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    dword_t sockaddr_len;
    if (user_get(sockaddr_len_addr, sockaddr_len))
        return _EFAULT;

    if (is_netlink_route(sock)) {
        struct sockaddr_nl_ nl = {.family = AF_NETLINK_, .pid = 0, .groups = 0};
        dword_t copy_len = sockaddr_len < sizeof(nl) ? sockaddr_len : sizeof(nl);
        if (user_write(sockaddr_addr, &nl, copy_len))
            return _EFAULT;
        sockaddr_len = sizeof(nl);
        if (user_put(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;
        return 0;
    }

    // TODO if this is a unix socket, return the same string the peer passed to
    // bind once the peer pointer is available

    char sockaddr[sockaddr_len];
    int res = getpeername(sock->real_fd, (void *) sockaddr, &sockaddr_len);
    if (res < 0)
        return errno_map();

    int err = sockaddr_write(sockaddr_addr, sockaddr, sizeof(sockaddr), &sockaddr_len);
    if (err < 0)
        return err;
    if (user_put(sockaddr_len_addr, sockaddr_len))
        return _EFAULT;
    return res;
}

int_t sys_socketpair(dword_t domain, dword_t type, dword_t protocol, addr_t sockets_addr) {
    STRACE("socketpair(%d, %d, %d, 0x%x)", domain, type, protocol, sockets_addr);
    int real_domain = sock_family_to_real(domain);
    if (real_domain < 0)
        return _EINVAL;
    int real_type = sock_type_to_real(type, protocol);
    if (real_type < 0)
        return _EINVAL;

    int sockets[2];
    int err = socketpair(domain, type, protocol, sockets);
    if (err < 0)
        return errno_map();

    lock(&peer_lock);
    int fake_sockets[2];
    err = fake_sockets[0] = sock_fd_create(sockets[0], domain, type, protocol);
    if (fake_sockets[0] < 0) {
        unlock(&peer_lock);
        goto close_sockets;
    }
    err = fake_sockets[1] = sock_fd_create(sockets[1], domain, type, protocol);
    if (fake_sockets[1] < 0) {
        unlock(&peer_lock);
        goto close_fake_0;
    }
    struct fd *sock1 = f_get(fake_sockets[0]);
    struct fd *sock2 = f_get(fake_sockets[1]);
    sock1->socket.unix_peer = sock2;
    sock2->socket.unix_peer = sock1;
    unlock(&peer_lock);

    err = _EFAULT;
    if (user_put(sockets_addr, fake_sockets))
        goto close_fake_1;

    STRACE(" [%d, %d]", fake_sockets[0], fake_sockets[1]);
    return 0;

close_fake_1:
    sys_close(fake_sockets[1]);
close_fake_0:
    sys_close(fake_sockets[0]);
close_sockets:
    close(sockets[0]);
    close(sockets[1]);
    return err;
}

int_t sys_sendto(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, dword_t sockaddr_len) {
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;

    if (is_netlink_route(sock)) {
        if (len > 1024 * 1024)
            return _EINVAL;
        void *request = malloc(len);
        if (request == NULL)
            return _ENOMEM;
        if (user_read(buffer_addr, request, len)) {
            free(request);
            return _EFAULT;
        }
        int err = netlink_handle_request(sock, request, len);
        free(request);
        return err < 0 ? err : (int_t) len;
    }

    char *buffer = malloc(len + 1);
    if (user_read(buffer_addr, buffer, len))
        return _EFAULT;
    buffer[len] = '\0';
    STRACE("sendto(%d, \"%.100s\", %d, %d, 0x%x, %d)", sock_fd, buffer, len, flags, sockaddr_addr, sockaddr_len);
    int real_flags = sock_flags_to_real(flags);
    int err = _EINVAL;
    if (real_flags < 0)
        goto error;
    struct sockaddr_max_ sockaddr;
    if (sockaddr_addr) {
        err = sockaddr_read(sockaddr_addr, &sockaddr, &sockaddr_len);
        if (err < 0)
            goto error;
    }

    ssize_t res = sendto(sock->real_fd, buffer, len, real_flags,
            sockaddr_addr ? (void *) &sockaddr : NULL, sockaddr_len);
    free(buffer);
    if (res < 0)
        return errno_map();
    return res;

error:
    free(buffer);
    return err;
}

int_t sys_recvfrom(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, addr_t sockaddr_len_addr) {
    STRACE("recvfrom(%d, 0x%x, %d, %d, 0x%x, 0x%x)", sock_fd, buffer_addr, len, flags, sockaddr_addr, sockaddr_len_addr);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;

    if (is_netlink_route(sock)) {
        if (!sock->socket.netlink_pending || sock->socket.netlink_response == NULL)
            return _EAGAIN;
        size_t response_len = sock->socket.netlink_response_len;
        size_t copy_len = len < response_len ? len : response_len;
        if (user_write(buffer_addr, sock->socket.netlink_response, copy_len))
            return _EFAULT;
        if (sockaddr_addr != 0 && sockaddr_len_addr != 0) {
            uint_t out_len;
            if (user_get(sockaddr_len_addr, out_len))
                return _EFAULT;
            struct sockaddr_nl_ nl = {.family = AF_NETLINK_};
            uint_t name_len = out_len < sizeof(nl) ? out_len : sizeof(nl);
            if (user_write(sockaddr_addr, &nl, name_len))
                return _EFAULT;
            out_len = sizeof(nl);
            if (user_put(sockaddr_len_addr, out_len))
                return _EFAULT;
        }
        if (!(flags & MSG_PEEK_))
            netlink_clear_response(sock);
        return (flags & MSG_TRUNC_) ? response_len : copy_len;
    }

    int real_flags = sock_flags_to_real(flags);
    if (real_flags < 0)
        return _EINVAL;
    uint_t sockaddr_len = 0;
    if (sockaddr_len_addr != 0)
        if (user_get(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;

    char *buffer = malloc(len);
    char sockaddr[sockaddr_len];
    ssize_t res = recvfrom(sock->real_fd, buffer, len, real_flags,
            sockaddr_addr != 0 ? (void *) sockaddr : NULL,
            sockaddr_len_addr != 0 ? &sockaddr_len : NULL);
    if (res < 0) {
        free(buffer);
        return errno_map();
    }

    if (user_write(buffer_addr, buffer, len)) {
        free(buffer);
        return _EFAULT;
    }
    free(buffer);
    if (sockaddr_addr != 0) {
        int err = sockaddr_write(sockaddr_addr, sockaddr, sizeof(sockaddr), &sockaddr_len);
        if (err < 0)
            return err;
    }
    if (sockaddr_len_addr != 0)
        if (user_put(sockaddr_len_addr, sockaddr_len))
            return _EFAULT;
    return res;
}

int_t sys_send(fd_t sock_fd, addr_t buf, dword_t len, int_t flags) {
    return sys_sendto(sock_fd, buf, len, flags, 0, 0);
}

int_t sys_recv(fd_t sock_fd, addr_t buf, dword_t len, int_t flags) {
    return sys_recvfrom(sock_fd, buf, len, flags, 0, 0);
}

int_t sys_shutdown(fd_t sock_fd, dword_t how) {
    STRACE("shutdown(%d, %d)", sock_fd, how);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    if (is_netlink_route(sock))
        return 0;
    int err = shutdown(sock->real_fd, how);
    if (err < 0)
        return errno_map();
    return 0;
}

#define DEFAULT_TCP_CONGESTION "cubic"

int_t sys_setsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t value_len) {
    STRACE("setsockopt(%d, %d, %d, 0x%x, %d)", sock_fd, level, option, value_addr, value_len);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    char value[value_len];
    if (user_read(value_addr, value, value_len))
        return _EFAULT;

    if (is_netlink_route(sock))
        return 0;

    if (level == SOL_SOCKET_ && option == SO_BINDTODEVICE_) {
        // Linux applications such as Nmap use SO_BINDTODEVICE to pin a
        // socket to an interface. iOS exposes equivalent per-family options
        // rather than the Linux SOL_SOCKET option.
        if (value_len == 0)
            return 0;
        if (value_len > IFNAMSIZ)
            return _EINVAL;
        char ifname[IFNAMSIZ + 1];
        memset(ifname, 0, sizeof(ifname));
        memcpy(ifname, value, value_len);
        if (ifname[0] == '\0')
            return 0;
        unsigned ifindex = if_nametoindex(ifname);
        if (ifindex == 0)
            return _ENODEV;
#if defined(__APPLE__)
        if (sock->socket.domain == AF_INET_) {
#if defined(IP_BOUND_IF)
            if (setsockopt(sock->real_fd, IPPROTO_IP, IP_BOUND_IF,
                    &ifindex, sizeof(ifindex)) < 0)
                return errno_map();
#endif
        } else if (sock->socket.domain == AF_INET6_) {
#if defined(IPV6_BOUND_IF)
            if (setsockopt(sock->real_fd, IPPROTO_IPV6, IPV6_BOUND_IF,
                    &ifindex, sizeof(ifindex)) < 0)
                return errno_map();
#endif
        }
#endif
        return 0;
    }

    // ICMP6_FILTER can only be set on real SOCK_RAW
    if (level == IPPROTO_ICMPV6 && option == ICMP6_FILTER_)
        return 0;
    // IP_MTU_DISCOVER has no equivalent on Darwin
    if (level == IPPROTO_IP && option == IP_MTU_DISCOVER_)
        return 0;
    // TCP_CONGESTION also has no equivalent on Darwin
#if defined(__APPLE__)
    if (level == IPPROTO_TCP && option == TCP_CONGESTION_) {
        if (strncmp(value, DEFAULT_TCP_CONGESTION, sizeof(value)) == 0)
            return 0;
        return _ENOENT;
    }
#endif

    int real_opt = sock_opt_to_real(option, level);
    if (real_opt < 0)
        return _EINVAL;
    int real_level = sock_level_to_real(level);
    if (real_level < 0)
        return _EINVAL;

    // 0 means the option is not implemented, but things rely on it, so we
    // should just ignore attempts to set it.
    if (real_opt == 0)
        return 0;

    int err = setsockopt(sock->real_fd, real_level, real_opt, value, value_len);
    if (err < 0)
        return errno_map();
    return 0;
}

int_t sys_getsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t len_addr) {
    STRACE("getsockopt(%d, %d, %d, %#x, %#x)", sock_fd, level, option, value_addr, len_addr);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;
    dword_t value_len;
    if (user_get(len_addr, value_len))
        return _EFAULT;
    char value[value_len];
    if (user_read(value_addr, value, value_len))
        return _EFAULT;

    if (level == SOL_SOCKET_ && (option == SO_DOMAIN_ || option == SO_TYPE_ || option == SO_PROTOCOL_)) {
        dword_t *value_p = (dword_t *) value;
        if (value_len != sizeof(*value_p))
            return _EINVAL;
        if (option == SO_DOMAIN_)
            *value_p = sock->socket.domain;
        else if (option == SO_TYPE_)
            *value_p = sock->socket.type;
        else if (option == SO_PROTOCOL_)
            *value_p = sock->socket.protocol;
    } else if (level == SOL_SOCKET_ && option == SO_PEERCRED_) {
        struct ucred_ *cred = (struct ucred_ *) value;
        if (value_len != sizeof(*cred))
            return _EINVAL;
        lock(&peer_lock);
        if (sock->socket.domain != AF_LOCAL_ || sock->socket.unix_peer == NULL) {
            cred->pid = 0;
            cred->uid = cred->gid = -1;
        } else {
            *cred = sock->socket.unix_peer->socket.unix_cred;
        }
        unlock(&peer_lock);
    } else if (level == SOL_SOCKET_ && option == SO_ERROR_) {
        if (value_len != sizeof(dword_t))
            return _EINVAL;
        if (is_netlink_route(sock)) {
            *(dword_t *) value = 0;
        } else {
        int real_error;
        socklen_t real_error_len = sizeof(real_error);
        int err = getsockopt(sock->real_fd, SOL_SOCKET, SO_ERROR, &real_error, &real_error_len);
        if (err < 0)
            return errno_map();
        *(dword_t *) value = real_error == 0 ? 0 :
            -sock_map_connect_error(sock, real_error);
        }
    } else if (level == IPPROTO_TCP && option == TCP_CONGESTION_) {
        value_len = strlen(DEFAULT_TCP_CONGESTION);
        memcpy(value, DEFAULT_TCP_CONGESTION, value_len);
#if defined(__APPLE__)
    } else if (level == IPPROTO_TCP && option == TCP_INFO_) {
        // This one's fun. On Linux, the struct is not ABI dependent, so no
        // special handling is needed. On Darwin, the struct is completely
        // different and has a different sockopt name.
        struct tcp_connection_info conn_info;
        socklen_t conn_info_size = sizeof(conn_info);
        int err = getsockopt(sock->real_fd, IPPROTO_TCP, TCP_CONNECTION_INFO, &conn_info, &conn_info_size);
        if (err < 0)
            return errno_map();

        // The possible keys for this table are in netinet/tcp_fsm.h, but that
        // header isn't available on iOS, only macOS.
        static const uint8_t tcp_state_table[] = {
            7, // TCPS_CLOSED
            10, // TCPS_LISTEN
            2, // TCPS_SYN_SENT
            3, // TCPS_SYN_RECEIVED
            1, // TCPS_ESTABLISHED
            8, // TCPS_CLOSE_WAIT
            4, // TCPS_FIN_WAIT_1
            11, // TCPS_CLOSING
            9, // TCPS_LAST_ACK
            5, // TCPS_FIN_WAIT_2
            6, // TCPS_TIME_WAIT
        };
        struct tcp_info_ info = {
            .state = tcp_state_table[conn_info.tcpi_state],
            .options = conn_info.tcpi_options,
            .snd_wscale = conn_info.tcpi_snd_wscale,
            .rcv_wscale = conn_info.tcpi_rcv_wscale,

            .rto = conn_info.tcpi_rto * 1000,
            .snd_mss = conn_info.tcpi_maxseg,

            .rtt = conn_info.tcpi_srtt * 1000,
            .rttvar = conn_info.tcpi_rttvar * 1000,
            .snd_ssthresh = conn_info.tcpi_snd_ssthresh,
            .snd_cwnd = conn_info.tcpi_snd_cwnd / conn_info.tcpi_maxseg,

            // https://lkml.org/lkml/2017/4/24/923
            .total_retrans = conn_info.tcpi_txretransmitpackets,
        };
        if (value_len > sizeof(struct tcp_info_))
            value_len = sizeof(struct tcp_info_);
        memcpy(value, &info, value_len);
#endif
    } else {
        int real_opt = sock_opt_to_real(option, level);
        if (real_opt < 0)
            return _EINVAL;
        int real_level = sock_level_to_real(level);
        if (real_level < 0)
            return _EINVAL;

        int err = getsockopt(sock->real_fd, real_level, real_opt, value, &value_len);
        if (err < 0)
            return errno_map();
    }

    if (user_put(len_addr, value_len))
        return _EFAULT;
    if (user_put(value_addr, value))
        return _EFAULT;
    return 0;
}

static void scm_free(struct scm *scm) {
    for (unsigned i = 0; i < scm->num_fds; i++)
        fd_close(scm->fds[i]);
    free(scm);
}

int_t sys_sendmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags) {
    int err;
    STRACE("sendmsg(%d, %#x, %d)", sock_fd, msghdr_addr, flags);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;

    struct msghdr msg;
    struct msghdr_ msg_fake;
    if (user_get(msghdr_addr, msg_fake))
        return _EFAULT;

    if (is_netlink_route(sock)) {
        if (msg_fake.msg_iovlen == 0)
            return 0;
        struct iovec_ iov[msg_fake.msg_iovlen];
        if (user_get(msg_fake.msg_iov, iov))
            return _EFAULT;
        size_t total = 0;
        for (size_t i = 0; i < msg_fake.msg_iovlen; i++) {
            if (iov[i].len > 1024 * 1024 - total)
                return _EINVAL;
            total += iov[i].len;
        }
        uint8_t *request = malloc(total);
        if (request == NULL)
            return _ENOMEM;
        size_t off = 0;
        for (size_t i = 0; i < msg_fake.msg_iovlen; i++) {
            if (user_read(iov[i].base, request + off, iov[i].len)) {
                free(request);
                return _EFAULT;
            }
            off += iov[i].len;
        }
        int result = netlink_handle_request(sock, request, total);
        free(request);
        return result < 0 ? result : (int_t) total;
    }

    // msg_name
    struct sockaddr_max_ msg_name;
    if (msg_fake.msg_name != 0) {
        int err = sockaddr_read(msg_fake.msg_name, &msg_name, &msg_fake.msg_namelen);
        if (err < 0)
            return err;
        msg.msg_name = &msg_name;
        msg.msg_namelen = msg_fake.msg_namelen;
    } else {
        msg.msg_name = NULL;
    }

    // msg_iovec
    struct iovec_ msg_iov_fake[msg_fake.msg_iovlen];
    if (user_get(msg_fake.msg_iov, msg_iov_fake))
        return _EFAULT;
    struct iovec msg_iov[msg_fake.msg_iovlen];
    memset(msg_iov, 0, sizeof(msg_iov));
    msg.msg_iov = msg_iov;
    msg.msg_iovlen = sizeof(msg_iov) / sizeof(msg_iov[0]);
    for (size_t i = 0; i < (size_t) msg.msg_iovlen; i++) {
        msg_iov[i].iov_len = msg_iov_fake[i].len;
        msg_iov[i].iov_base = malloc(msg_iov_fake[i].len);
        err = _EFAULT;
        if (user_read(msg_iov_fake[i].base, msg_iov[i].iov_base, msg_iov_fake[i].len))
            goto out_free_iov;
    }

    // msg_control
    uint8_t msg_control_buf[2048];
    uint8_t *msg_control = NULL;
    if (msg_fake.msg_control != 0) {
        if (msg_fake.msg_controllen > sizeof(msg_control_buf)) {
            err = _EINVAL;
            goto out_free_iov;
        }
        msg_control = msg_control_buf;
        err = _EFAULT;
        if (user_read(msg_fake.msg_control, msg_control, msg_fake.msg_controllen))
            goto out_free_iov;
    }
    msg.msg_control = NULL;
    msg.msg_controllen = 0;

    struct scm *scm = NULL;
    char real_msg_control[CMSG_SPACE(sizeof(int))]; // only used if actually sending an fd
    if (sock->socket.domain == AF_LOCAL_ && msg_control != NULL && msg_fake.msg_controllen >= sizeof(struct cmsghdr_)) {
        // figure out how many file descriptors we're sending
        uint8_t *mhdr_end = msg_control + msg_fake.msg_controllen;
        unsigned num_fds = 0;
        struct cmsghdr_ *cmsg;
        for (cmsg = (void *) msg_control; cmsg != NULL; cmsg = CMSG_NXTHDR_(cmsg, mhdr_end)) {
            if (cmsg->level != SOL_SOCKET_)
                continue;
            if (cmsg->type != SCM_RIGHTS_)
                return _EINVAL;
            num_fds += (cmsg->len - sizeof(struct cmsghdr_)) / sizeof(fd_t);
        }
        if (num_fds > 253) // *magic*
            return _EINVAL;

        if (num_fds > 0) {
            // send one (1) real fd and put the rest in a struct scm
            static int real_fd = -1;
            if (real_fd == -1) {
                real_fd = open(".", O_RDONLY);
                if (real_fd < 0)
                    ERRNO_DIE("no");
            }
            msg.msg_control = real_msg_control;
            msg.msg_controllen = sizeof(real_msg_control);
            struct cmsghdr *real_cmsg = CMSG_FIRSTHDR(&msg);
            real_cmsg->cmsg_level = SOL_SOCKET;
            real_cmsg->cmsg_type = SCM_RIGHTS;
            real_cmsg->cmsg_len = CMSG_LEN(sizeof(real_fd));
            memcpy(CMSG_DATA(real_cmsg), &real_fd, sizeof(real_fd));

            scm = malloc(sizeof(struct scm) + num_fds * sizeof(struct fd *));
            list_init(&scm->queue);
            scm->num_fds = num_fds;
            unsigned fd_i = 0;
            for (cmsg = (void *) msg_control; cmsg != NULL; cmsg = CMSG_NXTHDR_(cmsg, mhdr_end)) {
                if (cmsg->level != SOL_SOCKET_)
                    continue;
                fd_t *fds = (void *) cmsg->data;
                for (unsigned i = 0; i < (cmsg->len - sizeof(struct cmsghdr_)) / sizeof(fd_t); i++) {
                    STRACE(" sending fd %d", fds[i]);
                    scm->fds[fd_i++] = fd_retain(f_get(fds[i]));
                }
            }
            lock(&peer_lock);
            struct fd *peer = sock->socket.unix_peer;
            if (peer == NULL) {
                unlock(&peer_lock);
                err = _EPIPE;
                goto out_free_scm;
            }
            lock(&peer->lock);
            list_add_tail(&peer->socket.unix_scm, &scm->queue);
            unlock(&peer->lock);
            unlock(&peer_lock);
        }
    }

    msg.msg_flags = sock_flags_to_real(msg_fake.msg_flags);
    err = _EINVAL;
    if (msg.msg_flags < 0)
        goto out_free_scm;
    int real_flags = sock_flags_to_real(flags);
    if (real_flags < 0)
        goto out_free_scm;

    err = sendmsg(sock->real_fd, &msg, real_flags);
    if (err < 0) {
        err = errno_map();
        goto out_free_scm;
    }
    goto out_free_iov;

out_free_scm:
    if (scm != NULL) {
        lock(&peer_lock);
        struct fd *peer = sock->socket.unix_peer;
        if (peer != NULL) {
            lock(&peer->lock);
            list_remove_safe(&scm->queue);
            unlock(&peer->lock);
        }
        unlock(&peer_lock);
        scm_free(scm);
    }
out_free_iov:
    for (size_t i = 0; i < (size_t) msg.msg_iovlen; i++)
        free(msg_iov[i].iov_base);
    return err;
}

int_t sys_recvmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags) {
    STRACE("recvmsg(%d, %#x, %d)", sock_fd, msghdr_addr, flags);
    struct fd *sock = sock_getfd(sock_fd);
    if (sock == NULL)
        return _EBADF;

    struct msghdr msg;
    struct msghdr_ msg_fake;
    if (user_get(msghdr_addr, msg_fake))
        return _EFAULT;

    if (is_netlink_route(sock)) {
        if (!sock->socket.netlink_pending || sock->socket.netlink_response == NULL)
            return _EAGAIN;
        if (msg_fake.msg_iovlen == 0)
            return _EINVAL;
        struct iovec_ iov[msg_fake.msg_iovlen];
        if (user_get(msg_fake.msg_iov, iov))
            return _EFAULT;

        size_t response_len = sock->socket.netlink_response_len;
        size_t remaining = response_len;
        size_t off = 0;
        for (size_t i = 0; i < msg_fake.msg_iovlen && remaining != 0; i++) {
            size_t chunk = iov[i].len < remaining ? iov[i].len : remaining;
            if (user_write(iov[i].base, (uint8_t *) sock->socket.netlink_response + off, chunk))
                return _EFAULT;
            off += chunk;
            remaining -= chunk;
        }

        if (msg_fake.msg_name != 0 && msg_fake.msg_namelen != 0) {
            struct sockaddr_nl_ nl = {.family = AF_NETLINK_};
            uint_t copy_len = msg_fake.msg_namelen < sizeof(nl) ? msg_fake.msg_namelen : sizeof(nl);
            if (user_write(msg_fake.msg_name, &nl, copy_len))
                return _EFAULT;
            msg_fake.msg_namelen = sizeof(nl);
        }
        msg_fake.msg_controllen = 0;
        msg_fake.msg_flags = remaining != 0 ? MSG_TRUNC_ : 0;
        if (user_put(msghdr_addr, msg_fake))
            return _EFAULT;
        size_t result = (flags & MSG_TRUNC_) ? response_len : off;
        if (!(flags & MSG_PEEK_))
            netlink_clear_response(sock);
        return result;
    }

    // msg_name
    char msg_name[msg_fake.msg_namelen];
    if (msg_fake.msg_name != 0) {
        msg.msg_name = msg_name;
        msg.msg_namelen = sizeof(msg_name);
    } else {
        msg.msg_name = NULL;
        msg.msg_namelen = 0;
    }

    char real_msg_control[CMSG_SPACE(sizeof(int))] = {}; // only used if needed
    if (msg_fake.msg_controllen != 0) {
        // msg_control, include room for one (1) fd
        msg.msg_control = real_msg_control;
        msg.msg_controllen = sizeof(real_msg_control);
    } else {
        msg.msg_control = NULL;
        msg.msg_controllen = 0;
    }

    int real_flags = sock_flags_to_real(flags);
    if (real_flags < 0)
        return _EINVAL;

    // msg_iovec (no initial content)
    struct iovec_ msg_iov_fake[msg_fake.msg_iovlen];
    if (user_get(msg_fake.msg_iov, msg_iov_fake))
        return _EFAULT;
    struct iovec msg_iov[msg_fake.msg_iovlen];
    msg.msg_iov = msg_iov;
    msg.msg_iovlen = sizeof(msg_iov) / sizeof(msg_iov[0]);
    for (size_t i = 0; i < (size_t) msg.msg_iovlen; i++) {
        msg_iov[i].iov_len = msg_iov_fake[i].len;
        msg_iov[i].iov_base = malloc(msg_iov_fake[i].len);
    }

    ssize_t res = recvmsg(sock->real_fd, &msg, real_flags);
    int err = 0;
    if (res < 0)
        err = errno_map();
    // don't return err quite yet, there are outstanding mallocs

    // msg_iovec (changed)
    // copy as many bytes as were received, according to the return value
    size_t n = res;
    if (res < 0)
        n = 0;
    for (size_t i = 0; i < (size_t) msg.msg_iovlen; i++) {
        size_t chunk_size = msg_iov[i].iov_len;
        if (chunk_size > n)
            chunk_size = n;
        if (chunk_size > 0)
            if (user_write(msg_iov_fake[i].base, msg_iov[i].iov_base, chunk_size))
                return _EFAULT;
        n -= chunk_size;
        free(msg_iov[i].iov_base);
    }

    // msg_control (changed)
    msg_fake.msg_controllen = 0;
    struct cmsghdr *cmsg = CMSG_FIRSTHDR(&msg);
    if (sock->socket.domain == AF_LOCAL_ && cmsg != NULL &&
            cmsg->cmsg_level == SOL_SOCKET && cmsg->cmsg_type == SCM_RIGHTS) {
        int dummy_fd = ((int *) CMSG_DATA(cmsg))[0];
        close(dummy_fd);

        lock(&sock->lock);
        assert(!list_empty(&sock->socket.unix_scm));
        struct scm *scm = list_first_entry(&sock->socket.unix_scm, struct scm, queue);
        list_remove(&scm->queue);
        unlock(&sock->lock);

        if (res < 0) {
            scm_free(scm);
            return err;
        }

        uint8_t msg_control[sizeof(struct cmsghdr_) + scm->num_fds * sizeof(fd_t)];
        struct cmsghdr_ *cmsg = (void *) msg_control;
        cmsg->len = sizeof(msg_control);
        cmsg->level = SOL_SOCKET_;
        cmsg->type = SCM_RIGHTS_;
        fd_t *fds = (void *) cmsg->data;
        for (unsigned i = 0; i < scm->num_fds; i++) {
            fds[i] = f_install(scm->fds[i], 0);
            STRACE(" receiving fd %d", fds[i]);
        }
        if (user_write(msg_fake.msg_control, cmsg, cmsg->len))
            return _EFAULT;
        msg_fake.msg_controllen = msg.msg_controllen;
    }

    // by now the iovecs and scm have been freed so we can return
    if (res < 0)
        return err;

    // msg_name (changed)
    if (msg.msg_name != 0) {
        int err = sockaddr_write(msg_fake.msg_name, msg.msg_name, sizeof(msg_name), &msg.msg_namelen);
        if (err < 0)
            return err;
    }
    msg_fake.msg_namelen = msg.msg_namelen;

    // msg_flags (changed)
    msg_fake.msg_flags = sock_flags_from_real(msg.msg_flags);

    if (user_put(msghdr_addr, msg_fake))
        return _EFAULT;
    return res;
}

struct mmsghdr_ {
    struct msghdr_ hdr;
    uint_t len;
};

int_t sys_sendmmsg(fd_t sock_fd, addr_t msg_vec, uint_t vec_len, int_t flags) {
    int num_sent = 0;
    for (unsigned i = 0; i < vec_len; i++) {
        addr_t msghdr = msg_vec + i * sizeof(struct mmsghdr_);
        int_t res = sys_sendmsg(sock_fd, msghdr, flags);
        if (res >= 0) {
            addr_t msg_len_addr = msghdr + offsetof(struct mmsghdr_, len);
            if (user_put(msg_len_addr, res))
                res = _EFAULT;
        }
        if (res < 0) {
            // From the man page:
            // If an error occurs after at least one message has been sent, the
            // call succeeds, and returns the number of messages sent.  The
            // error code is lost.
            if (num_sent > 0)
                break;
            return res;
        }
        num_sent++;
        if (res == 0) {
            // This means the socket is non-blocking and can't be written to anymore.
            break;
        }
    }
    return num_sent;
}

static void sock_translate_err(struct fd *fd, int *err) {
    // on ios, when the device goes to sleep, all connected sockets are killed.
    // reads/writes return ENOTCONN, which I'm pretty sure is a violation of
    // posix. so instead, detect this and return ECONNRESET.
    if (*err == _ENOTCONN) {
        struct sockaddr addr;
        socklen_t len = sizeof(addr);
        if (getpeername(fd->real_fd, &addr, &len) < 0 && errno == EINVAL) {
            *err = _ECONNRESET;
        }
    }
}

static ssize_t sock_read(struct fd *fd, void *buf, size_t size) {
    if (is_netlink_route(fd))
        return netlink_take_response(fd, buf, size);
    int err = realfs_read(fd, buf, size);
    sock_translate_err(fd, &err);
    return err;
}

static ssize_t sock_write(struct fd *fd, const void *buf, size_t size) {
    if (is_netlink_route(fd)) {
        int err = netlink_handle_request(fd, buf, size);
        return err < 0 ? err : (ssize_t) size;
    }
    int err = realfs_write(fd, buf, size);
    sock_translate_err(fd, &err);
    return err;
}

static int sock_poll(struct fd *fd) {
    if (is_netlink_route(fd))
        return POLLOUT | (fd->socket.netlink_pending ? POLLIN : 0);
    return realfs_poll(fd);
}

static int sock_getflags(struct fd *fd) {
    if (is_netlink_route(fd))
        return fd->flags;
    return realfs_getflags(fd);
}

static int sock_setflags(struct fd *fd, dword_t flags) {
    if (is_netlink_route(fd)) {
        fd->flags = flags;
        return 0;
    }
    return realfs_setflags(fd, flags);
}

#define SIOCGIFNAME_ 0x8910
#define SIOCGIFCONF_ 0x8912
#define SIOCGIFFLAGS_ 0x8913
#define SIOCGIFADDR_ 0x8915
#define SIOCGIFDSTADDR_ 0x8917
#define SIOCGIFBRDADDR_ 0x8919
#define SIOCGIFNETMASK_ 0x891b
#define SIOCGIFMTU_ 0x8921
#define SIOCGIFHWADDR_ 0x8927
#define SIOCGIFINDEX_ 0x8933
#define SIOCGIFTXQLEN_ 0x8942
#define IFCONF32_SIZE_ 8
#define IFREQ32_SIZE_ 32
#define IFNAMSIZ_ 16

static void sock_ifreq_name(const void *arg, char ifname[IFNAMSIZ_ + 1]) {
    memcpy(ifname, arg, IFNAMSIZ_);
    ifname[IFNAMSIZ_] = '\0';
}

static void sock_linux_sockaddr4(uint8_t out[16], const struct in_addr *addr) {
    memset(out, 0, 16);
    uint16_t family = AF_INET_;
    memcpy(out, &family, sizeof(family));
    // Linux sockaddr_in has sin_port at bytes 2-3 and sin_addr at bytes 4-7.
    memcpy(out + 4, addr, sizeof(*addr));
}

static struct ifaddrs *sock_find_ifaddr(struct ifaddrs *ifap,
        const char *ifname, int family) {
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || strcmp(ifa->ifa_name, ifname) != 0)
            continue;
        if (family == AF_UNSPEC ||
                (ifa->ifa_addr != NULL && ifa->ifa_addr->sa_family == family))
            return ifa;
    }
    return NULL;
}

static int sock_ioctl_ifconf(void *arg) {
    int32_t requested_len;
    uint32_t guest_buf;
    memcpy(&requested_len, arg, sizeof(requested_len));
    memcpy(&guest_buf, (uint8_t *) arg + sizeof(requested_len),
            sizeof(guest_buf));
    if (requested_len < 0)
        return _EINVAL;

    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    size_t available = guest_buf == 0 ? SIZE_MAX : (size_t) requested_len;
    size_t used = 0;
    int err = 0;
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != AF_INET)
            continue;
        if (strlen(ifa->ifa_name) >= IFNAMSIZ_)
            continue;
        if (available != SIZE_MAX && available - used < IFREQ32_SIZE_)
            break;

        uint8_t ifreq[IFREQ32_SIZE_] = {};
        strncpy((char *) ifreq, ifa->ifa_name, IFNAMSIZ_ - 1);
        const struct sockaddr_in *sin = (const void *) ifa->ifa_addr;
        sock_linux_sockaddr4(ifreq + IFNAMSIZ_, &sin->sin_addr);

        if (guest_buf != 0 &&
                user_write((addr_t) guest_buf + used, ifreq, sizeof(ifreq))) {
            err = _EFAULT;
            break;
        }
        used += sizeof(ifreq);
    }
    freeifaddrs(ifap);
    if (err < 0)
        return err;
    if (used > INT32_MAX)
        return _EOVERFLOW;

    int32_t returned_len = (int32_t) used;
    memcpy(arg, &returned_len, sizeof(returned_len));
    return 0;
}

static ssize_t sock_ioctl_size(int cmd) {
    if (cmd == SIOCGIFCONF_)
        return IFCONF32_SIZE_;
    switch (cmd) {
        case SIOCGIFNAME_:
        case SIOCGIFFLAGS_:
        case SIOCGIFADDR_:
        case SIOCGIFDSTADDR_:
        case SIOCGIFBRDADDR_:
        case SIOCGIFNETMASK_:
        case SIOCGIFMTU_:
        case SIOCGIFHWADDR_:
        case SIOCGIFINDEX_:
        case SIOCGIFTXQLEN_:
            return IFREQ32_SIZE_;
    }
    return realfs_ioctl_size(cmd);
}

static int sock_ioctl(struct fd *fd, int cmd, void *arg) {
    if (cmd == SIOCGIFCONF_)
        return sock_ioctl_ifconf(arg);

    if (cmd == SIOCGIFNAME_) {
        // Linux userspace (including musl if_indextoname()) resolves an
        // interface index through SIOCGIFNAME. Translate the host index back
        // to the host interface name so route tools can print eth0/en0/etc.
        int32_t index;
        memcpy(&index, (uint8_t *) arg + IFNAMSIZ_, sizeof(index));
        if (index <= 0)
            return _ENODEV;

        char ifname[IFNAMSIZ_];
        if (if_indextoname((unsigned) index, ifname) == NULL)
            return errno_map();

        memset(arg, 0, IFNAMSIZ_);
        strncpy(arg, ifname, IFNAMSIZ_ - 1);
        return 0;
    }

    switch (cmd) {
        case SIOCGIFFLAGS_:
        case SIOCGIFADDR_:
        case SIOCGIFDSTADDR_:
        case SIOCGIFBRDADDR_:
        case SIOCGIFNETMASK_:
        case SIOCGIFMTU_:
        case SIOCGIFHWADDR_:
        case SIOCGIFINDEX_:
        case SIOCGIFTXQLEN_:
            break;
        default:
            return realfs_ioctl(fd, cmd, arg);
    }

    char ifname[IFNAMSIZ_ + 1];
    sock_ifreq_name(arg, ifname);
    unsigned ifindex = if_nametoindex(ifname);
    if (ifindex == 0)
        return _ENODEV;

    if (cmd == SIOCGIFINDEX_) {
        int32_t index = (int32_t) ifindex;
        memcpy((uint8_t *) arg + IFNAMSIZ_, &index, sizeof(index));
        return 0;
    }

    if (cmd == SIOCGIFTXQLEN_) {
        // Darwin/iOS has no SIOCGIFTXQLEN equivalent. A neutral queue length
        // is sufficient for Linux tools that use this as display metadata.
        int32_t qlen = 0;
        memcpy((uint8_t *) arg + IFNAMSIZ_, &qlen, sizeof(qlen));
        return 0;
    }

    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    int result = 0;
    struct ifaddrs *ifa = sock_find_ifaddr(ifap, ifname, AF_UNSPEC);
    if (ifa == NULL) {
        result = _ENODEV;
        goto out;
    }

    switch (cmd) {
        case SIOCGIFFLAGS_: {
            int16_t flags = (int16_t) netlink_linux_if_flags(ifa->ifa_flags);
            memcpy((uint8_t *) arg + IFNAMSIZ_, &flags, sizeof(flags));
            break;
        }
        case SIOCGIFMTU_: {
            uint32_t mtu = 0;
            // Some iOS pseudo-interfaces (for example XHC0) are real
            // interfaces but do not expose a nonzero ifi_mtu through
            // getifaddrs(). Linux interface consumers such as Nmap's libdnet
            // treat a failed SIOCGIFMTU as a fatal interface-enumeration
            // error. Preserve the host's "unknown/zero" value instead of
            // failing the ioctl for an interface we already know exists.
            netlink_link_mtu(ifap, ifname, &mtu);
            int32_t linux_mtu = (int32_t) mtu;
            memcpy((uint8_t *) arg + IFNAMSIZ_, &linux_mtu,
                    sizeof(linux_mtu));
            break;
        }
        case SIOCGIFHWADDR_: {
            uint8_t *sa = (uint8_t *) arg + IFNAMSIZ_;
            memset(sa, 0, 16);
            uint16_t type = (ifa->ifa_flags & IFF_LOOPBACK)
                ? ARPHRD_LOOPBACK_
                : (ifa->ifa_flags & IFF_POINTOPOINT)
                    ? ARPHRD_NONE_ : ARPHRD_ETHER_;
            memcpy(sa, &type, sizeof(type));
            uint8_t hw[14] = {};
            size_t hwlen = netlink_hwaddr(ifap, ifname, hw, sizeof(hw));
            if (hwlen != 0)
                memcpy(sa + 2, hw, hwlen);
            break;
        }
        case SIOCGIFADDR_:
        case SIOCGIFDSTADDR_:
        case SIOCGIFBRDADDR_:
        case SIOCGIFNETMASK_: {
            struct ifaddrs *inet = sock_find_ifaddr(ifap, ifname, AF_INET);
            if (inet == NULL) {
                result = _EADDRNOTAVAIL;
                break;
            }

            const struct sockaddr *host_sa = NULL;
            if (cmd == SIOCGIFADDR_)
                host_sa = inet->ifa_addr;
            else if (cmd == SIOCGIFDSTADDR_)
                host_sa = inet->ifa_dstaddr;
            else if (cmd == SIOCGIFBRDADDR_)
                host_sa = inet->ifa_broadaddr;
            else
                host_sa = inet->ifa_netmask;

            if (host_sa == NULL || host_sa->sa_family != AF_INET) {
                result = _EADDRNOTAVAIL;
                break;
            }
            const struct sockaddr_in *sin = (const void *) host_sa;
            sock_linux_sockaddr4((uint8_t *) arg + IFNAMSIZ_,
                    &sin->sin_addr);
            break;
        }
        default:
            result = realfs_ioctl(fd, cmd, arg);
            break;
    }

out:
    freeifaddrs(ifap);
    return result;
}

static int sock_close(struct fd *fd) {
    if (is_netlink_route(fd)) {
        netlink_clear_response(fd);
        return 0;
    }

    sockrestart_end_listen(fd);
    // FIXME next 3 lines should go in a function like release_unix_names
    inode_release_if_exist(fd->socket.unix_name_inode);
    if (fd->socket.unix_name_abstract != NULL)
        unix_abstract_release(fd->socket.unix_name_abstract);
    lock(&peer_lock);
    struct fd *peer = fd->socket.unix_peer;
    if (peer != NULL)
        peer->socket.unix_peer = NULL;
    unlock(&peer_lock);
    if (fd->socket.domain == AF_LOCAL_) {
        lock(&fd->lock);
        struct scm *scm, *tmp;
        list_for_each_entry_safe(&fd->socket.unix_scm, scm, tmp, queue) {
            list_remove(&scm->queue);
            scm_free(scm);
        }
        unlock(&fd->lock);
    }
    return realfs_close(fd);
}

const struct fd_ops socket_fdops = {
    .read = sock_read,
    .write = sock_write,
    .close = sock_close,
    .poll = sock_poll,
    .getflags = sock_getflags,
    .setflags = sock_setflags,
    .ioctl_size = sock_ioctl_size,
    .ioctl = sock_ioctl,
};

#if is_gcc(8) || is_clang(21)
#pragma GCC diagnostic ignored "-Wcast-function-type"
#endif
#if defined(__clang__)
#pragma GCC diagnostic ignored "-Wmissing-field-initializers"
#endif
static struct socket_call {
    syscall_t func;
    int args;
} socket_calls[] = {
    {NULL},
    {(syscall_t) sys_socket, 3},
    {(syscall_t) sys_bind, 3},
    {(syscall_t) sys_connect, 3},
    {(syscall_t) sys_listen, 2},
    {(syscall_t) sys_accept, 3},
    {(syscall_t) sys_getsockname, 3},
    {(syscall_t) sys_getpeername, 3},
    {(syscall_t) sys_socketpair, 4},
    {(syscall_t) sys_send, 4}, // send
    {(syscall_t) sys_recv, 4}, // recv
    {(syscall_t) sys_sendto, 6},
    {(syscall_t) sys_recvfrom, 6},
    {(syscall_t) sys_shutdown, 2},
    {(syscall_t) sys_setsockopt, 5},
    {(syscall_t) sys_getsockopt, 5},
    {(syscall_t) sys_sendmsg, 3},
    {(syscall_t) sys_recvmsg, 3},
    {NULL}, // accept4
    {NULL}, // recvmmsg
    {(syscall_t) sys_sendmmsg, 4},
};

int_t sys_socketcall(dword_t call_num, addr_t args_addr) {
    STRACE("%d ", call_num);
    if (call_num < 1 || call_num >= sizeof(socket_calls)/sizeof(socket_calls[0]))
        return _EINVAL;
    struct socket_call call = socket_calls[call_num];
    if (call.func == NULL) {
        FIXME("socketcall %d", call_num);
        return _ENOSYS;
    }

    dword_t args[6];
    if (user_read(args_addr, args, sizeof(dword_t) * call.args))
        return _EFAULT;
    return call.func(args[0], args[1], args[2], args[3], args[4], args[5]);
}

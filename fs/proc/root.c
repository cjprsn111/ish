#include <sys/stat.h>
#include <sys/socket.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <arpa/inet.h>
#include <net/if.h>
#include <netinet/in.h>
#include <sys/ioctl.h>
#include <string.h>
#ifndef __APPLE__
#include <linux/if_link.h>
#endif
#include "kernel/calls.h"
#include "kernel/task.h"
#include "fs/fd.h"
#include "fs/inode.h"
#include "fs/sock.h"
#include "fs/proc.h"
#include "platform/platform.h"

static int proc_show_version(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    struct uname uts;
    do_uname(&uts);
    proc_printf(buf, "%s version %s %s\n", uts.system, uts.release, uts.version);
    return 0;
}

static int proc_show_stat(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    struct cpu_usage usage = get_cpu_usage();
    proc_printf(buf, "cpu  %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64"\n", usage.user_ticks, usage.nice_ticks, usage.system_ticks, usage.idle_ticks);

    // calculate btime (boot time in seconds since epoch) by subtracting uptime from current time
    struct uptime_info uptime = get_uptime();
    struct timespec uptime_ts = {.tv_sec = uptime.uptime_ticks / 100, .tv_nsec = uptime.uptime_ticks % 100};
    struct timespec boot_time = timespec_subtract(timespec_now(CLOCK_REALTIME), uptime_ts);
    proc_printf(buf, "btime %ld\n", boot_time.tv_sec);

    return 0;
}

static int proc_show_cpuinfo(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    unsigned cpus = sysconf(_SC_NPROCESSORS_ONLN);
    for (unsigned i = 0; i < cpus; i++) {
        proc_printf(buf, "processor\t: %u\n", i);
        proc_printf(buf, "vendor_id\t: iSH\n");
        proc_printf(buf, "\n");
    }
    return 0;
}

static void show_kb(struct proc_data *buf, const char *name, uint64_t value) {
    proc_printf(buf, "%s%8"PRIu64" kB\n", name, value / 1000);
}

static int proc_show_meminfo(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    struct mem_usage usage = get_mem_usage();
    show_kb(buf, "MemTotal:       ", usage.total);
    show_kb(buf, "MemFree:        ", usage.free);
    show_kb(buf, "MemShared:      ", usage.free);
    // a bunch of crap busybox top needs to see or else it gets stack garbage
    show_kb(buf, "Shmem:          ", 0);
    show_kb(buf, "Buffers:        ", 0);
    show_kb(buf, "Cached:         ", 0);
    show_kb(buf, "SwapTotal:      ", 0);
    show_kb(buf, "SwapFree:       ", 0);
    show_kb(buf, "Dirty:          ", 0);
    show_kb(buf, "Writeback:      ", 0);
    show_kb(buf, "AnonPages:      ", 0);
    show_kb(buf, "Mapped:         ", 0);
    show_kb(buf, "Slab:           ", 0);
    return 0;
}

static int proc_show_uptime(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    struct uptime_info uptime_info = get_uptime();
    unsigned long uptime = uptime_info.uptime_ticks;
    proc_printf(buf, "%lu.%lu %lu.%lu\n", uptime / 100, uptime % 100, uptime / 100, uptime % 100);
    return 0;
}

struct proc_net_dev_stats {
    uint64_t rx_bytes;
    uint64_t rx_packets;
    uint64_t rx_errors;
    uint64_t rx_dropped;
    uint64_t rx_fifo;
    uint64_t rx_frame;
    uint64_t rx_compressed;
    uint64_t multicast;
    uint64_t tx_bytes;
    uint64_t tx_packets;
    uint64_t tx_errors;
    uint64_t tx_dropped;
    uint64_t tx_fifo;
    uint64_t collisions;
    uint64_t tx_carrier;
    uint64_t tx_compressed;
};

static void proc_net_dev_stats(struct ifaddrs *ifap, const char *name,
        struct proc_net_dev_stats *stats) {
    memset(stats, 0, sizeof(*stats));
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || strcmp(ifa->ifa_name, name) != 0 ||
                ifa->ifa_data == NULL)
            continue;
#ifdef __APPLE__
        const struct if_data *data = ifa->ifa_data;
        stats->rx_bytes = data->ifi_ibytes;
        stats->rx_packets = data->ifi_ipackets;
        stats->rx_errors = data->ifi_ierrors;
        stats->rx_dropped = data->ifi_iqdrops;
        stats->multicast = data->ifi_imcasts;
        stats->tx_bytes = data->ifi_obytes;
        stats->tx_packets = data->ifi_opackets;
        stats->tx_errors = data->ifi_oerrors;
        stats->collisions = data->ifi_collisions;
        return;
#else
        if (ifa->ifa_addr == NULL || ifa->ifa_addr->sa_family != AF_PACKET)
            continue;
        const struct rtnl_link_stats *data = ifa->ifa_data;
        stats->rx_bytes = data->rx_bytes;
        stats->rx_packets = data->rx_packets;
        stats->rx_errors = data->rx_errors;
        stats->rx_dropped = data->rx_dropped;
        stats->rx_fifo = data->rx_fifo_errors;
        stats->rx_frame = data->rx_frame_errors;
        stats->rx_compressed = data->rx_compressed;
        stats->multicast = data->multicast;
        stats->tx_bytes = data->tx_bytes;
        stats->tx_packets = data->tx_packets;
        stats->tx_errors = data->tx_errors;
        stats->tx_dropped = data->tx_dropped;
        stats->tx_fifo = data->tx_fifo_errors;
        stats->collisions = data->collisions;
        stats->tx_carrier = data->tx_carrier_errors;
        stats->tx_compressed = data->tx_compressed;
        return;
#endif
    }
}

static bool proc_net_dev_seen_before(struct ifaddrs *first,
        struct ifaddrs *current) {
    for (struct ifaddrs *ifa = first; ifa != current; ifa = ifa->ifa_next) {
        if (ifa->ifa_name != NULL &&
                strcmp(ifa->ifa_name, current->ifa_name) == 0)
            return true;
    }
    return false;
}

static int proc_show_net_dev(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    proc_printf(buf,
            "Inter-|   Receive                                                |  Transmit\n"
            " face |bytes    packets errs drop fifo frame compressed multicast|bytes    packets errs drop fifo colls carrier compressed\n");

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || proc_net_dev_seen_before(ifap, ifa))
            continue;

        struct proc_net_dev_stats stats;
        proc_net_dev_stats(ifap, ifa->ifa_name, &stats);
        proc_printf(buf,
                "%6s: %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64
                " %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64
                " %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64" %"PRIu64
                " %"PRIu64"\n",
                ifa->ifa_name,
                stats.rx_bytes, stats.rx_packets, stats.rx_errors,
                stats.rx_dropped, stats.rx_fifo, stats.rx_frame,
                stats.rx_compressed, stats.multicast,
                stats.tx_bytes, stats.tx_packets, stats.tx_errors,
                stats.tx_dropped, stats.tx_fifo, stats.collisions,
                stats.tx_carrier, stats.tx_compressed);
    }

    freeifaddrs(ifap);
    return 0;
}

static unsigned proc_net_prefix_bits(const uint8_t *mask, size_t len) {
    unsigned bits = 0;
    for (size_t i = 0; i < len; i++) {
        uint8_t byte = mask[i];
        for (int bit = 7; bit >= 0; bit--) {
            if ((byte & (1u << bit)) == 0)
                return bits;
            bits++;
        }
    }
    return bits;
}

static int proc_net_probe_default_interface(int family, const void *dst,
        char ifname[IFNAMSIZ]) {
    int fd = socket(family, SOCK_DGRAM, 0);
    if (fd < 0)
        return -1;

    struct sockaddr_storage target = {};
    socklen_t target_len;
    if (family == AF_INET) {
        struct sockaddr_in *sin = (void *) &target;
        sin->sin_family = AF_INET;
        sin->sin_port = htons(9);
        memcpy(&sin->sin_addr, dst, sizeof(sin->sin_addr));
        target_len = sizeof(*sin);
    } else if (family == AF_INET6) {
        struct sockaddr_in6 *sin6 = (void *) &target;
        sin6->sin6_family = AF_INET6;
        sin6->sin6_port = htons(9);
        memcpy(&sin6->sin6_addr, dst, sizeof(sin6->sin6_addr));
        target_len = sizeof(*sin6);
    } else {
        close(fd);
        return -1;
    }

    if (connect(fd, (void *) &target, target_len) < 0) {
        close(fd);
        return -1;
    }

    struct sockaddr_storage local = {};
    socklen_t local_len = sizeof(local);
    if (getsockname(fd, (void *) &local, &local_len) < 0) {
        close(fd);
        return -1;
    }
    close(fd);

    size_t addr_len = family == AF_INET ? sizeof(struct in_addr) :
                                         sizeof(struct in6_addr);
    const void *local_addr = family == AF_INET
        ? (const void *) &((struct sockaddr_in *) &local)->sin_addr
        : (const void *) &((struct sockaddr_in6 *) &local)->sin6_addr;

    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return -1;

    int found = -1;
    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL ||
                ifa->ifa_addr->sa_family != family)
            continue;
        const void *candidate = family == AF_INET
            ? (const void *) &((struct sockaddr_in *) ifa->ifa_addr)->sin_addr
            : (const void *) &((struct sockaddr_in6 *) ifa->ifa_addr)->sin6_addr;
        if (memcmp(candidate, local_addr, addr_len) == 0) {
            strncpy(ifname, ifa->ifa_name, IFNAMSIZ - 1);
            ifname[IFNAMSIZ - 1] = '\0';
            found = 0;
            break;
        }
    }

    freeifaddrs(ifap);
    return found;
}

static int proc_show_net_route(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    proc_printf(buf,
            "Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT\n");

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL ||
                ifa->ifa_netmask == NULL ||
                ifa->ifa_addr->sa_family != AF_INET ||
                ifa->ifa_netmask->sa_family != AF_INET)
            continue;

        const struct sockaddr_in *addr = (const void *) ifa->ifa_addr;
        const struct sockaddr_in *mask = (const void *) ifa->ifa_netmask;
        uint32_t destination = addr->sin_addr.s_addr & mask->sin_addr.s_addr;

        // Publish connected routes only. A gateway of zero means the route is
        // directly connected; never invent a default gateway in procfs.
        proc_printf(buf,
                "%s\t%08X\t%08X\t%04X\t0\t0\t0\t%08X\t0\t0\t0\n",
                ifa->ifa_name, destination, 0u, 0x0001u,
                mask->sin_addr.s_addr);
    }

    freeifaddrs(ifap);

    // /proc/net/route consumers such as Nmap/libdnet do not use rtnetlink
    // for route-table enumeration. Publish the host-selected default device
    // here as a direct default route. Keep the gateway zero unless iOS
    // exposes a trustworthy gateway elsewhere; never invent one.
    const struct in_addr probe = {.s_addr = htonl(0x01010101)};
    char default_if[IFNAMSIZ] = {};
    if (proc_net_probe_default_interface(AF_INET, &probe, default_if) == 0) {
        proc_printf(buf,
                "%s\t%08X\t%08X\t%04X\t0\t0\t0\t%08X\t0\t0\t0\n",
                default_if, 0u, 0u, 0x0001u, 0u);
    }
    return 0;
}

static int proc_show_net_if_inet6(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL ||
                ifa->ifa_netmask == NULL ||
                ifa->ifa_addr->sa_family != AF_INET6 ||
                ifa->ifa_netmask->sa_family != AF_INET6)
            continue;

        const struct sockaddr_in6 *addr = (const void *) ifa->ifa_addr;
        const struct sockaddr_in6 *mask = (const void *) ifa->ifa_netmask;
        const uint8_t *bytes = (const uint8_t *) &addr->sin6_addr;
        unsigned prefix = proc_net_prefix_bits(
                (const uint8_t *) &mask->sin6_addr, 16);
        unsigned scope = IN6_IS_ADDR_LOOPBACK(&addr->sin6_addr) ? 0x10 :
                         IN6_IS_ADDR_LINKLOCAL(&addr->sin6_addr) ? 0x20 : 0;
        unsigned index = if_nametoindex(ifa->ifa_name);
        if (index == 0)
            continue;

        for (size_t i = 0; i < 16; i++)
            proc_printf(buf, "%02x", bytes[i]);
        proc_printf(buf, " %02x %02x %02x 00 %s\n",
                index, prefix, scope, ifa->ifa_name);
    }

    freeifaddrs(ifap);
    return 0;
}

static int proc_show_net_ipv6_route(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    struct ifaddrs *ifap;
    if (getifaddrs(&ifap) < 0)
        return errno_map();

    for (struct ifaddrs *ifa = ifap; ifa != NULL; ifa = ifa->ifa_next) {
        if (ifa->ifa_name == NULL || ifa->ifa_addr == NULL ||
                ifa->ifa_netmask == NULL ||
                ifa->ifa_addr->sa_family != AF_INET6 ||
                ifa->ifa_netmask->sa_family != AF_INET6)
            continue;

        const struct sockaddr_in6 *addr = (const void *) ifa->ifa_addr;
        const struct sockaddr_in6 *mask = (const void *) ifa->ifa_netmask;
        const uint8_t *addr_bytes = (const uint8_t *) &addr->sin6_addr;
        const uint8_t *mask_bytes = (const uint8_t *) &mask->sin6_addr;
        uint8_t network[16];
        for (size_t i = 0; i < sizeof(network); i++)
            network[i] = addr_bytes[i] & mask_bytes[i];
        unsigned prefix = proc_net_prefix_bits(mask_bytes, sizeof(network));

        for (size_t i = 0; i < sizeof(network); i++)
            proc_printf(buf, "%02x", network[i]);
        proc_printf(buf, " %02x ", prefix);
        for (size_t i = 0; i < 16; i++)
            proc_printf(buf, "00");
        proc_printf(buf, " 00 ");
        for (size_t i = 0; i < 16; i++)
            proc_printf(buf, "00");
        // metric, reference count, use count, flags, interface
        proc_printf(buf, " 00000000 00000000 00000000 00000001 %s\n",
                ifa->ifa_name);
    }

    freeifaddrs(ifap);

    struct in6_addr probe6;
    char default_if[IFNAMSIZ] = {};
    if (inet_pton(AF_INET6, "2606:4700:4700::1111", &probe6) == 1 &&
            proc_net_probe_default_interface(AF_INET6, &probe6,
                    default_if) == 0) {
        for (size_t i = 0; i < 16; i++)
            proc_printf(buf, "00");
        proc_printf(buf, " 00 ");
        for (size_t i = 0; i < 16; i++)
            proc_printf(buf, "00");
        proc_printf(buf, " 00 ");
        for (size_t i = 0; i < 16; i++)
            proc_printf(buf, "00");
        proc_printf(buf,
                " 00000000 00000000 00000000 00000001 %s\n",
                default_if);
    }
    return 0;
}

extern const struct fd_ops socket_fdops;

struct proc_inet_socket {
    struct fd *fd;
    uid_t_ uid;
};

static int proc_socket_seen(struct proc_inet_socket *sockets, size_t count,
        struct fd *fd) {
    for (size_t i = 0; i < count; i++)
        if (sockets[i].fd == fd)
            return 1;
    return 0;
}

static size_t proc_collect_inet_sockets(struct proc_inet_socket **out) {
    struct proc_inet_socket *sockets = NULL;
    size_t count = 0;
    size_t cap = 0;

    lock(&pids_lock);
    for (pid_t_ pid = 1; pid <= MAX_PID; pid++) {
        struct task *task = pid_get_task(pid);
        if (task == NULL || task->files == NULL)
            continue;

        struct fdtable *table = task->files;
        lock(&table->lock);
        for (unsigned i = 0; i < table->size; i++) {
            struct fd *fd = table->files[i];
            if (fd == NULL || fd->ops != &socket_fdops || fd->real_fd < 0)
                continue;
            if (fd->socket.domain != AF_INET_ &&
                    fd->socket.domain != AF_INET6_ &&
                    fd->socket.domain != AF_LOCAL_)
                continue;
            if (fd->socket.type != SOCK_STREAM_ &&
                    fd->socket.type != SOCK_DGRAM_)
                continue;
            if (proc_socket_seen(sockets, count, fd))
                continue;

            if (count == cap) {
                size_t next = cap == 0 ? 16 : cap * 2;
                struct proc_inet_socket *grown =
                    realloc(sockets, next * sizeof(*grown));
                if (grown == NULL)
                    break;
                sockets = grown;
                cap = next;
            }
            sockets[count].fd = fd_retain(fd);
            sockets[count].uid = task->euid;
            count++;
        }
        unlock(&table->lock);
    }
    unlock(&pids_lock);

    *out = sockets;
    return count;
}

static void proc_release_inet_sockets(struct proc_inet_socket *sockets,
        size_t count) {
    for (size_t i = 0; i < count; i++)
        fd_close(sockets[i].fd);
    free(sockets);
}

static void proc_format_inet_addr(const struct sockaddr_storage *ss,
        int family, char *out, size_t out_len, unsigned *port) {
    if (family == AF_INET) {
        const struct sockaddr_in *sin = (const void *) ss;
        const uint8_t *a = (const uint8_t *) &sin->sin_addr;
        snprintf(out, out_len, "%02X%02X%02X%02X",
                a[3], a[2], a[1], a[0]);
        *port = ntohs(sin->sin_port);
        return;
    }

    const struct sockaddr_in6 *sin6 = (const void *) ss;
    const uint8_t *a = (const uint8_t *) &sin6->sin6_addr;
    size_t off = 0;
    for (size_t word = 0; word < 4 && off + 8 < out_len; word++) {
        int n = snprintf(out + off, out_len - off, "%02X%02X%02X%02X",
                a[word * 4 + 3], a[word * 4 + 2],
                a[word * 4 + 1], a[word * 4]);
        if (n < 0)
            break;
        off += (size_t) n;
    }
    *port = ntohs(sin6->sin6_port);
}

static unsigned proc_tcp_state(struct fd *fd) {
    int accepting = 0;
    socklen_t accepting_len = sizeof(accepting);
    if (getsockopt(fd->real_fd, SOL_SOCKET, SO_ACCEPTCONN,
            &accepting, &accepting_len) == 0 && accepting)
        return 0x0a; // TCP_LISTEN

    struct sockaddr_storage peer = {};
    socklen_t peer_len = sizeof(peer);
    if (getpeername(fd->real_fd, (void *) &peer, &peer_len) == 0)
        return 0x01; // TCP_ESTABLISHED

    return 0x07; // TCP_CLOSE / not connected
}

static int proc_show_net_inet(struct proc_data *buf, int family,
        int type) {
    struct proc_inet_socket *sockets;
    size_t count = proc_collect_inet_sockets(&sockets);

    proc_printf(buf,
            "  sl  local_address rem_address   st tx_queue rx_queue tr tm->when retrnsmt   uid  timeout inode\n");

    unsigned slot = 0;
    for (size_t i = 0; i < count; i++) {
        struct fd *fd = sockets[i].fd;
        if ((family == AF_INET && fd->socket.domain != AF_INET_) ||
                (family == AF_INET6 && fd->socket.domain != AF_INET6_) ||
                fd->socket.type != type)
            continue;

        if (type == SOCK_DGRAM_ &&
                fd->socket.protocol != 0 &&
                fd->socket.protocol != IPPROTO_UDP)
            continue;

        struct sockaddr_storage local = {};
        struct sockaddr_storage remote = {};
        socklen_t local_len = sizeof(local);
        socklen_t remote_len = sizeof(remote);
        if (getsockname(fd->real_fd, (void *) &local, &local_len) < 0)
            continue;

        int real_family = family == AF_INET ? AF_INET : AF_INET6;
        if (((struct sockaddr *) &local)->sa_family != real_family)
            continue;
        if (getpeername(fd->real_fd, (void *) &remote, &remote_len) < 0)
            ((struct sockaddr *) &remote)->sa_family = real_family;

        char local_addr[33] = {};
        char remote_addr[33] = {};
        unsigned local_port = 0;
        unsigned remote_port = 0;
        proc_format_inet_addr(&local, family, local_addr,
                sizeof(local_addr), &local_port);
        proc_format_inet_addr(&remote, family, remote_addr,
                sizeof(remote_addr), &remote_port);

        int rx_queue = 0;
        if (ioctl(fd->real_fd, FIONREAD, &rx_queue) < 0 || rx_queue < 0)
            rx_queue = 0;

        unsigned state = type == SOCK_STREAM_
            ? proc_tcp_state(fd) : 0x07;

        proc_printf(buf,
                "%4u: %s:%04X %s:%04X %02X "
                "00000000:%08X 00:00000000 00000000 "
                "%5u 0 0 1 0000000000000000 0 0 0 2 -1\n",
                slot++, local_addr, local_port, remote_addr, remote_port,
                state, (unsigned) rx_queue, (unsigned) sockets[i].uid);
    }

    proc_release_inet_sockets(sockets, count);
    return 0;
}

static int proc_show_net_tcp(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    return proc_show_net_inet(buf, AF_INET, SOCK_STREAM_);
}

static int proc_show_net_tcp6(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    return proc_show_net_inet(buf, AF_INET6, SOCK_STREAM_);
}

static int proc_show_net_udp(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    return proc_show_net_inet(buf, AF_INET, SOCK_DGRAM_);
}

static int proc_show_net_udp6(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    return proc_show_net_inet(buf, AF_INET6, SOCK_DGRAM_);
}

static int proc_show_net_unix(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    struct proc_inet_socket *sockets;
    size_t count = proc_collect_inet_sockets(&sockets);

    proc_printf(buf,
            "Num       RefCount Protocol Flags    Type St Inode Path\n");

    unsigned slot = 1;
    for (size_t i = 0; i < count; i++) {
        struct fd *fd = sockets[i].fd;
        if (fd->socket.domain != AF_LOCAL_)
            continue;

        int accepting = 0;
        socklen_t accepting_len = sizeof(accepting);
        int is_listener = getsockopt(fd->real_fd, SOL_SOCKET, SO_ACCEPTCONN,
                &accepting, &accepting_len) == 0 && accepting;

        struct sockaddr_storage peer = {};
        socklen_t peer_len = sizeof(peer);
        int is_connected =
            getpeername(fd->real_fd, (void *) &peer, &peer_len) == 0;

        unsigned flags = is_listener ? 0x00010000u : 0;
        unsigned state = is_connected ? 3u : 1u;
        unsigned inode = fd->socket.unix_name_inode != NULL
            ? (unsigned) fd->socket.unix_name_inode->number : 0;

        char path[110] = {};
        if (fd->socket.unix_name_len != 0) {
            size_t len = fd->socket.unix_name_len;
            if (len > sizeof(fd->socket.unix_name))
                len = sizeof(fd->socket.unix_name);

            if (fd->socket.unix_name[0] == '\0') {
                path[0] = '@';
                size_t copy = len > 1 ? len - 1 : 0;
                if (copy > sizeof(path) - 2)
                    copy = sizeof(path) - 2;
                memcpy(path + 1, fd->socket.unix_name + 1, copy);
                path[1 + copy] = '\0';
            } else {
                if (len > sizeof(path) - 1)
                    len = sizeof(path) - 1;
                memcpy(path, fd->socket.unix_name, len);
                path[len] = '\0';
            }
        }

        proc_printf(buf,
                "%016X: 00000002 00000000 %08X %04X %02X %u",
                slot++, flags, (unsigned) fd->socket.type, state, inode);
        if (path[0] != '\0')
            proc_printf(buf, " %s", path);
        proc_printf(buf, "\n");
    }

    proc_release_inet_sockets(sockets, count);
    return 0;
}

static int proc_show_net_arp(struct proc_entry *UNUSED(entry),
        struct proc_data *buf) {
    // iOS does not expose a stable public ARP/NDP table to sandboxed apps.
    // Linux tools commonly expect /proc/net/arp to exist, so expose a valid
    // empty table rather than fabricating neighbor information.
    proc_printf(buf,
            "IP address       HW type     Flags       HW address            Mask     Device\n");
    return 0;
}

static struct proc_children proc_net_children = PROC_CHILDREN({
    {"arp", .show = proc_show_net_arp},
    {"dev", .show = proc_show_net_dev},
    {"if_inet6", .show = proc_show_net_if_inet6},
    {"ipv6_route", .show = proc_show_net_ipv6_route},
    {"route", .show = proc_show_net_route},
    {"tcp", .show = proc_show_net_tcp},
    {"tcp6", .show = proc_show_net_tcp6},
    {"udp", .show = proc_show_net_udp},
    {"udp6", .show = proc_show_net_udp6},
    {"unix", .show = proc_show_net_unix},
});

static int proc_readlink_self(struct proc_entry *UNUSED(entry), char *buf) {
    sprintf(buf, "%d/", current->pid);
    return 0;
}

static void proc_print_escaped(struct proc_data *buf, const char *str) {
    for (size_t i = 0; str[i]; i++) {
        switch (str[i]) {
            case '\t': case ' ': case '\\':
                proc_printf(buf, "\\%03o", str[i]);
                break;
            default:
                proc_printf(buf, "%c", str[i]);
        }
    }
}

#define proc_printf_comma(buf, at_start, format, ...) do { \
    proc_printf((buf), "%s" format, *(at_start) ? "" : ",", ##__VA_ARGS__); \
    *(at_start) = false; \
} while (0)

static int proc_show_mounts(struct proc_entry *UNUSED(entry), struct proc_data *buf) {
    struct mount *mount;
    list_for_each_entry(&mounts, mount, mounts) {
        const char *point = mount->point;
        if (point[0] == '\0')
            point = "/";

        proc_print_escaped(buf, mount->source);
        proc_printf(buf, " ");
        proc_print_escaped(buf, point);
        proc_printf(buf, " %s ", mount->fs->name);
        bool at_start = true;
        proc_printf_comma(buf, &at_start, "%s", mount->flags & MS_READONLY_ ? "ro" : "rw");
        if (mount->flags & MS_NOSUID_)
            proc_printf_comma(buf, &at_start, "nosuid");
        if (mount->flags & MS_NODEV_)
            proc_printf_comma(buf, &at_start, "nodev");
        if (mount->flags & MS_NOEXEC_)
            proc_printf_comma(buf, &at_start, "noexec");
        if (strcmp(mount->info, "") != 0)
            proc_printf_comma(buf, &at_start, "%s", mount->info);
        proc_printf(buf, " 0 0\n");
    };
    return 0;
}

// in alphabetical order
struct proc_dir_entry proc_root_entries[] = {
    {"cpuinfo", .show = proc_show_cpuinfo},
    {"ish", S_IFDIR, .children = &proc_ish_children},
    {"meminfo", .show = proc_show_meminfo},
    {"mounts", .show = proc_show_mounts},
    {"net", S_IFDIR, .children = &proc_net_children},
    {"self", S_IFLNK, .readlink = proc_readlink_self},
    {"stat", .show = proc_show_stat},
    {"uptime", .show = proc_show_uptime},
    {"version", .show = proc_show_version},
};
#define PROC_ROOT_LEN sizeof(proc_root_entries)/sizeof(proc_root_entries[0])

static bool proc_root_readdir(struct proc_entry *UNUSED(entry), unsigned long *index, struct proc_entry *next_entry) {
    if (*index < PROC_ROOT_LEN) {
        *next_entry = (struct proc_entry) {&proc_root_entries[*index], *index, NULL, NULL, 0, 0};
        (*index)++;
        return true;
    }

    pid_t_ pid = *index - PROC_ROOT_LEN;
    if (pid <= MAX_PID) {
        lock(&pids_lock);
        do {
            pid++;
        } while (pid <= MAX_PID && pid_get_task(pid) == NULL);
        unlock(&pids_lock);
        if (pid > MAX_PID)
            return false;
        *next_entry = (struct proc_entry) {&proc_pid, .pid = pid};
        *index = pid + PROC_ROOT_LEN;
        return true;
    }

    return false;
}

struct proc_dir_entry proc_root = {NULL, S_IFDIR, .readdir = proc_root_readdir};

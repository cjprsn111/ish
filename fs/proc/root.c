#include <sys/stat.h>
#include <inttypes.h>
#include <ifaddrs.h>
#include <net/if.h>
#include <string.h>
#ifndef __APPLE__
#include <linux/if_link.h>
#endif
#include "kernel/calls.h"
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

static struct proc_children proc_net_children = PROC_CHILDREN({
    {"dev", .show = proc_show_net_dev},
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

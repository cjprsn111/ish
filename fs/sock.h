#ifndef SYS_SOCK_H
#define SYS_SOCK_H

#include <sys/socket.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include "kernel/errno.h"
#include "fs/fd.h"
#include "misc.h"
#include "debug.h"

int_t sys_socketcall(dword_t call_num, addr_t args_addr);

int_t sys_socket(dword_t domain, dword_t type, dword_t protocol);
int_t sys_bind(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len);
int_t sys_connect(fd_t sock_fd, addr_t sockaddr_addr, uint_t sockaddr_len);
int_t sys_listen(fd_t sock_fd, int_t backlog);
int_t sys_accept(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_getsockname(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_getpeername(fd_t sock_fd, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_socketpair(dword_t domain, dword_t type, dword_t protocol, addr_t sockets_addr);
int_t sys_sendto(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, dword_t sockaddr_len);
int_t sys_recvfrom(fd_t sock_fd, addr_t buffer_addr, dword_t len, dword_t flags, addr_t sockaddr_addr, addr_t sockaddr_len_addr);
int_t sys_shutdown(fd_t sock_fd, dword_t how);
int_t sys_setsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t value_len);
int_t sys_getsockopt(fd_t sock_fd, dword_t level, dword_t option, addr_t value_addr, dword_t len_addr);
int_t sys_sendmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags);
int_t sys_recvmsg(fd_t sock_fd, addr_t msghdr_addr, int_t flags);
int_t sys_sendmmsg(fd_t sock_fd, addr_t msgvec_addr, uint_t msgvec_len, int_t flags);

#define SOCKADDR_DATA_MAX 108

struct sockaddr_ {
    uint16_t family;
    char data[14];
};
struct sockaddr_max_ {
    uint16_t family;
    char data[SOCKADDR_DATA_MAX];
};

// Minimal Linux Netlink ABI. iOS/Darwin has no AF_NETLINK, so NETLINK_ROUTE
// is emulated inside iSH rather than forwarded to a host socket.
struct sockaddr_nl_ {
    uint16_t family;
    uint16_t pad;
    uint32_t pid;
    uint32_t groups;
};

struct nlmsghdr_ {
    uint32_t len;
    uint16_t type;
    uint16_t flags;
    uint32_t seq;
    uint32_t pid;
};

#define NLMSG_NOOP_ 1
#define NLMSG_ERROR_ 2
#define NLMSG_DONE_ 3

#define NLM_F_REQUEST_ 0x1
#define NLM_F_MULTI_ 0x2
#define NLM_F_ACK_ 0x4
#define NLM_F_ROOT_ 0x100
#define NLM_F_MATCH_ 0x200
#define NLM_F_DUMP_ (NLM_F_ROOT_ | NLM_F_MATCH_)

#define RTM_NEWLINK_ 16
#define RTM_GETLINK_ 18
#define RTM_NEWADDR_ 20
#define RTM_GETADDR_ 22
#define RTM_NEWROUTE_ 24
#define RTM_GETROUTE_ 26
#define RTM_NEWNEIGH_ 28
#define RTM_GETNEIGH_ 30

struct ifinfomsg_ {
    uint8_t family;
    uint8_t pad;
    uint16_t type;
    int32_t index;
    uint32_t flags;
    uint32_t change;
};

struct ifaddrmsg_ {
    uint8_t family;
    uint8_t prefixlen;
    uint8_t flags;
    uint8_t scope;
    uint32_t index;
};

struct rtmsg_ {
    uint8_t family;
    uint8_t dst_len;
    uint8_t src_len;
    uint8_t tos;
    uint8_t table;
    uint8_t protocol;
    uint8_t scope;
    uint8_t type;
    uint32_t flags;
};

struct rtattr_ {
    uint16_t len;
    uint16_t type;
};

#define IFLA_ADDRESS_ 1
#define IFLA_BROADCAST_ 2
#define IFLA_IFNAME_ 3
#define IFLA_MTU_ 4
#define IFLA_STATS_ 7
#define IFLA_OPERSTATE_ 16

struct rtnl_link_stats_ {
    uint32_t rx_packets;
    uint32_t tx_packets;
    uint32_t rx_bytes;
    uint32_t tx_bytes;
    uint32_t rx_errors;
    uint32_t tx_errors;
    uint32_t rx_dropped;
    uint32_t tx_dropped;
    uint32_t multicast;
    uint32_t collisions;
    uint32_t rx_length_errors;
    uint32_t rx_over_errors;
    uint32_t rx_crc_errors;
    uint32_t rx_frame_errors;
    uint32_t rx_fifo_errors;
    uint32_t rx_missed_errors;
    uint32_t tx_aborted_errors;
    uint32_t tx_carrier_errors;
    uint32_t tx_fifo_errors;
    uint32_t tx_heartbeat_errors;
    uint32_t tx_window_errors;
    uint32_t rx_compressed;
    uint32_t tx_compressed;
    uint32_t rx_nohandler;
};

#define IFA_ADDRESS_ 1
#define IFA_LOCAL_ 2
#define IFA_LABEL_ 3
#define IFA_BROADCAST_ 4

#define RTA_DST_ 1
#define RTA_SRC_ 2
#define RTA_IIF_ 3
#define RTA_OIF_ 4
#define RTA_GATEWAY_ 5
#define RTA_PRIORITY_ 6
#define RTA_PREFSRC_ 7

#define RT_TABLE_MAIN_ 254
#define RTPROT_KERNEL_ 2
#define RTPROT_BOOT_ 3
#define RT_SCOPE_UNIVERSE_ 0
#define RT_SCOPE_LINK_ 253
#define RT_SCOPE_HOST_ 254
#define RTN_UNICAST_ 1
#define RTN_UNREACHABLE_ 7

#define ARPHRD_ETHER_ 1
#define ARPHRD_LOOPBACK_ 772
#define ARPHRD_NONE_ 0xfffe

size_t sockaddr_size(void *p);
// result comes from malloc
struct sockaddr *sockaddr_to_real(void *p);

struct msghdr_ {
    addr_t msg_name;
    uint_t msg_namelen;
    addr_t msg_iov;
    uint_t msg_iovlen;
    addr_t msg_control;
    uint_t msg_controllen;
    int_t msg_flags;
};

struct cmsghdr_ {
    dword_t len;
    int_t level;
    int_t type;
    uint8_t data[];
};
#define SCM_RIGHTS_ 1
// copied and ported from musl
#define CMSG_LEN_(cmsg) (((cmsg)->len + sizeof(dword_t) - 1) & ~(dword_t)(sizeof(dword_t) - 1))
#define CMSG_NEXT_(cmsg) ((uint8_t *)(cmsg) + CMSG_LEN_(cmsg))
#define CMSG_NXTHDR_(cmsg, mhdr_end) ((cmsg)->len < sizeof (struct cmsghdr_) || \
        CMSG_LEN_(cmsg) + sizeof(struct cmsghdr_) >= (size_t) (mhdr_end - (uint8_t *)(cmsg)) \
        ? NULL : (struct cmsghdr_ *)CMSG_NEXT_(cmsg))

struct scm {
    struct list queue;
    unsigned num_fds;
    struct fd *fds[];
};

#define PF_LOCAL_ 1
#define PF_INET_ 2
#define PF_INET6_ 10
#define PF_NETLINK_ 16
#define AF_LOCAL_ PF_LOCAL_
#define AF_INET_ PF_INET_
#define AF_INET6_ PF_INET6_
#define AF_NETLINK_ PF_NETLINK_

#define NETLINK_ROUTE_ 0
static inline int sock_family_to_real(int fake) {
    switch (fake) {
        case PF_LOCAL_: return PF_LOCAL;
        case PF_INET_: return PF_INET;
        case PF_INET6_: return PF_INET6;
    }
    return -1;
}
static inline int sock_family_from_real(int fake) {
    switch (fake) {
        case PF_LOCAL: return PF_LOCAL_;
        case PF_INET: return PF_INET_;
        case PF_INET6: return PF_INET6_;
    }
    return -1;
}

#define SOCK_STREAM_ 1
#define SOCK_DGRAM_ 2
#define SOCK_RAW_ 3
#define SOCK_NONBLOCK_ 0x800
#define SOCK_CLOEXEC_ 0x80000

static inline int sock_type_to_real(int type, int protocol) {
    switch (type & 0xff) {
        case SOCK_STREAM_:
            if (protocol != 0 && protocol != IPPROTO_TCP)
                return -1;
            return SOCK_STREAM;
        case SOCK_DGRAM_:
            switch (protocol) {
                default:
                    return -1;
                case 0:
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                case IPPROTO_ICMPV6:
                    break;
            }
            return SOCK_DGRAM;
        case SOCK_RAW_:
            switch (protocol) {
                default:
                    return -1;
                case IPPROTO_RAW:
                case IPPROTO_UDP:
                case IPPROTO_ICMP:
                case IPPROTO_ICMPV6:
                    break;
            }
            return SOCK_DGRAM;
    }
    return -1;
}

#define MSG_OOB_ 0x1
#define MSG_PEEK_ 0x2
#define MSG_CTRUNC_  0x8
#define MSG_TRUNC_  0x20
#define MSG_DONTWAIT_ 0x40
#define MSG_EOR_    0x80
#define MSG_WAITALL_ 0x100

static inline int sock_flags_to_real(int fake) {
    int real = 0;
    if (fake & MSG_OOB_) real |= MSG_OOB;
    if (fake & MSG_PEEK_) real |= MSG_PEEK;
    if (fake & MSG_CTRUNC_) real |= MSG_CTRUNC;
    if (fake & MSG_TRUNC_) real |= MSG_TRUNC;
    if (fake & MSG_DONTWAIT_) real |= MSG_DONTWAIT;
    if (fake & MSG_EOR_) real |= MSG_EOR;
    if (fake & MSG_WAITALL_) real |= MSG_WAITALL;
    if (fake & ~(MSG_OOB_|MSG_PEEK_|MSG_CTRUNC_|MSG_TRUNC_|MSG_DONTWAIT_|MSG_EOR_|MSG_WAITALL_))
        TRACE("unimplemented socket flags %d\n", fake);
    return real;
}
static inline int sock_flags_from_real(int real) {
    int fake = 0;
    if (real & MSG_OOB) fake |= MSG_OOB_;
    if (real & MSG_PEEK) fake |= MSG_PEEK_;
    if (real & MSG_CTRUNC) fake |= MSG_CTRUNC_;
    if (real & MSG_TRUNC) fake |= MSG_TRUNC_;
    if (real & MSG_DONTWAIT) fake |= MSG_DONTWAIT_;
    if (real & MSG_EOR) fake |= MSG_EOR_;
    if (real & MSG_WAITALL) fake |= MSG_WAITALL_;
    if (real & ~(MSG_OOB|MSG_PEEK|MSG_CTRUNC|MSG_TRUNC|MSG_DONTWAIT|MSG_EOR|MSG_WAITALL))
        TRACE("unimplemented socket flags %d\n", real);
    return fake;
}

#define SOL_SOCKET_ 1

#define SO_REUSEADDR_ 2
#define SO_TYPE_ 3
#define SO_ERROR_ 4
#define SO_BROADCAST_ 6
#define SO_SNDBUF_ 7
#define SO_RCVBUF_ 8
#define SO_KEEPALIVE_ 9
#define SO_LINGER_ 13
#define SO_PEERCRED_ 17
#define SO_TIMESTAMP_ 29
#define SO_PROTOCOL_ 38
#define SO_DOMAIN_ 39
#define SO_RCVTIMEO_ 66
#define SO_SNDTIMEO_ 67
#define IP_TOS_ 1
#define IP_TTL_ 2
#define IP_HDRINCL_ 3
#define IP_RETOPTS_ 7
#define IP_MTU_DISCOVER_ 10
#define IP_RECVTTL_ 12
#define IP_RECVTOS_ 13
#define TCP_NODELAY_ 1
#define TCP_DEFER_ACCEPT_ 9
#define TCP_INFO_ 11
#define TCP_CONGESTION_ 13
#define IPV6_UNICAST_HOPS_ 16
#define IPV6_V6ONLY_ 26
#define IPV6_TCLASS_ 67
#define ICMP6_FILTER_ 1

static inline int sock_opt_to_real(int fake, int level) {
    switch (level) {
        case SOL_SOCKET_: switch (fake) {
            case SO_REUSEADDR_: return SO_REUSEADDR;
            case SO_TYPE_: return SO_TYPE;
            case SO_ERROR_: return SO_ERROR;
            case SO_BROADCAST_: return SO_BROADCAST;
            case SO_KEEPALIVE_: return SO_KEEPALIVE;
            case SO_LINGER_: return SO_LINGER;
            case SO_SNDBUF_: return SO_SNDBUF;
            case SO_RCVBUF_: return SO_RCVBUF;
            case SO_TIMESTAMP_: return SO_TIMESTAMP;
            case SO_RCVTIMEO_: return SO_RCVTIMEO;
            case SO_SNDTIMEO_: return SO_SNDTIMEO;
        } break;
        case IPPROTO_TCP: switch (fake) {
            case TCP_NODELAY_: return TCP_NODELAY;
            case TCP_DEFER_ACCEPT_: return 0; // unimplemented
#if defined(__linux__)
            case TCP_INFO_: return TCP_INFO;
            case TCP_CONGESTION_: return TCP_CONGESTION;
#endif
        } break;
        case IPPROTO_IP: switch (fake) {
            case IP_TOS_: return IP_TOS;
            case IP_TTL_: return IP_TTL;
            case IP_HDRINCL_: return IP_HDRINCL;
            case IP_RETOPTS_: return IP_RETOPTS;
            case IP_RECVTTL_: return IP_RECVTTL;
            case IP_RECVTOS_: return IP_RECVTOS;
        } break;
        case IPPROTO_IPV6: switch (fake) {
            case IPV6_UNICAST_HOPS_: return IPV6_UNICAST_HOPS;
            case IPV6_TCLASS_: return IPV6_TCLASS;
            case IPV6_V6ONLY_: return IPV6_V6ONLY;
        } break;
    }
    return -1;
}

static inline int sock_level_to_real(int fake) {
    if (fake == SOL_SOCKET_)
        return SOL_SOCKET;
    return fake;
}

extern const char *sock_tmp_prefix;

struct tcp_info_ {
    uint8_t state;
    uint8_t ca_state;
    uint8_t retransmits;
    uint8_t probes;
    uint8_t backoff;
    uint8_t options;
    uint8_t snd_wscale:4, rcv_wscale:4;

    uint32_t rto;
    uint32_t ato;
    uint32_t snd_mss;
    uint32_t rcv_mss;

    uint32_t unacked;
    uint32_t sacked;
    uint32_t lost;
    uint32_t retrans;
    uint32_t fackets;

    uint32_t last_data_sent;
    uint32_t last_ack_sent;
    uint32_t last_data_recv;
    uint32_t last_ack_recv;

    uint32_t pmtu;
    uint32_t rcv_ssthresh;
    uint32_t rtt;
    uint32_t rttvar;
    uint32_t snd_ssthresh;
    uint32_t snd_cwnd;
    uint32_t advmss;
    uint32_t reordering;

    uint32_t rcv_rtt;
    uint32_t rcv_space;

    uint32_t total_retrans;
};

#endif

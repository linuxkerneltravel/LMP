// Copyright 2023 The LMP Authors.
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// https://github.com/linuxkerneltravel/lmp/blob/develop/LICENSE
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
//
// author: blown.away@qq.com
//
// net_watcher libbpf 内核<->用户 传递信息相关结构体

#ifndef __COMMON_BPF_H
#define __COMMON_BPF_H

#include "net_watcher.h"
#include "vmlinux.h"
#include <asm-generic/errno.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <string.h>

struct ktime_info
{                   // us time stamp info发送数据包
    u64 qdisc_time; // tx包离开mac层时间戳
    u64 mac_time;   // tx、rx包到达mac层时间戳
    u64 ip_time;    // tx、rx包到达ip层时间戳
    // u64 tcp_time;      // tx、rx包到达tcp层时间戳
    u64 tran_time;            // tx、rx包到达传输层时间戳
    u64 app_time;             // rx包离开tcp层时间戳
    void *sk;                 // 此包所属 socket套接字
    u8 data[MAX_HTTP_HEADER]; // 用户层数据
};

struct packet_tuple
{
    unsigned __int128 saddr_v6; // ipv6 源地址
    unsigned __int128 daddr_v6; // ipv6 目的地址
    u32 saddr;                  // 源地址
    u32 daddr;                  // 目的地址
    u16 sport;                  // 源端口号
    u16 dport;                  // 目的端口号
    u32 seq;                    // seq报文序号
    u32 ack;                    // ack确认号
    u32 tran_flag;              // 1:tcp 2:udp
    u32 len;
};

struct tcpstate
{
    u32 saddr;
    u32 daddr;
    u16 sport;
    u16 dport;
    u16 family;
    int oldstate;
    int newstate;
    u64 time;
};

enum
{
    e_ip_rcv = 0,
    e_ip_local_deliver,
    e_ip_local_deliver_finish,
    e_ip__forward,
    e_ip_local_out,
    e_ip_output,
    e_ip_finish_output,
    e_ip_forward,
    nf_max
} nf_hook;

enum
{
    PROTO_TCP = 0,
    PROTO_UDP,
    PROTO_ICMP,
    PROTO_UNKNOWN,
    PROTO_MAX,
};

struct filtertime
{
    struct packet_tuple init;
    struct packet_tuple done;
    u64 time[nf_max];
};

struct ip_packet
{
    unsigned int saddr; // 源地址
    unsigned int daddr; // 目的地址
};

struct dns_header
{
    u16 id;      // 事务ID
    u16 flags;   // 标志字段
    u16 qdcount; // 问题部分计数
    u16 ancount; // 应答记录计数
    u16 nscount; // 授权记录计数
    u16 arcount; // 附加记录计数
};

struct dns_query
{
    struct dns_header header; // DNS头部
    char data[64];            // 可变长度数据（域名+类型+类）
};

struct dns
{
    u32 saddr;
    u32 daddr;
};

struct query_info
{
    char msql[256];
    u32 size;
    u64 start_time;
};

struct hist
{
    u64 slots[MAX_SLOTS];
    u64 latency;
    u64 cnt;
};

struct trace_event_raw_tcp_send_reset
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skbaddr;
    const void *skaddr;
    int state;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
};

struct trace_event_raw_tcp_receive_reset
{
    unsigned short common_type;
    unsigned char common_flags;
    unsigned char common_preempt_count;
    int common_pid;
    const void *skaddr;
    __u16 sport;
    __u16 dport;
    __u16 family;
    __u8 saddr[4];
    __u8 daddr[4];
    __u8 saddr_v6[16];
    __u8 daddr_v6[16];
    __u64 sock_cookie;
};
#define MAX_CONN 1000
#define MAX_SLOTS 27

static __always_inline void *
bpf_map_lookup_or_try_init(void *map, const void *key, const void *init)
{
    void *val;
    long err;

    val = bpf_map_lookup_elem(map, key);
    if (val)
        return val;

    err = bpf_map_update_elem(map, key, init,
                              BPF_NOEXIST); // 向BPF映射中插入或更新一个条目
    if (err && err != -EEXIST)              // 插入失败
        return 0;

    return bpf_map_lookup_elem(map, key); // 返回对应value值
}

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 存储每个packet_tuple包所对应的ktime_info时间戳
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, struct packet_tuple);
    __type(value, struct ktime_info);
} timestamps SEC(".maps");

// 包相关信息通过此buffer提供给userspace
struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rtt_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} udp_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} netfilter_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} mysql_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} redis_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} kfree_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} icmp_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rate_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} tcp_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} dns_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} trace_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} redis_stat_rb SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} events SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} port_rb SEC(".maps");

// 存储每个tcp连接所对应的conn_t
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, struct sock *);
    __type(value, struct conn_t);
} conns_info SEC(".maps");

// 根据ptid存储sock指针，从而在上下文无sock的内核探测点获得sock
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN);
    __type(key, u64);
    __type(value, struct sock *);
} sock_stores SEC(".maps");

// 存储每个pid所对应的udp包
struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, int);
    __type(value, struct packet_tuple);
} pid_UDP SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, struct sk_buff *);
    __type(value, struct filtertime);
} netfilter_time SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, int);
    __type(value, struct packet_tuple);
} kfree SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_CONN *MAX_PACKET);
    __type(key, struct ip_packet);
    __type(value, unsigned long long);
} icmp_time SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, struct sock *);
    __type(value, __u64);
} tcp_state SEC(".maps");

// sql 耗时
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, __u32);
    __type(value, __u64);
} mysql_time SEC(".maps");

// redis 耗时
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, __u32);
    __type(value, struct redis_query);
} redis_time SEC(".maps");

// sql请求数
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, __u64);
} sql_count SEC(".maps");

// dns计数根据每个saddr、daddr
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dns);
    __type(value, __u64);
} dns_request_count SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct dns);
    __type(value, __u64);
} dns_response_count SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, __u32);
    __type(value, struct query_info);
} queries SEC(".maps");

// 定义一个哈希映射，用于存储直方图数据
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 256 * 1024);
    __type(key, struct ip_packet);
    __type(value, struct hist);
} hists SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, u32);
    __type(value, u64);
    __uint(max_entries, 1024);
} counters SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, MAX_COMM *MAX_PACKET);
    __type(key, u32);
    __type(value, struct packet_count);
} proto_stats SEC(".maps");
struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __type(key, char *);       // 键的最大长度，假设为 256 字节
    __type(value, u32);        // 计数值
    __uint(max_entries, 1024); // 最大条目数
} key_count SEC(".maps");

struct
{
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, MAX_COMM *MAX_PACKET);
    __type(key, struct sock *);
    __type(value, u64);
} tcp_rate_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);     
    __type(key, u32);                    
    __type(value, struct tcp_args_s); 
    __uint(max_entries, 1);           
} args_map SEC(".maps");


const volatile int filter_dport = 0;
const volatile int filter_sport = 0;
const volatile int all_conn = 0, err_packet = 0, extra_conn_info = 0,
                   layer_time = 0, http_info = 0, retrans_info = 0,
                   udp_info = 0, net_filter = 0, drop_reason = 0, icmp_info = 0,
                   tcp_info = 0, dns_info = 0, stack_info = 0, mysql_info = 0,
                   redis_info = 0, rtt_info = 0, rst_info = 0,
                   protocol_count = 0, redis_stat = 0,overrun_time = 0;
;

/* help macro */

#define FILTER                                           \
    if (filter_dport && filter_dport != pkt_tuple.dport) \
        return 0;                                        \
    if (filter_sport && filter_sport != pkt_tuple.sport) \
        return 0;

// 连接的目标端口是否匹配于filter_dport的值
#define FILTER_DPORT                    \
    if (filter_dport)                   \
    {                                   \
        if (conn.dport != filter_dport) \
        {                               \
            return 0;                   \
        }                               \
    }
// 连接的源端口是否匹配于filter_sport的值
#define FILTER_SPORT                    \
    if (filter_sport)                   \
    {                                   \
        if (conn.sport != filter_sport) \
        {                               \
            return 0;                   \
        }                               \
    }

// 初始化conn_t结构
#define CONN_INIT                                            \
    struct conn_t conn = {0};                                \
    conn.pid = ptid >> 32;                                   \
    conn.ptid = ptid;                                        \
    u16 protocol = BPF_CORE_READ(sk, sk_protocol);           \
    if (protocol != IPPROTO_TCP)                             \
        return 0;                                            \
    bpf_get_current_comm(&conn.comm, sizeof(conn.comm));     \
    conn.sock = sk;                                          \
    u16 family = BPF_CORE_READ(sk, __sk_common.skc_family);  \
    __be16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport); \
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);      \
    conn.family = family;                                    \
    conn.sport = sport;                                      \
    conn.dport = __bpf_ntohs(dport);                         \
    conn.init_timestamp = bpf_ktime_get_ns() / 1000;

// 初始化conn_t地址相关信息
#define CONN_ADD_ADDRESS                                              \
    if (family == AF_INET)                                            \
    {                                                                 \
        conn.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);    \
        conn.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);        \
    }                                                                 \
    else if (family == AF_INET6)                                      \
    {                                                                 \
        bpf_probe_read_kernel(                                        \
            &conn.saddr_v6,                                           \
            sizeof(sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32), \
            &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);       \
        bpf_probe_read_kernel(                                        \
            &conn.daddr_v6,                                           \
            sizeof(sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32),     \
            &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);           \
    }

// 初始化conn其余额外信息
#define CONN_ADD_EXTRA_INFO                                                \
    if (extra_conn_info)                                                   \
    {                                                                      \
        struct tcp_sock *tp = (struct tcp_sock *)sk;                       \
        conn->srtt = BPF_CORE_READ(tp, srtt_us);                           \
        conn->duration = bpf_ktime_get_ns() / 1000 - conn->init_timestamp; \
        conn->bytes_acked = BPF_CORE_READ(tp, bytes_acked);                \
        conn->bytes_received = BPF_CORE_READ(tp, bytes_received);          \
        conn->snd_cwnd = BPF_CORE_READ(tp, snd_cwnd);                      \
        conn->rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);                        \
        conn->snd_ssthresh = BPF_CORE_READ(tp, snd_ssthresh);              \
        conn->total_retrans = BPF_CORE_READ(tp, total_retrans);            \
        conn->sndbuf = BPF_CORE_READ(sk, sk_sndbuf);                       \
        conn->sk_wmem_queued = BPF_CORE_READ(sk, sk_wmem_queued);          \
        conn->tcp_backlog = BPF_CORE_READ(sk, sk_ack_backlog);             \
        conn->max_tcp_backlog = BPF_CORE_READ(sk, sk_max_ack_backlog);     \
    }

#define CONN_INFO_TRANSFER tinfo->sk = conn->sock; // 将conn->sock赋给tinfo->sk

#define PACKET_INIT_WITH_COMMON_INFO                       \
    struct pack_t *packet;                                 \
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0); \
    if (!packet)                                           \
    {                                                      \
        return 0;                                          \
    }                                                      \
    packet->err = 0;                                       \
    packet->sock = sk;                                     \
    packet->ack = pkt_tuple.ack;                           \
    packet->seq = pkt_tuple.seq;

#define READ_ONCE(x) (*(volatile typeof(x) *)&(x))
#define WRITE_ONCE(x, val) ((*(volatile typeof(x) *)&(x)) = val)

#define INIT_PACKET_TCP_TUPLE(sk, pkt)                                  \
    struct packet_tuple pkt = {                                         \
        .saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),          \
        .daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr),              \
        .sport = BPF_CORE_READ(sk, __sk_common.skc_num),                \
        .dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), \
        .tran_flag = TCP}

#define INIT_PACKET_UDP_TUPLE(sk, pkt)                                  \
    struct packet_tuple pkt = {                                         \
        .saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr),          \
        .daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr),              \
        .sport = BPF_CORE_READ(sk, __sk_common.skc_num),                \
        .dport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport)), \
        .tran_flag = UDP}

// http data
#if defined(USE_NEW_GET_USER_DATA)
#define GET_USER_DATA(msg) BPF_CORE_READ(msg, msg_iter.iov, iov_base)
#else
#define GET_USER_DATA(msg) BPF_CORE_READ(msg, msg_iter.__iov, iov_base)
#endif

/* help macro end */

/* help functions */
// 将struct sock类型的指针转化为struct tcp_sock类型的指针
static __always_inline struct tcp_sock *tcp_sk(const struct sock *sk)
{
    return (struct tcp_sock *)sk;
}
// 将struct sk_buff类型的指针转化为struct udphdr类型的指针
static __always_inline struct udphdr *skb_to_udphdr(const struct sk_buff *skb)
{
    return (struct udphdr *)((
        BPF_CORE_READ(skb, head) +
        BPF_CORE_READ(skb, transport_header)));
}
// 将struct sk_buff类型的指针转化为struct tcphdr类型的指针
static __always_inline struct tcphdr *skb_to_tcphdr(const struct sk_buff *skb)
{
    return (struct tcphdr *)((
        BPF_CORE_READ(skb, head) +
        BPF_CORE_READ(skb, transport_header)));
}
// 将struct sk_buff类型的指针转化为struct iphdr类型的指针
static __always_inline struct iphdr *skb_to_iphdr(const struct sk_buff *skb)
{
    return (struct iphdr *)(BPF_CORE_READ(skb, head) +
                            BPF_CORE_READ(skb, network_header));
}
// 将struct sk_buff类型的指针转化为struct ipv6hdr类型的指针
static __always_inline struct ipv6hdr *
skb_to_ipv6hdr(const struct sk_buff *skb)
{
    return (struct ipv6hdr *)(BPF_CORE_READ(skb, head) +
                              BPF_CORE_READ(skb, network_header));
}
// 初始化ip_packet
static void get_ip_pkt_tuple(struct ip_packet *ipk, struct iphdr *ip)
{
    ipk->saddr = BPF_CORE_READ(ip, saddr);
    ipk->daddr = BPF_CORE_READ(ip, daddr);
}

// 初始化packet_tuple结构指针pkt_tuple
static __always_inline void get_pkt_tuple(struct packet_tuple *pkt_tuple,
                                          struct iphdr *ip,
                                          struct tcphdr *tcp)
{
    pkt_tuple->saddr = BPF_CORE_READ(ip, saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip, daddr);
    u16 sport = BPF_CORE_READ(tcp, source);
    u16 dport = BPF_CORE_READ(tcp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    //__bpf_ntohs根据字节序来转化为真实值(16位) 网络传输中为大端序(即为真实值)
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp, seq);
    u32 ack = BPF_CORE_READ(tcp, ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    //__bpf_ntohls根据字节序来转化为真实值(32位)
    pkt_tuple->ack = __bpf_ntohl(ack);

    pkt_tuple->tran_flag = TCP; // tcp包

    pkt_tuple->saddr_v6 = 0;
    pkt_tuple->daddr_v6 = 0;
    pkt_tuple->len = 0;
}
// 初始化packet_tuple结构指针pkt_tuple
static __always_inline void get_udp_pkt_tuple(struct packet_tuple *pkt_tuple,
                                              struct iphdr *ip,
                                              struct udphdr *udp)
{
    pkt_tuple->saddr = BPF_CORE_READ(ip, saddr);
    pkt_tuple->daddr = BPF_CORE_READ(ip, daddr);
    u16 sport = BPF_CORE_READ(udp, source);
    u16 dport = BPF_CORE_READ(udp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    //__bpf_ntohs根据字节序来转化为真实值(16位) 网络传输中为大端序(即为真实值)
    pkt_tuple->dport = __bpf_ntohs(dport);
    pkt_tuple->seq = 0;
    pkt_tuple->ack = 0;
    pkt_tuple->tran_flag = UDP; // udp包
}

static __always_inline void get_pkt_tuple_v6(struct packet_tuple *pkt_tuple,
                                             struct ipv6hdr *ip6h,
                                             struct tcphdr *tcp)
{
    bpf_probe_read_kernel(&pkt_tuple->saddr_v6, sizeof(pkt_tuple->saddr_v6),
                          &ip6h->saddr.in6_u.u6_addr32);
    bpf_probe_read_kernel(&pkt_tuple->daddr_v6, sizeof(pkt_tuple->daddr_v6),
                          &ip6h->daddr.in6_u.u6_addr32);
    u16 sport = BPF_CORE_READ(tcp, source);
    u16 dport = BPF_CORE_READ(tcp, dest);
    pkt_tuple->sport = __bpf_ntohs(sport);
    pkt_tuple->dport = __bpf_ntohs(dport);
    u32 seq = BPF_CORE_READ(tcp, seq);
    u32 ack = BPF_CORE_READ(tcp, ack_seq);
    pkt_tuple->seq = __bpf_ntohl(seq);
    pkt_tuple->ack = __bpf_ntohl(ack);

    pkt_tuple->tran_flag = 1; // tcp包
}
int getstack(void *ctx)
{
    int pid = bpf_get_current_pid_tgid() >> 32;
    int cpu_id = bpf_get_smp_processor_id();
    struct stacktrace_event *event;
    int cp;

    event = bpf_ringbuf_reserve(&trace_rb, sizeof(*event), 0);
    if (!event)
        return 1;

    event->pid = pid;
    event->cpu_id = cpu_id;

    if (bpf_get_current_comm(event->comm, sizeof(event->comm)))
        event->comm[0] = 0;

    event->kstack_sz =
        bpf_get_stack(ctx, event->kstack, sizeof(event->kstack), 0);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

/*
例子： log2(16384)  =14
16384 2进制表示  1000000000000000
初始值： v=16384  r=0
1、16384 > 65535 不成立,r=0； v右移动0位
2、16384 > 255 成立,shift = 8,v右移动8位100000000,r=0|8=8
3、256 > 15 成立,shift = 4,v右移4位10000,r=8|4=12
4、16 > 3 成立,shift = 2,右移2位100,r=12|2=14
5、v=4,右移1位10,r|=2>>1=1  r=14|1=14
*/

static __always_inline u64 log2(u32 v)
{
    u32 shift, r;
    // 检测v是否大于0xFFFF（65535），如果是，则将r设置为16
    r = (v > 0xFFFF) << 4;
    v >>= r; // 右移
    shift = (v > 0xFF) << 3;
    v >>= shift;
    r |= shift;
    shift = (v > 0xF) << 2;
    v >>= shift;
    r |= shift;
    shift = (v > 0x3) << 1;
    v >>= shift;
    r |= shift;
    // 右移v一位并将结果累加到r中
    r |= (v >> 1);
    return r;
}
/*
例子：log2l(4294967296)=32
4294967296 2进制表示 100000000000000000000000000000000
1、v右移32位 1
2、log2(1)=0  计算得0+32=32
*/
static __always_inline u64 log2l(u64 v)
{
    u32 hi = v >> 32; // 取v的高32位
    // 如果高32位非0，计算高32位的对数并加32
    if (hi)
        return log2(hi) + 32;
    else
        return log2(v);
}

static __always_inline int get_current_tgid()
{
    return (int)(bpf_get_current_pid_tgid() >> PID);
}

/* help functions end */

#endif

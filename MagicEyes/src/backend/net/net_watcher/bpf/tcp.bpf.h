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
// netwatcher libbpf tcp

#include "common.bpf.h"

static __always_inline int __inet_csk_accept(struct sock *sk) {
    if (sk == NULL) { // newsk is null
        // bpf_printk("inet_accept_ret err: newsk is null\n");
        return 0;
    }
    u64 ptid = bpf_get_current_pid_tgid();

    CONN_INIT // 初始化conn_t结构中基本信息
        conn.is_server = 1;

    FILTER_DPORT // 过滤目标端口

        FILTER_SPORT // 过滤源端口

            CONN_ADD_ADDRESS // conn_t结构中增加地址信息

        // 更新/插入conns_info中的键值对
        int err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    if (err) { // 更新错误
        // bpf_printk("inet_accept update err.\n");
        return 0;
    }

    return 0;
}

static __always_inline int __tcp_v4_connect(const struct sock *sk) {
    u64 ptid = bpf_get_current_pid_tgid();
    int err = bpf_map_update_elem(&sock_stores, &ptid, &sk, BPF_ANY);
    // 更新/插入sock_stores中的键值对
    if (err) {
        // bpf_printk("tcp_v4_connect update sock_stores err.\n");
        return 0;
    }
    return 0;
}

static __always_inline int __tcp_v4_connect_exit(int ret) {
    u64 ptid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &ptid);

    if (skp == NULL) {
        return 0;
    }
    // bpf_printk("tcp_v4_connect_exit\n");
    if (ret != 0) { // 连接失败
        // bpf_printk("tcp_v4_connect_exit but ret %d\n", ret);
        bpf_map_delete_elem(&sock_stores, &ptid); // 删除对应键值对
        return 0;
    }
    struct sock *sk = *skp;
    CONN_INIT
    conn.is_server = 0; // 主动连接

    FILTER_DPORT // 过滤目标端口

        FILTER_SPORT // 过滤源端口

            CONN_ADD_ADDRESS // conn_t结构中增加地址信息

        long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    // 更新conns_info中sk对应的conn
    if (err) {
        return 0;
    }
    return 0;
}

static __always_inline int __tcp_v6_connect(const struct sock *sk) {
    u64 pid = bpf_get_current_pid_tgid(); // 获取pid
    int err = bpf_map_update_elem(&sock_stores, &pid, &sk, BPF_ANY);
    // 更新sock_stores中对应pid对应的sk
    if (err) {
        return 0;
    }
    return 0;
}

static __always_inline int __tcp_v6_connect_exit(int ret) {
    u64 ptid = bpf_get_current_pid_tgid(); // 获取pid
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &ptid);
    // 获得sock_stores中ptid对应的*sk 用skp指向
    if (skp == NULL) {
        return 0;
    }
    if (ret != 0) {
        bpf_map_delete_elem(&sock_stores, &ptid);
        return 0;
    }
    struct sock *sk = *skp;

    CONN_INIT               // 初始化conn_t结构中基本信息
        conn.is_server = 0; // 主动连接

    FILTER_DPORT // 过滤目标端口

        FILTER_SPORT // 过滤源端口

            CONN_ADD_ADDRESS // conn_t结构中增加地址信息

        long err = bpf_map_update_elem(&conns_info, &sk, &conn, BPF_ANY);
    // 更新conns_info中sk对应的conn
    if (err) {
        return 0;
    }
    // bpf_printk("tcp_v4_connect_exit update sk: %p.\n", sk);
    return 0;
}
static __always_inline int __tcp_set_state(struct sock *sk, int state) {
    if (all_conn) {
        return 0;
    }
    struct conn_t *value = bpf_map_lookup_elem(&conns_info, &sk);
    // 查找sk对应的conn_t
    if (state == TCP_CLOSE && value != NULL) { // TCP_CLOSE置1 说明关闭连接
        // delete
        bpf_map_delete_elem(&sock_stores, &value->ptid); // 删除sock_stores
        bpf_map_delete_elem(&conns_info, &sk);           // 删除conns_info
    }
    return 0;
}

// receive error packet
static __always_inline int __tcp_validate_incoming(struct sock *sk,
                                                   struct sk_buff *skb) {
    if (!err_packet) {
        return 0;
    }
    if (sk == NULL || skb == NULL)
        return 0;
    struct conn_t *conn =
        bpf_map_lookup_elem(&conns_info, &sk); // BPFmap查找与套接字sk关联的信息
    if (conn == NULL) {
        return 0;
    }
    struct tcp_skb_cb *tcb = TCP_SKB_CB(skb);  // 数据包信息
    u32 start_seq = BPF_CORE_READ(tcb, seq);   // 开始序列号
    u32 end_seq = BPF_CORE_READ(tcb, end_seq); // 结束序列号
    struct tcp_sock *tp = tcp_sk(sk);          // 套接字信息
    u32 rcv_wup = BPF_CORE_READ(
        tp, rcv_wup); // 接收方已经确认并准备接收的数据最后一个字节的序列号
    u32 rcv_nxt =
        BPF_CORE_READ(tp, rcv_nxt); // 期望发送发下次发送的数据字节序列号
    u32 rcv_wnd = BPF_CORE_READ(tp, rcv_wnd);         // tcp接收窗口大小
    u32 receive_window = rcv_wup + rcv_nxt - rcv_wnd; // 当前可用的接收窗口
    receive_window = 0;

    if (end_seq >= rcv_wup && rcv_nxt + receive_window >= start_seq) {
        // bpf_printk("error_identify: tcp seq validated. \n");
        return 0;
        // 检查数据包序列号是否在接收窗口内
    }
    // bpf_printk("error_identify: tcp seq err. \n");
    //  invalid seq
    u16 family = BPF_CORE_READ(
        sk, __sk_common.skc_family); // 获取套接字的地址族就是获得当前ip协议
    struct packet_tuple pkt_tuple = {0};
    if (family == AF_INET) {
        struct iphdr *ip = skb_to_iphdr(skb);
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        get_pkt_tuple(&pkt_tuple, ip, tcp);
    } else if (family == AF_INET6) {
        struct ipv6hdr *ip6h = skb_to_ipv6hdr(skb);
        struct tcphdr *tcp = skb_to_tcphdr(skb);
        get_pkt_tuple_v6(&pkt_tuple, ip6h, tcp);
    } else {
        return 0;
    }
    struct pack_t *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
    if (!packet) {
        return 0;
    }
    packet->err = 1; // 错误标记此数据包有问题
    packet->sock = sk;
    packet->ack = pkt_tuple.ack;
    packet->seq = pkt_tuple.seq;
    bpf_ringbuf_submit(packet, 0);
    return 0;
}
static __always_inline int skb_checksum_complete(int ret) {
    if (!err_packet) {
        return 0;
    }
    u64 pid = bpf_get_current_pid_tgid();
    struct sock **skp = bpf_map_lookup_elem(&sock_stores, &pid);
    if (skp == NULL) {
        return 0;
    }
    if (ret == 0) {
        // bpf_printk("error_identify: tcp checksum validated. \n");
        return 0;
    }
    // bpf_printk("error_identify: tcp checksum error. \n");
    struct sock *sk = *skp;
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }
    struct pack_t *packet;
    packet = bpf_ringbuf_reserve(&rb, sizeof(*packet), 0);
    if (!packet) {
        return 0;
    }
    packet->err = 2;   // 校验和错误
    packet->sock = sk; // 存储socket信息到sock字段中
    bpf_ringbuf_submit(packet, 0);

    return 0;
}
// retrans packet
static __always_inline int __tcp_enter_recovery(struct sock *sk) {
    if (!retrans_info) {
        return 0;
    }
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        // bpf_printk("get a v4 rx pack but conn not record, its sock is: %p",
        // sk);
        return 0;
    }
    conn->fastRe += 1; // 统计进入tcp恢复状态的次数

    return 0;
}
static __always_inline int __tcp_enter_loss(struct sock *sk) {
    if (!retrans_info) {
        return 0;
    }
    struct conn_t *conn = bpf_map_lookup_elem(&conns_info, &sk);
    if (conn == NULL) {
        return 0;
    }
    conn->timeout += 1;
    return 0;
}
static __always_inline int
__handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    if (ctx->protocol != IPPROTO_TCP)
        return 0;

    struct sock *sk = (struct sock *)ctx->skaddr;
    __u64 *before_time, new_time, time;

    before_time = bpf_map_lookup_elem(&tcp_state, &sk);
    new_time = bpf_ktime_get_ns();
    if (!before_time)
        time = 0;
    else
        time = (new_time - *before_time) / 1000;
    struct tcpstate tcpstate = {};
    tcpstate.oldstate = ctx->oldstate;
    tcpstate.newstate = ctx->newstate;
    tcpstate.family = ctx->family;
    tcpstate.sport = ctx->sport;
    tcpstate.dport = ctx->dport;
    bpf_probe_read_kernel(&tcpstate.saddr, sizeof(tcpstate.saddr),
                          &sk->__sk_common.skc_rcv_saddr);
    bpf_probe_read_kernel(&tcpstate.daddr, sizeof(tcpstate.daddr),
                          &sk->__sk_common.skc_daddr);
    tcpstate.time = time;

    if (ctx->newstate == TCP_CLOSE)
        bpf_map_delete_elem(&tcp_state, &sk);
    else
        bpf_map_update_elem(&tcp_state, &sk, &new_time, BPF_ANY);

    struct tcp_state *message;
    message = bpf_ringbuf_reserve(&tcp_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }

    message->saddr = tcpstate.saddr;
    message->daddr = tcpstate.daddr;
    message->sport = tcpstate.sport;
    message->dport = tcpstate.dport;
    message->oldstate = tcpstate.oldstate;
    message->newstate = tcpstate.newstate;
    message->time = tcpstate.time;

    bpf_ringbuf_submit(message, 0);
    return 0;
}

static __always_inline int __tcp_rcv_established(struct sock *sk,
                                                 struct sk_buff *skb) {
    const struct inet_sock *inet = (struct inet_sock *)(sk);
    struct tcp_sock *ts;
    struct hist *histp;
    u64 slot;
    u32 srtt;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct tcphdr *tcp = skb_to_tcphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_pkt_tuple(&pkt_tuple, ip, tcp);
    //  INIT_PACKET_TCP_TUPLE(sk, pkt_tuple);
    struct ip_packet key = {.saddr = pkt_tuple.saddr, .daddr = pkt_tuple.daddr};

    histp = bpf_map_lookup_elem(&hists, &key);
    if (!histp) {

        struct hist zero = {};
        bpf_map_update_elem(&hists, &key, &zero, BPF_ANY);
        histp = bpf_map_lookup_elem(&hists, &key);
        if (!histp)
            return 0;
    }
    ts = (struct tcp_sock *)(sk);

    // 读取并处理SRTT（平滑往返时间）
    srtt = BPF_CORE_READ(ts, srtt_us) >> 3;
    // 计算对数值，根据得到的结果决定数据应该归入直方图的哪个槽位
    slot = log2l(srtt);
    if (slot >= MAX_SLOTS)
        slot = MAX_SLOTS - 1; // 确保槽位置不超过最大槽数

    // 更新
    __sync_fetch_and_add(&histp->slots[slot], 1);
    __sync_fetch_and_add(&histp->latency, srtt);
    __sync_fetch_and_add(&histp->cnt, 1);

    struct RTT *message;
    message = bpf_ringbuf_reserve(&rtt_rb, sizeof(*message), 0);
    if (!message) {
        return 0;
    }
    message->saddr = pkt_tuple.saddr;
    message->daddr = pkt_tuple.daddr;
    //  bpf_printk("Saddr:%u Daddr:%u", pkt_tuple.saddr, pkt_tuple.daddr);
    bpf_probe_read_kernel(message->slots, sizeof(message->slots), histp->slots);
    message->latency = histp->latency;
    message->cnt = histp->cnt;
    // bpf_printk("Updating histogram: latency %llu, cnt %llu, slot %llu,
    // slot_count %llu", histp->latency, histp->cnt, slot, histp->slots[slot]);
    bpf_ringbuf_submit(message, 0);
    return 0;
}

static __always_inline int ret(void *ctx, u8 direction, u16 sport, u16 dport) {
    struct reset_event_t *message =
        bpf_ringbuf_reserve(&events, sizeof(*message), 0);
    if (!message)
        return 0;

    message->pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&message->comm, sizeof(message->comm));

    struct sock *sk = (struct sock *)ctx;
    message->family = BPF_CORE_READ(sk, __sk_common.skc_family);
    message->timestamp = bpf_ktime_get_ns() / 1000;

    if (message->family == AF_INET) {
        if (direction == 0) { // Send
            message->saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
            message->daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
        } else { // Receive
            message->saddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
            message->daddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
        }
        message->saddr_v6 = 0;
        message->daddr_v6 = 0;
    } else if (message->family == AF_INET6) {
        if (direction == 0) { // Send
            bpf_probe_read_kernel(
                &message->saddr_v6, sizeof(message->saddr_v6),
                &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(
                &message->daddr_v6, sizeof(message->daddr_v6),
                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
        } else { // Receive
            bpf_probe_read_kernel(
                &message->saddr_v6, sizeof(message->saddr_v6),
                &sk->__sk_common.skc_v6_daddr.in6_u.u6_addr32);
            bpf_probe_read_kernel(
                &message->daddr_v6, sizeof(message->daddr_v6),
                &sk->__sk_common.skc_v6_rcv_saddr.in6_u.u6_addr32);
        }

        message->saddr = 0;
        message->daddr = 0;
    }

    if (direction == 0) { // Send
        message->sport = bpf_ntohs(sport);
        message->dport = bpf_ntohs(dport);
    } else { // Receive
        message->sport = bpf_ntohs(dport);
        message->dport = bpf_ntohs(sport);
    }
    message->direction = direction;

    // 增加 RST 计数
    u32 pid = message->pid;
    u64 *count = bpf_map_lookup_elem(&counters, &pid);
    if (count) {
        *count += 1;
    } else {
        u64 initial_count = 1;
        bpf_map_update_elem(&counters, &pid, &initial_count, BPF_ANY);
        count = &initial_count;
    }
    message->count = *count;

    bpf_ringbuf_submit(message, 0);

    return 0;
}
static __always_inline int
__handle_send_reset(struct trace_event_raw_tcp_send_reset *ctx) {
    struct sock *sk = (struct sock *)ctx->skaddr;
    if (!sk)
        return 0;
    //   bpf_printk("Send reset: sport=%u, dport=%u\n", ctx->sport, ctx->dport);
    return ret((void *)ctx->skaddr, 0, ctx->sport, ctx->dport);
}

static __always_inline int
__handle_receive_reset(struct trace_event_raw_tcp_receive_reset *ctx) {
    struct sock *sk = (struct sock *)ctx->skaddr;
    if (!sk)
        return 0;
    //  bpf_printk("Receive reset: sport=%u, dport=%u\n", ctx->sport,
    //  ctx->dport);
    return ret((void *)ctx->skaddr, 1, ctx->sport, ctx->dport);
}

// 获取当前采样周期
static __always_inline u64 get_period(void) {
    u32 key = 0;
    u64 period = TIME_THRESHOLD_NS; // 默认值
    struct tcp_args_s *args;

    // 查找用户设置的采样周期
    args = (struct tcp_args_s *)bpf_map_lookup_elem(&args_map, &key);
    if (args) {
        period = args->sample_period;
    }

    return period;
}

static __always_inline int
__handle_tcp_rcv_space_adjust(struct bpf_raw_tracepoint_args *ctx) {
    struct sock *sk = (struct sock *)ctx->args[0];
    if (!sk)
        return 0;

    u64 current_time = bpf_ktime_get_ns();

    // 从 tcp_rate_map 中查找上次采样时间
    u64 *last_time = bpf_map_lookup_elem(&tcp_rate_map, &sk);

    // 如果没有找到上次采样时间，首次采样时设置为当前时间
    if (last_time) {
        if ((current_time - *last_time) < get_period()) {
            return 0;
        }
    }

    bpf_map_update_elem(&tcp_rate_map, &sk, &current_time, BPF_ANY);

    struct inet_connection_sock *icsk = (struct inet_connection_sock *)sk;
    if (!icsk)
        return 0;

    struct tcp_rate *message =
        bpf_ringbuf_reserve(&rate_rb, sizeof(*message), 0);
    if (!message)
        return 0;

    message->skbap.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    message->skbap.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    message->skbap.sport = __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_num));
    message->skbap.dport =
        __bpf_ntohs(BPF_CORE_READ(sk, __sk_common.skc_dport));
    message->tcp_rto = BPF_CORE_READ(icsk, icsk_rto);
    //  BPF_CORE_READ(icsk, icsk_ack.ato);
    message->pid = get_current_tgid();
    message->tcp_delack_max = BPF_CORE_READ(icsk, icsk_delack_max);
    bpf_ringbuf_submit(message, 0);

    return 0;
}

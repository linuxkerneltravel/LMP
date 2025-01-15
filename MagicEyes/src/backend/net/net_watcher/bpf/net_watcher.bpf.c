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
// tcpwatch libbpf 内核函数

#include "common.bpf.h"

#include "netfilter.bpf.h"

#include "icmp.bpf.h"

#include "tcp.bpf.h"

#include "packet.bpf.h"

#include "udp.bpf.h"

#include "mysql.bpf.h"

#include "redis.bpf.h"

#include "drop.bpf.h"

// accecpt an TCP connection
SEC("kretprobe/inet_csk_accept")
int BPF_KRETPROBE(inet_csk_accept_exit, // 接受tcp连接
                  struct sock *sk) {    // this func return a newsk
    return __inet_csk_accept(sk);
}

// connect an TCP connection
SEC("kprobe/tcp_v4_connect") // 进入tcp_v4_connect
int BPF_KPROBE(tcp_v4_connect, const struct sock *sk) {
    return __tcp_v4_connect(sk);
}

SEC("kretprobe/tcp_v4_connect") // 退出tcp_v4_connect
int BPF_KRETPROBE(tcp_v4_connect_exit, int ret) {
    return __tcp_v4_connect_exit(ret);
}

SEC("kprobe/tcp_v6_connect") // 进入tcp_v6_connect函数
int BPF_KPROBE(tcp_v6_connect, const struct sock *sk) {
    return __tcp_v6_connect(sk);
}

SEC("kretprobe/tcp_v6_connect") // 退出tcp_v6_connect函数
int BPF_KRETPROBE(tcp_v6_connect_exit, int ret) {
    return __tcp_v6_connect_exit(ret);
}

// erase CLOSED TCP connection
SEC("kprobe/tcp_set_state")
int BPF_KPROBE(tcp_set_state, struct sock *sk, int state) {
    return __tcp_set_state(sk, state);
}

/*!
in_ipv4:
    kprobe/eth_type_trans
    kprobe/ip_rcv_core.isra.0
    kprobe/tcp_v4_rcv
    kprobe/tcp_v4_do_rcv
    kprobe/skb_copy_datagram_iter

in_ipv6:
    kprobe/eth_type_trans
    kprobe/ip6_rcv_core.isra.0
    kprobe/tcp_v6_rcv
    kprobe/tcp_v6_do_rcv
    kprobe/skb_copy_datagram_iter

out_ipv4:
    kprobe/tcp_sendmsg
    kprobe/ip_queue_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

out_ipv6:
    kprobe/tcp_sendmsg
    kprobe/inet6_csk_xmit
    kprobe/dev_queue_xmit
    kprobe/dev_hard_start_xmit

*/
/************************************************ receive path
 * ****************************************/
/** in ipv4 && ipv6 */
SEC("kprobe/eth_type_trans") // 进入eth_type_trans
int BPF_KPROBE(eth_type_trans, struct sk_buff *skb) {
    if (protocol_count) {
        return sum_protocol(skb, false); // receive
    } else {
        return __eth_type_trans(skb);
    }
}

/** in only ipv4 */
SEC("kprobe/ip_rcv_core") // 跟踪记录ipv4数据包在内核中的处理时间
int BPF_KPROBE(ip_rcv_core, struct sk_buff *skb) { return __ip_rcv_core(skb); }
/** in only ipv6 */
SEC("kprobe/ip6_rcv_core")
int BPF_KPROBE(ip6_rcv_core, struct sk_buff *skb) {
    return __ip6_rcv_core(skb);
}

/**in only ipv4 */       // 接收数据包
SEC("kprobe/tcp_v4_rcv") // 记录数据包在tcpv4层时间戳
int BPF_KPROBE(tcp_v4_rcv, struct sk_buff *skb) { return __tcp_v4_rcv(skb); }

/** in only ipv6 */
SEC("kprobe/tcp_v6_rcv") // 接收tcpv6数据包
int BPF_KPROBE(tcp_v6_rcv, struct sk_buff *skb) { return __tcp_v6_rcv(skb); }

// v4 & v6 do_rcv to get sk and other info
SEC("kprobe/tcp_v4_do_rcv")
int BPF_KPROBE(tcp_v4_do_rcv, struct sock *sk, struct sk_buff *skb) {
    return __tcp_v4_do_rcv(sk, skb);
}
SEC("kprobe/tcp_v6_do_rcv") // tcp层包时间
int BPF_KPROBE(tcp_v6_do_rcv, struct sock *sk, struct sk_buff *skb) {
    return __tcp_v6_do_rcv(sk, skb);
}

/** in ipv4 && ipv6 */
SEC("kprobe/skb_copy_datagram_iter") // 处理网络数据包，记录分析包在不同网络层之间的时间差，分ipv4以及ipv6
int BPF_KPROBE(skb_copy_datagram_iter, struct sk_buff *skb) {
    return __skb_copy_datagram_iter(skb);
}

// receive error packet
/* TCP invalid seq error */
// 根据传入的数据包提取关键信息（如IP和TCP头部信息），并将这些信息与其他元数据（如套接字信息和错误标识）一同存储到BPF
// ring buffer中
SEC("kprobe/tcp_validate_incoming") // 验证传入数据包的序列号
int BPF_KPROBE(tcp_validate_incoming, struct sock *sk, struct sk_buff *skb) {
    return __tcp_validate_incoming(sk, skb);
}
// 跟踪网络数据包检测tcp检验和错误
/* TCP invalid checksum error*/
SEC("kretprobe/__skb_checksum_complete")
int BPF_KRETPROBE(__skb_checksum_complete_exit, int ret) {
    return skb_checksum_complete(ret);
}

/**** send path ****/
/*!
 * \brief: 获取数据包进入TCP层时刻的时间戳, 发送tcp层起始点
 *         out ipv4 && ipv6
 */
SEC("kprobe/tcp_sendmsg") // 跟踪tcp发送包信息
int BPF_KPROBE(tcp_sendmsg, struct sock *sk, struct msghdr *msg, size_t size) {
    return __tcp_sendmsg(sk, msg, size);
}

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip,
tcp)获取ip段的数据 out only ipv4
*/
SEC("kprobe/ip_queue_xmit")
int BPF_KPROBE(ip_queue_xmit, struct sock *sk, struct sk_buff *skb) {
    return __ip_queue_xmit(sk, skb);
};

/*!
* \brief: 获取数据包进入IP层时刻的时间戳
* tips:   此时ip数据段还没有数据，不能用 get_pkt_tuple(&pkt_tuple, ip,
tcp)获取ip段的数据 out only ipv6
*/
SEC("kprobe/inet6_csk_xmit")
int BPF_KPROBE(inet6_csk_xmit, struct sock *sk, struct sk_buff *skb) {
    return __inet6_csk_xmit(sk, skb);
};

/*!
* \brief: 获取数据包进入数据链路层时刻的时间戳
    out ipv4 && ipv6
*/
SEC("kprobe/__dev_queue_xmit")
int BPF_KPROBE(__dev_queue_xmit, struct sk_buff *skb) {
    return dev_queue_xmit(skb);
};

/*!
* \brief: 获取数据包发送时刻的时间戳
    out ipv4 && ipv6
*/
SEC("kprobe/dev_hard_start_xmit")
int BPF_KPROBE(dev_hard_start_xmit, struct sk_buff *skb) {
    if (protocol_count) {
        return sum_protocol(skb, true); // send
    } else {
        return __dev_hard_start_xmit(skb);
    }
};

// retrans
/* 在进入快速恢复阶段时，不管是基于Reno或者SACK的快速恢复，
 * 还是RACK触发的快速恢复，都将使用函数tcp_enter_recovery进入
 * TCP_CA_Recovery拥塞阶段。
 */
SEC("kprobe/tcp_enter_recovery") // tcp连接进入恢复状态调用
int BPF_KPROBE(tcp_enter_recovery, struct sock *sk) {
    return __tcp_enter_recovery(sk);
}

/* Enter Loss state. If we detect SACK reneging, forget all SACK information
 * and reset tags completely, otherwise preserve SACKs. If receiver
 * dropped its ofo queue, we will know this due to reneging detection.
 * 在报文的重传定时器到期时，在tcp_retransmit_timer函数中，进入TCP_CA_Loss拥塞状态。
 */
SEC("kprobe/tcp_enter_loss")
int BPF_KPROBE(tcp_enter_loss, struct sock *sk) { return __tcp_enter_loss(sk); }

/* udp */
//收包 udp_rcv-->__udp_enqueue_schedule_skb(数据包排队)
SEC("kprobe/udp_rcv")
int BPF_KPROBE(udp_rcv, struct sk_buff *skb) {
    if (udp_info)
        return __udp_rcv(skb);
    else if (dns_info)
        return __dns_rcv(skb);
    else
        return 0;
}

SEC("kprobe/__udp_enqueue_schedule_skb")
int BPF_KPROBE(__udp_enqueue_schedule_skb, struct sock *sk,
               struct sk_buff *skb) {
    return udp_enqueue_schedule_skb(sk, skb);
}
//发包 udp_send_skb-->ip_send_skb（skb 交给 IP 协议层）
SEC("kprobe/udp_send_skb")
int BPF_KPROBE(udp_send_skb, struct sk_buff *skb) {
    if (udp_info)
        return __udp_send_skb(skb);
    else if (dns_info)
        return __dns_send(skb);
    else
        return 0;
}
SEC("kprobe/ip_send_skb")
int BPF_KPROBE(ip_send_skb, struct net *net, struct sk_buff *skb) {
    return __ip_send_skb(skb);
}

// netfilter
SEC("kprobe/ip_rcv")
int BPF_KPROBE(ip_rcv, struct sk_buff *skb, struct net_device *dev,
               struct packet_type *pt, struct net_device *orig_dev) {
    return store_nf_time(skb, e_ip_rcv);
}

SEC("kprobe/ip_local_deliver")
int BPF_KPROBE(ip_local_deliver, struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_local_deliver);
}

SEC("kprobe/ip_local_deliver_finish")
int BPF_KPROBE(ip_local_deliver_finish, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_local_deliver_finish);
}

SEC("kprobe/ip_local_out")
int BPF_KPROBE(ip_local_out, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_local_out);
}

SEC("kprobe/ip_output")
int BPF_KPROBE(ip_output, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_output);
}

SEC("kprobe/__ip_finish_output")
int BPF_KPROBE(__ip_finish_output, struct net *net, struct sock *sk,
               struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_finish_output);
}

SEC("kprobe/ip_forward")
int BPF_KPROBE(ip_forward, struct sk_buff *skb) {
    return store_nf_time(skb, e_ip_forward);
}

// drop
SEC("tp/skb/kfree_skb")
int tp_kfree(struct trace_event_raw_kfree_skb *ctx) { return __tp_kfree(ctx); }

SEC("kprobe/icmp_rcv")
int BPF_KPROBE(icmp_rcv, struct sk_buff *skb) { return __icmp_time(skb); }

SEC("kprobe/__sock_queue_rcv_skb")
int BPF_KPROBE(__sock_queue_rcv_skb, struct sock *sk, struct sk_buff *skb) {
    return __rcvend_icmp_time(skb);
}

SEC("kprobe/icmp_reply")
int BPF_KPROBE(icmp_reply, struct icmp_bxm *icmp_param, struct sk_buff *skb) {
    return __reply_icmp_time(skb);
}

// mysql
SEC("uprobe/_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command")
int BPF_UPROBE(query__start) { return __handle_mysql_start(ctx); }

SEC("uretprobe/_Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command")
int BPF_UPROBE(query__end) { return __handle_mysql_end(ctx); }

//redis
SEC("uprobe/processCommand")
int BPF_KPROBE(redis_processCommand) { 
    return __handle_redis_start(ctx); }

SEC("uretprobe/call")
int BPF_KPROBE(redis_call) { return __handle_redis_end(ctx); }

SEC("uprobe/lookupKey")
int BPF_UPROBE(redis_lookupKey) {
    return __handle_redis_key(ctx);
}
SEC("uprobe/addReply")
int BPF_UPROBE(redis_addReply) {
    return __handle_redis_value(ctx);
}
// rtt
SEC("kprobe/tcp_rcv_established")
int BPF_KPROBE(tcp_rcv_established, struct sock *sk, struct sk_buff *skb) {
       return __tcp_rcv_established(sk, skb);
}

// tcpstate
SEC("tracepoint/sock/inet_sock_set_state")
int handle_set_state(struct trace_event_raw_inet_sock_set_state *ctx) {
    return __handle_set_state(ctx);
}

SEC("tracepoint/tcp/tcp_send_reset")
int handle_send_reset(struct trace_event_raw_tcp_send_reset *ctx) {
    return __handle_send_reset(ctx);
}

SEC("tracepoint/tcp/tcp_receive_reset")
int handle_receive_reset(struct trace_event_raw_tcp_receive_reset *ctx) {
    return __handle_receive_reset(ctx);
}

SEC("raw_tracepoint/tcp_rcv_space_adjust")
int handle_tcp_rcv_space_adjust(struct bpf_raw_tracepoint_args  *ctx) {
    return __handle_tcp_rcv_space_adjust(ctx);
}

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

#include "common.bpf.h"
// receive
static __always_inline int __udp_rcv(struct sk_buff *skb)
{
    if (!udp_info || skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
    FILTER
    struct ktime_info *tinfo, zero = {0};
    tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&timestamps,
                                                            &pkt_tuple, &zero);
    if (tinfo == NULL)
    {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    return 0;
}
static __always_inline int udp_enqueue_schedule_skb(struct sock *sk,
                                                    struct sk_buff *skb)
{
    if (!udp_info || skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
    FILTER
    struct ktime_info *tinfo, zero = {0};
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL)
    {
        return 0;
    }
    struct udp_message *message;
    struct udp_message *udp_message =
        bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    message = bpf_ringbuf_reserve(&udp_rb, sizeof(*message), 0);
    if (!message)
    {
        return 0;
    }
    message->saddr = pkt_tuple.saddr;
    message->daddr = pkt_tuple.daddr;
    message->dport = pkt_tuple.dport;
    message->sport = pkt_tuple.sport;
    message->tran_time = bpf_ktime_get_ns() / 1000 - tinfo->tran_time;
    message->rx = 1; // 收包
    message->len = __bpf_ntohs(BPF_CORE_READ(udp, len)) - UDP_HEAD;
    bpf_ringbuf_submit(message, 0);
    return 0;
}
// send
static __always_inline int __udp_send_skb(struct sk_buff *skb)
{
    if (!udp_info || skb == NULL)
        return 0;
    struct packet_tuple pkt_tuple = {0};
    struct sock *sk = BPF_CORE_READ(skb, sk);
    u16 dport = BPF_CORE_READ(sk, __sk_common.skc_dport);
    u16 sport = BPF_CORE_READ(sk, __sk_common.skc_num);
    pkt_tuple.saddr = BPF_CORE_READ(sk, __sk_common.skc_rcv_saddr);
    pkt_tuple.daddr = BPF_CORE_READ(sk, __sk_common.skc_daddr);
    pkt_tuple.sport = sport;
    pkt_tuple.dport = __bpf_ntohs(dport);
    pkt_tuple.tran_flag = UDP;
    FILTER
    struct ktime_info *tinfo, zero = {0};

    /** 注意： 
     * bpf_printk在老的Linux内核（在kernel 5.15测试）上，只支持三个以内的参数
     * 可查看： https://github.com/libbpf/libbpf-bootstrap/issues/206
    */
    //bpf_printk("udp_send_skb%d %d %d %d", pkt_tuple.saddr, pkt_tuple.daddr,
    //           pkt_tuple.sport, pkt_tuple.dport);
    bpf_printk("udp_send_skb s&d addr: %d %d", pkt_tuple.saddr, pkt_tuple.daddr);
    bpf_printk("udp_send_skb s&d port: %d %d", pkt_tuple.sport, pkt_tuple.dport);

    tinfo = (struct ktime_info *)bpf_map_lookup_or_try_init(&timestamps,
                                                            &pkt_tuple, &zero);
    if (tinfo == NULL)
    {
        return 0;
    }
    tinfo->tran_time = bpf_ktime_get_ns() / 1000;
    return 0;
}
static __always_inline int __ip_send_skb(struct sk_buff *skb)
{
    if (!udp_info || skb == NULL)
        return 0;
    struct iphdr *ip = skb_to_iphdr(skb);
    struct udphdr *udp = skb_to_udphdr(skb);
    struct packet_tuple pkt_tuple = {0};
    get_udp_pkt_tuple(&pkt_tuple, ip, udp);
    FILTER
    struct ktime_info *tinfo, zero = {0};
    tinfo = bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    if (tinfo == NULL)
    {
        return 0;
    }
    struct udp_message *message;
    struct udp_message *udp_message =
        bpf_map_lookup_elem(&timestamps, &pkt_tuple);
    message = bpf_ringbuf_reserve(&udp_rb, sizeof(*message), 0);
    if (!message)
    {
        return 0;
    }

    message->tran_time = bpf_ktime_get_ns() / 1000 - tinfo->tran_time;
    message->saddr = pkt_tuple.saddr;
    message->daddr = pkt_tuple.daddr;
    message->sport = pkt_tuple.sport;
    message->dport = pkt_tuple.dport;
    message->rx = 0; // 发包
    message->len = __bpf_ntohs(BPF_CORE_READ(udp, len)) - UDP_HEAD;
    bpf_ringbuf_submit(message, 0);
    return 0;
}
static __always_inline int process_dns_packet(struct sk_buff *skb, int rx)
{
    if (skb == NULL)
        return 0;
    u16 QR_flags;
    u64 *count_ptr, response_count = 0, request_count = 0;
    struct sock *sk = BPF_CORE_READ(skb, sk);
    INIT_PACKET_UDP_TUPLE(sk, pkt_tuple);
    // 使用saddr、daddr作为key
    struct dns key = {.saddr = pkt_tuple.saddr, .daddr = pkt_tuple.daddr};

    if ((pkt_tuple.sport != 53) && (pkt_tuple.dport != 53))
        return 0;

    struct dns_information *message =
        bpf_ringbuf_reserve(&dns_rb, sizeof(*message), 0);
    if (!message)
        return 0;

    // 计算dns数据开始偏移  传输层头部的位置加上 UDP 头部的大小
    u32 dns_offset =
        BPF_CORE_READ(skb, transport_header) + sizeof(struct udphdr);
    struct dns_query query;
    // dns头部位置
    bpf_probe_read_kernel(&query.header, sizeof(query.header),
                          BPF_CORE_READ(skb, head) + dns_offset);
    // dns数据部分
    bpf_probe_read_kernel(message->data, sizeof(message->data),
                          BPF_CORE_READ(skb, head) + dns_offset +
                              sizeof(struct dns_header));
    QR_flags = __bpf_ntohs(query.header.flags);
    /*
    1000 0000 0000 0000
    &运算提取最高位QR， QR=1 Response QR=0 Request
    */
    if (QR_flags & 0x8000)
    { // 响应
        count_ptr = bpf_map_lookup_elem(&dns_response_count, &key);
        if (count_ptr)
        {
            response_count = *count_ptr + 1;
        }
        else
        {
            response_count = 1;
        }
        bpf_map_update_elem(&dns_response_count, &key, &response_count,
                            BPF_ANY);
        // 保留映射中的请求计数值
        count_ptr = bpf_map_lookup_elem(&dns_request_count, &key);
        if (count_ptr)
        {
            request_count = *count_ptr;
        }
    }
    else
    { // 请求
        count_ptr = bpf_map_lookup_elem(&dns_request_count, &key);
        if (count_ptr)
        {
            request_count = *count_ptr + 1;
        }
        else
        {
            request_count = 1;
        }
        bpf_map_update_elem(&dns_request_count, &key, &request_count, BPF_ANY);
        // 保留映射中的响应计数值
        count_ptr = bpf_map_lookup_elem(&dns_response_count, &key);
        if (count_ptr)
        {
            response_count = *count_ptr;
        }
    }
    message->saddr = rx ? pkt_tuple.saddr : pkt_tuple.daddr;
    message->daddr = rx ? pkt_tuple.daddr : pkt_tuple.saddr;
    message->id = __bpf_ntohs(query.header.id);
    message->flags = __bpf_ntohs(query.header.flags);
    message->qdcount = __bpf_ntohs(query.header.qdcount);
    message->ancount = __bpf_ntohs(query.header.ancount);
    message->nscount = __bpf_ntohs(query.header.nscount);
    message->arcount = __bpf_ntohs(query.header.arcount);
    message->request_count = request_count;
    message->response_count = response_count;
    message->rx = rx;

    bpf_ringbuf_submit(message, 0);
    return 0;
}
static __always_inline int __dns_rcv(struct sk_buff *skb)
{
    return process_dns_packet(skb, 0); // 0 收
}

static __always_inline int __dns_send(struct sk_buff *skb)
{
    return process_dns_packet(skb, 1); // 1 发
}

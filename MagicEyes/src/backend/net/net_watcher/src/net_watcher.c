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
// net_watcher libbpf 用户态代码

#include "net_watcher/include/net_watcher.h"
#include "net_watcher/include/dropreason.h"
#include "net/net_watcher/net_watcher.skel.h"
#include "../include/net_watcher_hepler.h"
#include <argp.h>
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <netinet/in.h>
#include <netinet/tcp.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/time.h>
#include <time.h>
#include <unistd.h>

static volatile bool exiting = false;
struct packet_count proto_stats[256] = {0};
static struct reset_event_t event_store[MAX_EVENTS];
int event_count = 0, num_symbols = 0, cache_size = 0, map_fd, count[NUM_LAYERS] = {0};
static u64 sample_period = TIME_THRESHOLD_NS, rst_count = 0;
static char binary_path[64] = "", *dst_ip = NULL, *src_ip = NULL;
static int sport = 0, dport = 0; // for filter
static int all_conn = 0, err_packet = 0, extra_conn_info = 0, layer_time = 0,
           http_info = 0, retrans_info = 0, udp_info = 0, net_filter = 0,
           drop_reason = 0, addr_to_func = 0, icmp_info = 0, tcp_info = 0,
           time_load = 0, dns_info = 0, stack_info = 0, mysql_info = 0,
           redis_info = 0, count_info = 0, rtt_info = 0, rst_info = 0,
           protocol_count = 0, redis_stat = 0, overrun_time = 0; // flag
struct SymbolEntry symbols[300000];
struct SymbolEntry cache[CACHEMAXSIZE];
float ewma_values[NUM_LAYERS] = {0};

static const char argp_program_doc[] = "Watch tcp/ip in network subsystem \n";
static const struct argp_option opts[] = {
    {"all", 'a', 0, 0, "set to trace CLOSED connection"},
    {"err", 'e', 0, 0, "set to trace TCP error packets"},
    {"extra", 'x', 0, 0, "set to trace extra conn info"},
    {"retrans", 'r', 0, 0, "set to trace extra retrans info"},
    {"time", 't', 0, 0, "set to trace layer time of each packet"},
    {"http", 'i', 0, 0, "set to trace http info"},
    {"sport", 's', "SPORT", 0, "trace this source port only"},
    {"dport", 'd', "DPORT", 0, "trace this destination port only"},
    {"src-ip", 'S', "SRC_IP", 0, "Filter by source IP address"},
    {"dst-ip", 'D', "DST_IP", 0, "Filter by destination IP address"},
    {"udp", 'u', 0, 0, "trace the udp message"},
    {"net_filter", 'n', 0, 0, "trace ipv4 packget filter "},
    {"drop_reason", 'k', 0, 0, "trace kfree "},
    {"addr_to_func", 'F', 0, 0, "translation addr to func and offset"},
    {"icmptime", 'I', 0, 0, "set to trace layer time of icmp"},
    {"tcpstate", 'P', 0, 0, "set to trace tcpstate"},
    {"timeload", 'L', 0, 0, "analysis time load"},
    {"dns", 'N', 0, 0,
     "set to trace dns information info include Id 事务ID、Flags 标志字段、Qd "
     "问题部分计数、An 应答记录计数、Ns 授权记录计数、Ar 附加记录计数、Qr "
     "域名、rx 收发包 、Qc请求数、Sc响应数"},
    {"stack", 'A', 0, 0, "set to trace of stack "},
    {"mysql", 'M', 0, 0,
     "set to trace mysql information info include Pid 进程id、Comm "
     "进程名、Size sql语句字节大小、Sql 语句"},
    {"redis", 'R', 0, 0},
    {"redis-stat", 'b', 0, 0},
    {"count", 'C', "NUMBER", 0,
     "specify the time to count the number of requests"},
    {"rtt", 'T', 0, 0, "set to trace rtt"},
    {"rst_counters", 'U', 0, 0, "set to trace rst"},
    {"protocol_count", 'p', 0, 0, "set to trace protocol count"},
    {"overrun_time", 'o', "PERIOD", 0, "set to trace rto overrun"},
    {NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help"},
    {}};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    char *end;
    switch (key)
    {
    case 'a':
        all_conn = 1;
        break;
    case 'e':
        err_packet = 1;
        break;
    case 'x':
        extra_conn_info = 1;
        break;
    case 'r':
        retrans_info = 1;
        break;
    case 't':
        layer_time = 1;
        break;
    case 'i':
        http_info = 1;
        break;
    case 's':
        sport = strtoul(arg, &end, 10);
        break;
    case 'd':
        dport = strtoul(arg, &end, 10);
        break;
    case 'S':
        src_ip = arg;
        break;
    case 'D':
        dst_ip = arg;
        break;
    case 'u':
        udp_info = 1;
        break;
    case 'n':
        net_filter = 1;
        break;
    case 'k':
        drop_reason = 1;
        break;
    case 'F':
        addr_to_func = 1;
        break;
    case 'I':
        icmp_info = 1;
        break;
    case 'P':
        tcp_info = 1;
        break;
    case 'L':
        time_load = 1;
        break;
    case 'N':
        dns_info = 1;
        break;
    case 'A':
        stack_info = 1;
        break;
    case 'M':
        mysql_info = 1;
        break;
    case 'R':
        redis_info = 1;
        break;
    case 'T':
        rtt_info = 1;
        break;
    case 'U':
        rst_info = 1;
        break;
    case 'p':
        protocol_count = 1;
        break;
    case 'b':
        redis_stat = 1;
        break;
    case 'C':
        count_info = strtoul(arg, &end, 10);
        break;
    case 'o':
        overrun_time = strtoul(arg, &end, 10);
        break;
    case 'h':
        argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
        break;
    default:
        return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};
enum MonitorMode
{
    MODE_UDP,
    MODE_NET_FILTER,
    MODE_DROP_REASON,
    MODE_ICMP,
    MODE_TCP,
    MODE_DNS,
    MODE_MYSQL,
    MODE_REDIS,
    MODE_RTT,
    MODE_RST,
    MODE_PROTOCOL_COUNT,
    MODE_REDIS_STAT,
    MODE_EXTRA_CONN,
    MODE_RETRANS,
    MODE_CONN,
    MODE_ERROR,
    MODE_OVERTIME,
    MODE_DEFAULT
};
enum MonitorMode get_monitor_mode()
{
    if (udp_info)
    {
        return MODE_UDP;
    }
    else if (net_filter)
    {
        return MODE_NET_FILTER;
    }
    else if (drop_reason)
    {
        return MODE_DROP_REASON;
    }
    else if (icmp_info)
    {
        return MODE_ICMP;
    }
    else if (tcp_info)
    {
        return MODE_TCP;
    }
    else if (dns_info)
    {
        return MODE_DNS;
    }
    else if (mysql_info)
    {
        return MODE_MYSQL;
    }
    else if (redis_info)
    {
        return MODE_REDIS;
    }
    else if (redis_stat)
    {
        return MODE_REDIS_STAT;
    }
    else if (rtt_info)
    {
        return MODE_RTT;
    }
    else if (rst_info)
    {
        return MODE_RST;
    }
    else if (protocol_count)
    {
        return MODE_PROTOCOL_COUNT;
    }
    else if (extra_conn_info)
    {
        return MODE_EXTRA_CONN;
    }
    else if (retrans_info)
    {
        return MODE_RETRANS;
    }
    else if (all_conn)
    {
        return MODE_CONN;
    }
    else if (err_packet)
    {
        return MODE_ERROR;
    }
    else if (overrun_time)
    {
        return MODE_OVERTIME;
    }
    else
    {
        return MODE_DEFAULT;
    }
}
static void set_rodata_flags(struct net_watcher_bpf *skel)
{
    skel->rodata->filter_dport = dport;
    skel->rodata->filter_sport = sport;
    skel->rodata->all_conn = all_conn;
    skel->rodata->err_packet = err_packet;
    skel->rodata->extra_conn_info = extra_conn_info;
    skel->rodata->layer_time = layer_time;
    skel->rodata->http_info = http_info;
    skel->rodata->retrans_info = retrans_info;
    skel->rodata->udp_info = udp_info;
    skel->rodata->net_filter = net_filter;
    skel->rodata->drop_reason = drop_reason;
    skel->rodata->tcp_info = tcp_info;
    skel->rodata->icmp_info = icmp_info;
    skel->rodata->dns_info = dns_info;
    skel->rodata->stack_info = stack_info;
    skel->rodata->mysql_info = mysql_info;
    skel->rodata->redis_info = redis_info;
    skel->rodata->redis_stat = redis_stat;
    skel->rodata->rtt_info = rtt_info;
    skel->rodata->rst_info = rst_info;
    skel->rodata->protocol_count = protocol_count;
    skel->rodata->overrun_time = overrun_time;
}
static void set_disable_load(struct net_watcher_bpf *skel)
{

    bpf_program__set_autoload(skel->progs.inet_csk_accept_exit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v4_connect,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v4_connect_exit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v6_connect,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v6_connect_exit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_set_state,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.eth_type_trans,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info || protocol_count)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.ip_rcv_core,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.ip6_rcv_core,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v4_rcv,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v6_rcv,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v4_do_rcv,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_v6_do_rcv,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.skb_copy_datagram_iter,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_validate_incoming,
                              err_packet ? true : false);
    bpf_program__set_autoload(skel->progs.__skb_checksum_complete_exit,
                              err_packet ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_sendmsg,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.ip_queue_xmit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.inet6_csk_xmit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.__dev_queue_xmit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.dev_hard_start_xmit,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info || protocol_count)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.tcp_enter_recovery,
                              retrans_info ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_enter_loss,
                              retrans_info ? true : false);
    bpf_program__set_autoload(skel->progs.udp_rcv,
                              udp_info || dns_info ? true : false);
    bpf_program__set_autoload(skel->progs.__udp_enqueue_schedule_skb,
                              udp_info || dns_info ? true : false);
    bpf_program__set_autoload(skel->progs.udp_send_skb,
                              udp_info || dns_info ? true : false);
    bpf_program__set_autoload(skel->progs.ip_send_skb,
                              udp_info || dns_info ? true : false);
    bpf_program__set_autoload(skel->progs.ip_rcv, net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.ip_local_deliver,
                              net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.ip_local_deliver_finish,
                              net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.ip_local_out,
                              net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.ip_output, net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.__ip_finish_output,
                              net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.ip_forward,
                              net_filter ? true : false);
    bpf_program__set_autoload(skel->progs.tp_kfree, drop_reason ? true : false);
    bpf_program__set_autoload(skel->progs.icmp_rcv, icmp_info ? true : false);
    bpf_program__set_autoload(skel->progs.__sock_queue_rcv_skb,
                              icmp_info ? true : false);
    bpf_program__set_autoload(skel->progs.icmp_reply, icmp_info ? true : false);
    bpf_program__set_autoload(skel->progs.handle_set_state,
                              tcp_info ? true : false);
    bpf_program__set_autoload(skel->progs.query__start,
                              mysql_info ? true : false);
    bpf_program__set_autoload(skel->progs.query__end,
                              mysql_info ? true : false);
    bpf_program__set_autoload(skel->progs.redis_addReply,
                              redis_stat ? true : false);
    bpf_program__set_autoload(skel->progs.redis_lookupKey,
                              redis_stat ? true : false);
    bpf_program__set_autoload(skel->progs.redis_processCommand,
                              redis_info ? true : false);
    bpf_program__set_autoload(skel->progs.redis_call,
                              redis_info ? true : false);
    bpf_program__set_autoload(skel->progs.tcp_rcv_established,
                              (all_conn || err_packet || extra_conn_info ||
                               retrans_info || layer_time || http_info ||
                               rtt_info)
                                  ? true
                                  : false);
    bpf_program__set_autoload(skel->progs.handle_send_reset,
                              rst_info ? true : false);
    bpf_program__set_autoload(skel->progs.handle_receive_reset,
                              rst_info ? true : false);
    bpf_program__set_autoload(skel->progs.handle_tcp_rcv_space_adjust,
                              overrun_time ? true : false);
}
static void print_header(enum MonitorMode mode)
{
    switch (mode)
    {
    case MODE_UDP:
        printf("==============================================================="
               "UDP "
               "INFORMATION===================================================="
               "====\n");
        printf("%-20s %-20s %-20s %-20s %-20s %-20s %-20s\n", "Saddr", "Sport",
               "Daddr", "Dprot", "udp_time/μs", "RX/direction", "len/byte");
        break;
    case MODE_NET_FILTER:
        printf("==============================================================="
               "===NETFILTER "
               "INFORMATION===================================================="
               "=======\n");
        printf("%-20s %-20s %-12s %-12s %-8s %-8s %-7s %-8s %-8s %-8s\n",
               "Saddr", "Sport", "Daddr", "Dprot", "PreRT/μs", "L_IN/μs",
               "FW/μs", "PostRT/μs", "L_OUT/μs", "RX/direction");
        break;
    case MODE_DROP_REASON:
        printf("==============================================================="
               "DROP "
               "INFORMATION===================================================="
               "====\n");
        printf("%-13s %-17s %-17s %-10s %-10s %-9s %-33s %-30s\n", "Time",
               "Saddr", "Sport", "Daddr", "Dprot", "prot", "addr", "reason");
        break;
    case MODE_ICMP:
        printf("=================================================ICMP "
               "INFORMATION==============================================\n");
        printf("%-20s %-20s %-20s %-20s\n", "Saddr", "Daddr", "icmp_time/μs",
               "RX/direction");
        break;
    case MODE_TCP:
        printf("==============================================================="
               "TCP STATE "
               "INFORMATION===================================================="
               "====\n");
        printf("%-20s %-20s %-20s %-20s %-20s %-20s %-20s \n", "Saddr", "Sport",
               "Daddr", "Dport", "oldstate", "newstate", "time/μs");
        break;
    case MODE_DNS:
        printf("==============================================================="
               "====================DNS "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-20s %-20s %-12s %-12s %-5s %-5s %-5s %-5s %-47s %-10s %-10s "
               "%-10s \n",
               "Saddr", "Daddr", "Id", "Flags", "Qd", "An", "Ns", "Ar", "Qr",
               "Qc", "Sc", "RX/direction");
        break;
    case MODE_MYSQL:
        printf("==============================================================="
               "====================MYSQL "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-20s %-20s %-20s %-20s %-40s %-20s %-20s  \n", "Pid", "Tid",
               "Comm", "Size", "Sql", "Duration/μs", "Request");
        break;
    case MODE_REDIS:
        printf("==============================================================="
               "====================REDIS "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-20s %-20s %-20s %-20s %-20s \n", "Pid", "Comm", "Size",
               "Redis", "duration/μs");
        break;
    case MODE_REDIS_STAT:
        printf("==============================================================="
               "====================REDIS "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-20s %-20s %-20s %-20s %-20s %-20s\n", "Pid", "Comm", "key", "Key_count", "Value_Type", "Value");
        break;
    case MODE_RTT:
        printf("==============================================================="
               "====================RTT "
               "INFORMATION===================================================="
               "============================\n");
        break;
    case MODE_RST:
        printf("==============================================================="
               "====================RST "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-10s %-20s %-10s %-10s %-10s %-10s %-20s \n", "Pid", "Comm",
               "Saddr", "Sport", "Daddr", "Dport", "Time");
        break;
    case MODE_EXTRA_CONN:
        printf("==============================================================="
               "====================EXTRA CONN "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-15s %-15s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-10s %-13s %-10s %-10s %-10s %-10s\n", "Saddr", "Sport", "Daddr", "Dport", "backlog", "maxbacklog", "rwnd", "cwnd", "ssthresh", "sndbuf", "wmem_queued", "rx_bytes", "tx_bytes", "srtt", "duration");
        break;
    case MODE_RETRANS:
        printf("==============================================================="
               "====================RETRANS "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-15s %-15s %-10s %-10s %-10s %-10s %-10s\n", "Saddr", "Sport", "Daddr", "Dport", "fastRe", "total_retrans", "timeout");
        break;
    case MODE_CONN:
        printf("==============================================================="
               "====================CONN "
               "INFORMATION===================================================="
               "============================\n");
        printf("%-15s %-20s %-15s %-15s %-10s %-10s %-10s\n", "Pid", "Sock", "Saddr", "Sport", "Daddr", "Dport", "Is_Server");
        break;
    case MODE_DEFAULT:
        printf("==============================================================="
               "=INFORMATION==================================================="
               "======================\n");
        printf("%-22s %-20s %-8s %-20s %-8s %-15s %-15s %-15s %-14s %-14s %-14s %-16s \n",
               "SOCK", "Saddr", "Sport", "Daddr", "Dport", "MAC_TIME/μs",
               "IP_TIME/μs", "TRAN_TIME/μs", "Seq", "Ack", "RX/direction", "HTTP");
        break;
    case MODE_ERROR:
        printf("==============================================================="
               "=ERROR INFORMATION==================================================="
               "======================\n");
        printf("%-22s %-20s %-8s %-20s %-8s %-14s %-14s %-15s \n",
               "SOCK", "Saddr", "Sport", "Daddr", "Dport", "Seq", "Ack", "Reason");
        break;
    case MODE_OVERTIME:
        printf("==============================================================="
               "=OVERTIME INFORMATION==================================================="
               "======================\n");
        printf("%-20s %-20s %-20s %-20s %-20s %-20s\n",
               "Saddr", "Sport", "Daddr", "Dport", "RTO", "Delack_max");
        break;
    case MODE_PROTOCOL_COUNT:
        printf("==============================================================="
               "=MODE_PROTOCOL_COUNT==========================================="
               "========"
               "======================\n");
        break;
    }
}

static void sig_handler(int signo) { exiting = true; }

static int print_conns(struct net_watcher_bpf *skel)
{

    int map_fd = bpf_map__fd(skel->maps.conns_info);
    struct sock *sk = NULL;

    while (bpf_map_get_next_key(map_fd, &sk, &sk) == 0)
    {
        // fprintf(stdout, "next_sk: (%p)\n", sk);
        struct conn_t d = {};
        int err = bpf_map_lookup_elem(map_fd, &sk, &d);
        if (err)
        {
            fprintf(stderr, "Failed to read value from the conns map: (%s)\n",
                    strerror(errno));
            return 0;
        }
        char s_str[INET_ADDRSTRLEN];
        char d_str[INET_ADDRSTRLEN];

        char s_str_v6[INET6_ADDRSTRLEN];
        char d_str_v6[INET6_ADDRSTRLEN];

        char s_ip_port_str[INET6_ADDRSTRLEN + 6];
        char d_ip_port_str[INET6_ADDRSTRLEN + 6];

        if (d.family == AF_INET)
        {
            inet_ntop(AF_INET, &d.saddr, s_str, sizeof(s_str));
            inet_ntop(AF_INET, &d.daddr, d_str, sizeof(d_str));
            sprintf(s_ip_port_str, "%s:%d", s_str, d.sport);
            sprintf(d_ip_port_str, "%s:%d", d_str, d.dport);
        }
        else
        {
            inet_ntop(AF_INET6, &d.saddr_v6, s_str_v6, sizeof(s_str_v6));
            inet_ntop(AF_INET6, &d.daddr_v6, d_str_v6, sizeof(d_str_v6));
            sprintf(s_ip_port_str, "%s:%d", s_str_v6, d.sport);
            sprintf(d_ip_port_str, "%s:%d", d_str_v6, d.dport);
        }

        char s_ip_only[INET_ADDRSTRLEN];
        char d_ip_only[INET_ADDRSTRLEN];
        strncpy(s_ip_only, s_str, sizeof(s_ip_only));
        strncpy(d_ip_only, d_str, sizeof(d_ip_only));

        char received_bytes[11], acked_bytes[11];
        bytes_to_str(received_bytes, d.bytes_received);
        bytes_to_str(acked_bytes, d.bytes_acked);

        if (extra_conn_info)
        {
            printf("%-15s %-10d %-15s %-10d %-10u %-10u %-10u %-10u %-10u %-10u %-13u %-10s %-10s %-10u %-10llu\n",
                   s_ip_only, d.sport, d_ip_only, d.dport, d.tcp_backlog,
                   d.max_tcp_backlog, d.rcv_wnd, d.snd_cwnd, d.snd_ssthresh,
                   d.sndbuf, d.sk_wmem_queued, received_bytes, acked_bytes, d.srtt,
                   d.duration);
        }
        if (retrans_info)
        {
            printf("%-15s %-10d %-15s %-10d %-10u %-14u %-10u\n", s_ip_only, d.sport, d_ip_only, d.dport, d.fastRe, d.total_retrans, d.timeout);
        }
        if (all_conn)
        {
            printf("%-15d %-20p %-15s %-10d %-15s %-10d %-10u\n", d.pid, d.sock, s_ip_only, d.sport, d_ip_only, d.dport, d.is_server);
        }
    }
    return 0;
}
static int print_packet(void *ctx, void *packet_info, size_t size)
{
    if (udp_info || net_filter || drop_reason || icmp_info || tcp_info || all_conn ||
        dns_info || mysql_info || redis_info || rtt_info || protocol_count || redis_stat || extra_conn_info || retrans_info || overrun_time)
        return 0;
    char http_data[256];
    const struct pack_t *pack_info = packet_info;
    if (pack_info->mac_time > MAXTIME || pack_info->ip_time > MAXTIME ||
        pack_info->tran_time > MAXTIME)
    {
        return 0;
    }
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;
    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
    if (!should_filter_t(s_str, d_str, pack_info->sport, pack_info->dport, src_ip, dst_ip, sport, dport))
    {
        return 0;
    }
    if (strstr((char *)pack_info->data, "HTTP/1"))
    {

        for (int i = 0; i < sizeof(pack_info->data); ++i)
        {
            if (pack_info->data[i] == '\r')
            {
                http_data[i] = '\0';
                break;
            }
            http_data[i] = pack_info->data[i];
        }
    }
    else
    {
        sprintf(http_data, "-");
    }
    if (layer_time)
    {

        printf("%-22p %-20s %-8d %-20s %-8d %-14llu %-14llu %-14llu %-14u %-14u %-14d "
               "%-16s",
               pack_info->sock,
               s_str,
               pack_info->sport,
               d_str,
               pack_info->dport, pack_info->mac_time, pack_info->ip_time,
               pack_info->tran_time, pack_info->seq, pack_info->ack, pack_info->rx, http_data);
    }
    else if (err_packet)
    {
        if (pack_info->err)
        {
            char reason[20];
            if (pack_info->err == 1)
            {
                printf("[X] invalid SEQ: sock = %p,seq= %u,ack = %u\n",
                       pack_info->sock, pack_info->seq, pack_info->ack);
                sprintf(reason, "Invalid SEQ");
            }
            else if (pack_info->err == 2)
            {
                printf("[X] invalid checksum: sock = %p\n", pack_info->sock);
                sprintf(reason, "Invalid checksum");
            }
            else
            {
                printf("UNEXPECTED packet error %d.\n", pack_info->err);
                sprintf(reason, "Unkonwn");
            }
            printf("%-22p %-20s %-8d %-20s %-8d %-14u %-14u %-14s ",
                   pack_info->sock,
                   s_str,
                   pack_info->sport,
                   d_str,
                   pack_info->dport, pack_info->seq, pack_info->ack, reason);
        }
    }
    else
    {
        printf("%-22p %-20s %-8d %-20s %-8d %-14u %-14u %-14u %-14u %-14u %-14d %-16s\n",
               pack_info->sock,
               s_str,
               pack_info->sport,
               d_str,
               pack_info->dport, 0, 0, 0, pack_info->seq, pack_info->ack, pack_info->rx, http_data);
    }
    if (time_load)
    {
        int mac = process_delay(pack_info->mac_time, 0);
        int ip = process_delay(pack_info->ip_time, 1);
        int tran = process_delay(pack_info->tran_time, 2);
        if (mac || ip || tran)
        {
            printf("%-15s", "abnormal data");
        }
    }
    printf("\n");
    return 0;
}
static int print_udp(void *ctx, void *packet_info, size_t size)
{
    if (!udp_info)
        return 0;

    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    const struct udp_message *pack_info = packet_info;
    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;

    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
    if (!should_filter_t(s_str, d_str, pack_info->sport, pack_info->dport, src_ip, dst_ip, sport, dport))
    {
        return 0;
    }
    printf("%-20s %-20u %-20s %-20u %-20llu %-20d %-20d\n",
           s_str, pack_info->sport, d_str, pack_info->dport,
           pack_info->tran_time, pack_info->rx, pack_info->len);

    if (time_load)
    {
        int flag = process_delay(pack_info->tran_time, 3);
        if (flag)
            printf("%-15s", "abnormal data");
    }
    return 0;
}

static int print_netfilter(void *ctx, void *packet_info, size_t size)
{
    if (!net_filter)
        return 0;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    const struct netfilter *pack_info = packet_info;

    if (pack_info->local_input_time > MAXTIME ||
        pack_info->forward_time > MAXTIME ||
        pack_info->local_out_time > MAXTIME ||
        pack_info->post_routing_time > MAXTIME ||
        pack_info->pre_routing_time > MAXTIME)
        return 0;

    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;

    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));

    if (!should_filter_t(s_str, d_str, pack_info->sport, pack_info->dport, src_ip, dst_ip, sport, dport))
    {
        return 0;
    }

    printf("%-20s %-12d %-20s %-12d %-8lld %-8lld% -8lld %-8lld %-8lld %-8d",
           s_str, pack_info->sport, d_str,
           pack_info->dport, pack_info->pre_routing_time,
           pack_info->local_input_time, pack_info->forward_time,
           pack_info->post_routing_time, pack_info->local_out_time,
           pack_info->rx);
    // 定义一个数组用于存储需要检测的时延数据和对应的层索引
    struct LayerDelayInfo layer_delay_infos[] = {
        {pack_info->pre_routing_time, 4},
        {pack_info->local_input_time, 5},
        {pack_info->forward_time, 6},
        {pack_info->post_routing_time, 7},
        {pack_info->local_out_time, 8}};
    if (time_load)
    {
        // 循环遍历数组
        for (int i = 0; i < 5; i++)
        {
            // 数组的总字节数除以第一个元素的字节数得到元素的个数
            float delay = layer_delay_infos[i].delay;
            int layer_net = layer_delay_infos[i].layer_index;
            int flag = process_delay(delay, layer_net);
            if (flag)
                printf("%-15s", "abnormal data");
        }
    }
    printf("\n");

    return 0;
}
static int print_tcpstate(void *ctx, void *packet_info, size_t size)
{
    if (!tcp_info)
        return 0;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    const struct tcp_state *pack_info = packet_info;
    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;
    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
    if (!should_filter_t(s_str, d_str, pack_info->sport, pack_info->dport, src_ip, dst_ip, sport, dport))
    {
        return 0;
    }

    printf("%-20s %-20d %-20s %-20d %-20s %-20s  %-20lld\n",
           s_str, pack_info->sport, d_str,
           pack_info->dport, tcp_states[pack_info->oldstate],
           tcp_states[pack_info->newstate], pack_info->time);

    return 0;
}
static void calculate_protocol_usage(struct packet_count proto_stats[],
                                     int num_protocols, int interval)
{
    static uint64_t last_rx[256] = {0}, last_tx[256] = {0};
    uint64_t current_rx = 0, current_tx = 0;
    uint64_t delta_rx[256] = {0}, delta_tx[256] = {0};
    // 遍历所有的协议
    for (int i = 0; i < num_protocols; i++)
    {
        // 计算数据包增量
        if (proto_stats[i].rx_count >= last_rx[i])
        {
            delta_rx[i] = proto_stats[i].rx_count - last_rx[i];
        }
        else
        {
            delta_rx[i] = proto_stats[i].rx_count;
        }

        if (proto_stats[i].tx_count >= last_tx[i])
        {
            delta_tx[i] = proto_stats[i].tx_count - last_tx[i];
        }
        else
        {
            delta_tx[i] = proto_stats[i].tx_count;
        }
        // 时间段内总的接收和发送包数
        current_rx += delta_rx[i];
        current_tx += delta_tx[i];
        // 更新上次统计的包数
        last_rx[i] = proto_stats[i].rx_count;
        last_tx[i] = proto_stats[i].tx_count;
    }
    printf("Protocol Usage in Last %d Seconds:\n", interval);
    printf("Total_rx_count:%ld Total_tx_count:%ld\n", current_rx, current_tx);

    if (current_rx > 0)
    {
        printf("Receive Protocol Usage:\n");
        for (int i = 0; i < num_protocols; i++)
        {
            if (delta_rx[i] > 0)
            {
                double rx_percentage = (double)delta_rx[i] / current_rx * 100;
                if (rx_percentage >= 80.0)
                {
                    printf(RED_TEXT
                           "Protocol %s: %.2f%% Rx_count:%ld\n" RESET_TEXT,
                           protocol[i], rx_percentage, delta_rx[i]);
                }
                else
                {
                    printf("Protocol %s: %.2f%% Rx_count:%ld\n", protocol[i],
                           rx_percentage, delta_rx[i]);
                }
            }
        }
    }
    if (current_tx > 0)
    {
        printf("Transmit Protocol Usage:\n");
        for (int i = 0; i < num_protocols; i++)
        {
            if (delta_tx[i] > 0)
            {
                double tx_percentage = (double)delta_tx[i] / current_tx * 100;
                if (tx_percentage >= 80.0)
                {
                    printf(RED_TEXT
                           "Protocol %s: %.2f%% Tx_count:%ld\n" RESET_TEXT,
                           protocol[i], tx_percentage, delta_tx[i]);
                }
                else
                {
                    printf("Protocol %s: %.2f%% Tx_count:%ld\n", protocol[i],
                           tx_percentage, delta_tx[i]);
                }
            }
        }
    }
    memset(proto_stats, 0, num_protocols * sizeof(struct packet_count));
}
static int print_protocol_count(void *ctx, void *packet_info, size_t size)
{
    const struct packet_info *pack_protocol_info =
        (const struct packet_info *)packet_info;
    if (!protocol_count)
    {
        return 0;
    }
    proto_stats[pack_protocol_info->proto].rx_count =
        pack_protocol_info->count.rx_count;
    proto_stats[pack_protocol_info->proto].tx_count =
        pack_protocol_info->count.tx_count;
    return 0;
}
static int print_kfree(void *ctx, void *packet_info, size_t size)
{
    if (!drop_reason)
        return 0;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    char prot[6];
    const struct reasonissue *pack_info = packet_info;
    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;
    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
    if (!should_filter_t(s_str, d_str, pack_info->sport, pack_info->dport, src_ip, dst_ip, sport, dport))
    {
        return 0;
    }
    if (pack_info->protocol == 2048)
    {
        strcpy(prot, "ipv4");
    }
    else if (pack_info->protocol == 34525)
    {
        strcpy(prot, "ipv6");
    }
    else
    {
        // 其他协议
        strcpy(prot, "other");
    }
    time_t now = time(NULL);
    struct tm *localTime = localtime(&now);
    printf("%02d:%02d:%02d      %-17s %-10u %-17s %-10u %-10s",
           localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
           s_str, pack_info->sport, d_str,
           pack_info->dport, prot);
    if (!addr_to_func)
        printf("%-34lx", pack_info->location);
    else
    {
        struct SymbolEntry data = findfunc(pack_info->location);
        char result[40];
        sprintf(result, "%s+0x%lx", data.name, pack_info->location - data.addr);
        printf("%-34s", result);
    }
    printf("%s\n", SKB_Drop_Reason_Strings[pack_info->drop_reason]);
    return 0;
}
static int print_icmptime(void *ctx, void *packet_info, size_t size)
{
    if (!icmp_info)
        return 0;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    const struct icmptime *pack_info = packet_info;
    if (pack_info->icmp_tran_time > MAXTIME)
    {
        return 0;
    }
    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;
    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
    if (!should_filter(s_str, d_str, src_ip, dst_ip))
    {
        return 0;
    }
    printf("%-20s %-20s %-20lld %-20d",
           s_str, d_str,
           pack_info->icmp_tran_time, pack_info->flag);
    if (time_load)
    {
        int icmp_data = process_delay(pack_info->icmp_tran_time, 9);
        if (icmp_data)
        {
            printf("%-15s\n", "abnormal data");
        }
    }
    printf("\n");
    return 0;
}
static int print_rst(void *ctx, void *packet_info, size_t size)
{
    if (!rst_info)
    {
        return 0;
    }
    struct reset_event_t *event = packet_info;

    // 将事件存储到全局存储中
    if (event_count < MAX_EVENTS)
    {
        memcpy(&event_store[event_count], event, sizeof(struct reset_event_t));
        event_count++;
    }

    rst_count++;
    return 0;
}
static void print_stored_events()
{
    char s_str[INET_ADDRSTRLEN];
    char d_str[INET_ADDRSTRLEN];
    char saddr_v6[INET6_ADDRSTRLEN];
    char daddr_v6[INET6_ADDRSTRLEN];

    for (int i = 0; i < event_count; i++)
    {
        struct reset_event_t *event = &event_store[i];
        unsigned int saddr = event->saddr;
        unsigned int daddr = event->daddr;

        if (event->family == AF_INET)
        {
            inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
            inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
            printf("%-10d %-10s %-10s %-10u %-10s %-10u %-20llu",
                   event->pid, event->comm, s_str,
                   event->sport, d_str, event->dport,
                   event->timestamp);
        }
        else if (event->family == AF_INET6)
        {

            inet_ntop(AF_INET6, &event->saddr_v6, saddr_v6, sizeof(saddr_v6));
            inet_ntop(AF_INET6, &event->daddr_v6, daddr_v6, sizeof(daddr_v6));
            printf("%-10d %10s %-10s %-10u %-10s %-10u %-20llu\n",
                   event->pid, event->comm, saddr_v6,
                   event->sport, daddr_v6, event->dport,
                   event->timestamp);
        }
        printf("\n");
    }
}
static int print_dns(void *ctx, void *packet_info, size_t size)
{
    if (!packet_info)
        return 0;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    const struct dns_information *pack_info =
        (const struct dns_information *)packet_info; // 强制类型转换
    unsigned int saddr = pack_info->saddr;
    unsigned int daddr = pack_info->daddr;
    char domain_name[256]; // 用于存储输出的域名

    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));
    print_domain_name((const unsigned char *)pack_info->data, domain_name);

    if (!should_filter(s_str, d_str, src_ip, dst_ip))
    {
        return 0;
    }

    printf("%-20s %-20s %-#12x %-#12x %-5x %-5x %-5x %-5x %-47s %-10d %-10d "
           "%-10d \n",
           s_str, d_str, pack_info->id, pack_info->flags, pack_info->qdcount,
           pack_info->ancount, pack_info->nscount, pack_info->arcount,
           domain_name, pack_info->request_count, pack_info->response_count,
           pack_info->rx);
    return 0;
}
static int print_mysql(void *ctx, void *packet_info, size_t size)
{
    if (!mysql_info)
    {
        return 0;
    }

    const mysql_query *pack_info = packet_info;
    printf("%-20d %-20d %-20s %-20u %-41s", pack_info->pid, pack_info->tid,
           pack_info->comm, pack_info->size, pack_info->msql);
    if (pack_info->duratime > count_info)
    {
        printf("%-21llu", pack_info->duratime);
    }
    else
    {
        printf("%-21s", "");
    }
    printf("%-20d\n", pack_info->count);
    return 0;
}
static int print_redis(void *ctx, void *packet_info, size_t size)
{
    const struct redis_query *pack_info = packet_info;
    int i = 0;
    char redis[64];
    for (i = 0; i < pack_info->argc; i++)
    {
        strcat(redis, pack_info->redis[i]);
        strcat(redis, " ");
    }
    printf("%-20d %-20s %-20d %-20s %-21llu\n", pack_info->pid, pack_info->comm,
           pack_info->argc, redis, pack_info->duratime);
    strcpy(redis, "");
    return 0;
}
static int print_redis_stat(void *ctx, void *packet_info, size_t size)
{
    if (!redis_stat)
    {
        return 0;
    }
    char message[20] = {};
    const struct redis_stat_query *pack_info = packet_info;
    if (pack_info->key_count)
    {
        printf("%-20d %-20s %-20s %-20d %-20s %-20s\n", pack_info->pid, pack_info->comm,
               pack_info->key, pack_info->key_count, "-", "-");
    }
    else
    {
        process_redis_first(pack_info->value[0], message);
        printf("%-20d %-20s %-20s %-20s %-20s %-20s\n", pack_info->pid, pack_info->comm,
               "-", "-", message, pack_info->value);
    }

    return 0;
}

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
                           va_list args)
{
    return vfprintf(stderr, format, args);
}
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
{
    int i;
    printf("-----------------------------------\n");
    for (i = 1; i < stack_sz; i++)
    {
        if (addr_to_func)
        {
            struct SymbolEntry data = findfunc(stack[i]);
            char result[40];
            sprintf(result, "%s+0x%llx", data.name, stack[i] - data.addr);
            printf("%-10d [<%016llx>]=%s\n", i, stack[i], result);
        }
        else
        {
            printf("%-10d [<%016llx>]\n", i, stack[i]);
        }
    }
    printf("-----------------------------------\n");
}
static int print_trace(void *_ctx, void *data, size_t size)
{
    struct stacktrace_event *event = data;

    if (event->kstack_sz <= 0 && event->ustack_sz <= 0)
        return 1;

    printf("COMM: %s (pid=%d) @ CPU %d\n", event->comm, event->pid,
           event->cpu_id);

    if (event->kstack_sz > 0)
    {
        printf("Kernel:\n");
        show_stack_trace(event->kstack, event->kstack_sz / sizeof(__u64), 0);
    }
    else
    {
        printf("No Kernel Stack\n");
    }
    printf("\n");
    return 0;
}

static int print_rate(void *ctx, void *data, size_t size)
{
    if (!overrun_time)
    {
        return 0;
    }
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    const struct tcp_rate *pack_info = (const struct tcp_rate *)data;
    unsigned int saddr = pack_info->skbap.saddr;
    unsigned int daddr = pack_info->skbap.daddr;
    inet_ntop(AF_INET, &saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &daddr, d_str, sizeof(d_str));

    if (!should_filter_t(s_str, d_str, pack_info->skbap.sport, pack_info->skbap.dport, src_ip, dst_ip, sport, dport))
    {
        return 0;
    }

    printf("%-20s %-20d %-20s %-20d %-20lld %-20lld\n", s_str,
           pack_info->skbap.sport, d_str, pack_info->skbap.dport, pack_info->tcp_rto,
           pack_info->tcp_delack_max);

    return 0;
}
static int print_rtt(void *ctx, void *data, size_t size)
{
    if (!rtt_info)
        return 0;
    struct RTT *rtt_tuple = data;
    unsigned long long total_latency = 0;
    unsigned long long total_count = 0;
    char d_str[INET_ADDRSTRLEN];
    char s_str[INET_ADDRSTRLEN];
    inet_ntop(AF_INET, &rtt_tuple->saddr, s_str, sizeof(s_str));
    inet_ntop(AF_INET, &rtt_tuple->daddr, d_str, sizeof(d_str));
    if (!should_filter(s_str, d_str, src_ip, dst_ip))
    {
        return 0;
    }
    // 打印源地址和目的地址
    printf("Source Address: %s\n", s_str);
    printf("Destination Address: %s\n", d_str);
    // 更新总延迟和计数
    total_latency += rtt_tuple->latency;
    total_count += rtt_tuple->cnt;

    // 打印总延迟和平均RTT
    double average_rtt =
        (total_count > 0) ? (double)total_latency / total_count : 0;
    printf("Total Latency: %llu μs\n", total_latency);
    printf("Average RTT: %.2f ms\n", average_rtt / 1000.0);

    // 计算和打印RTT分布图
    printf(" usecs               : count     distribution\n");
    int bucket_size = 1;
    for (int i = 0; i < MAX_SLOTS; i++)
    {
        int start_range = bucket_size == 1 ? 0 : bucket_size;
        int end_range = bucket_size * 2 - 1;
        printf("%8d -> %-8d : %-8llu |", start_range, end_range,
               rtt_tuple->slots[i]);
        int bar_length =
            rtt_tuple->slots[i] /
            10; // 计算该延迟范围内的计数对应的直方图条形长度,每个'*'
                // 表示 10 个计数
        for (int j = 0; j < bar_length; j++)
        {
            printf("*");
        }
        printf("\n");
        bucket_size *= 2; // 以对数方式扩展
    }
    printf("===============================================================\n");
    return 0;
}
int attach_uprobe_mysql(struct net_watcher_bpf *skel)
{

    ATTACH_UPROBE_CHECKED(
        skel, _Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command,
        query__start);
    ATTACH_URETPROBE_CHECKED(
        skel, _Z16dispatch_commandP3THDPK8COM_DATA19enum_server_command,
        query__end);
    return 0;
}
int attach_uprobe_redis(struct net_watcher_bpf *skel)
{
    if (redis_info)
    {
        ATTACH_UPROBE_CHECKED(skel, call, redis_call);
        ATTACH_UPROBE_CHECKED(skel, processCommand, redis_processCommand);
    }
    if (redis_stat)
    {
        ATTACH_UPROBE_CHECKED(skel, lookupKey, redis_lookupKey);
        ATTACH_UPROBE_CHECKED(skel, addReply, redis_addReply);
    }
    return 0;
}

void print_top_5_keys()
{
    kv_pair *pairs;
    pairs = malloc(sizeof(kv_pair) * 1024);
    if (!pairs)
    {
        perror("Failed to allocate memory");
        exit(EXIT_FAILURE);
    }
    int index = 0;
    char *key = NULL;
    while (bpf_map_get_next_key(map_fd, &key, &key) == 0)
    {
        // fprintf(stdout, "next_sk: (%p)\n", sk);
        int count;
        int err = bpf_map_lookup_elem(map_fd, &key, &count);
        if (err)
        {
            fprintf(stderr, "Failed to read value from the conns map: (%s)\n",
                    strerror(errno));
            return;
        }
        memcpy(pairs[index].key, &key, 256);
        pairs[index].value = count;
        // printf("Key: %s, Count: %u\n", pairs[index].key, pairs[index].value);
        index++;
    }

    // 简单选择排序前 5 个元素
    for (int i = 0; i < index - 1; i++)
    {
        for (int j = i + 1; j < index; j++)
        {
            if (pairs[j].value > pairs[i].value)
            {
                kv_pair temp = pairs[i];
                pairs[i] = pairs[j];
                pairs[j] = temp;
            }
        }
    }
    printf("----------------------------\n");

    printf("Top 5 Keys:\n");
    for (int i = 0; i < 5 && i < index; i++)
    {
        printf("Key: %s, Count: %u\n", pairs[i].key, pairs[i].value);
    }
    free(pairs);
}

// free
int main(int argc, char **argv)
{

    struct ring_buffer *rb = NULL;
    struct ring_buffer *udp_rb = NULL;
    struct ring_buffer *netfilter_rb = NULL;
    struct ring_buffer *kfree_rb = NULL;
    struct ring_buffer *icmp_rb = NULL;
    struct ring_buffer *tcp_rb = NULL;
    struct ring_buffer *dns_rb = NULL;
    struct ring_buffer *trace_rb = NULL;
    struct ring_buffer *mysql_rb = NULL;
    struct ring_buffer *redis_rb = NULL;
    struct ring_buffer *redis_stat_rb = NULL;
    struct ring_buffer *rtt_rb = NULL;
    struct ring_buffer *events = NULL;
    struct ring_buffer *port_rb = NULL;
    struct ring_buffer *rate_rb = NULL;
    struct net_watcher_bpf *skel;
    int err;
    /* Parse command line arguments */
    if (argc > 1)
    {
        err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
        if (err)
            return err;
    }

    // libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);
    /* Open load and verify BPF application */
    skel = net_watcher_bpf__open();
    if (!skel)
    {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }
    /* Parameterize BPF code */
    set_rodata_flags(skel);
    set_disable_load(skel);

    if (addr_to_func)
        readallsym();
    err = net_watcher_bpf__load(skel);
    if (err)
    {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }
    /* Attach tracepoint handler */
    if (mysql_info)
    {
        strcpy(binary_path, "/usr/sbin/mysqld");
        err = attach_uprobe_mysql(skel);
        if (err)
        {
            fprintf(stderr, "failed to attach uprobes\n");

            goto cleanup;
        }
    }
    else if (redis_info || redis_stat)
    {
        strcpy(binary_path, "/usr/bin/redis-server");
        err = attach_uprobe_redis(skel);
        if (err)
        {
            fprintf(stderr, "failed to attach uprobes\n");

            goto cleanup;
        }
    }
    else
    {
        err = net_watcher_bpf__attach(skel);
        if (err)
        {
            fprintf(stderr, "Failed to attach BPF skeleton\n");
            goto cleanup;
        }
    }
    enum MonitorMode mode = get_monitor_mode();

    print_logo();

    print_header(mode);

    udp_rb =
        ring_buffer__new(bpf_map__fd(skel->maps.udp_rb), print_udp, NULL, NULL);
    if (!udp_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(udp)\n");
        goto cleanup;
    }
    netfilter_rb = ring_buffer__new(bpf_map__fd(skel->maps.netfilter_rb),
                                    print_netfilter, NULL, NULL);
    if (!netfilter_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(netfilter)\n");
        goto cleanup;
    }
    kfree_rb = ring_buffer__new(bpf_map__fd(skel->maps.kfree_rb), print_kfree,
                                NULL, NULL);
    if (!kfree_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(kfree)\n");
        goto cleanup;
    }
    icmp_rb = ring_buffer__new(bpf_map__fd(skel->maps.icmp_rb), print_icmptime,
                               NULL, NULL);
    if (!icmp_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(icmp)\n");
        goto cleanup;
    }
    tcp_rb = ring_buffer__new(bpf_map__fd(skel->maps.tcp_rb), print_tcpstate,
                              NULL, NULL);
    if (!tcp_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(tcp)\n");
        goto cleanup;
    }
    dns_rb =
        ring_buffer__new(bpf_map__fd(skel->maps.dns_rb), print_dns, NULL, NULL);
    if (!dns_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(dns)\n");
        goto cleanup;
    }
    trace_rb = ring_buffer__new(bpf_map__fd(skel->maps.trace_rb), print_trace,
                                NULL, NULL);
    if (!trace_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(trace)\n");
        goto cleanup;
    }
    mysql_rb = ring_buffer__new(bpf_map__fd(skel->maps.mysql_rb), print_mysql,
                                NULL, NULL);
    if (!mysql_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(trace)\n");
        goto cleanup;
    }
    redis_rb = ring_buffer__new(bpf_map__fd(skel->maps.redis_rb), print_redis,
                                NULL, NULL);
    if (!redis_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(trace)\n");
        goto cleanup;
    }
    redis_stat_rb = ring_buffer__new(bpf_map__fd(skel->maps.redis_stat_rb), print_redis_stat,
                                     NULL, NULL);
    if (!redis_stat_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(trace)\n");
        goto cleanup;
    }
    rtt_rb =
        ring_buffer__new(bpf_map__fd(skel->maps.rtt_rb), print_rtt, NULL, NULL);
    if (!rtt_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(connect_rb)\n");
        goto cleanup;
    }
    events =
        ring_buffer__new(bpf_map__fd(skel->maps.events), print_rst, NULL, NULL);
    if (!events)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(rst_rb)\n");
        goto cleanup;
    }

    port_rb = ring_buffer__new(bpf_map__fd(skel->maps.port_rb),
                               print_protocol_count, NULL, NULL);
    if (!port_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(trace)\n");
        goto cleanup;
    }

    rate_rb = ring_buffer__new(bpf_map__fd(skel->maps.rate_rb),
                               print_rate, NULL, NULL);
    if (!rate_rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(trace)\n");
        goto cleanup;
    }
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), print_packet, NULL, NULL);
    if (!rb)
    {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer(packet)\n");
        goto cleanup;
    }

    // open_log_files();
    struct timeval start, end;
    gettimeofday(&start, NULL);
    /* Process events */
    while (!exiting)
    {
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(udp_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(netfilter_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(kfree_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(icmp_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(tcp_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(dns_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(trace_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(mysql_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(redis_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(rtt_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(events, 100 /* timeout, ms */);
        err = ring_buffer__poll(port_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(redis_stat_rb, 100 /* timeout, ms */);
        err = ring_buffer__poll(rate_rb, 100 /* timeout, ms */);
        print_conns(skel);
        sleep(1);
        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR)
        {
            err = 0;
            break;
        }
        if (err < 0)
        {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
        gettimeofday(&end, NULL);
        if (overrun_time)
        {
            u32 key = 0;
            struct tcp_args_s new_args;
            new_args.sample_period = overrun_time;

            // 更新 args_map，传递采样周期给 BPF 程序
            err = bpf_map_update_elem(bpf_map__fd(skel->maps.args_map), &key, &new_args, BPF_ANY);
            if (err)
            {
                fprintf(stderr, "Failed to update sample period\n");
                return 1;
            }
        }

        if ((end.tv_sec - start.tv_sec) >= 5)
        {
            if (rst_info)
            {
                print_stored_events();
                printf("Total RSTs in the last 5 seconds: %llu\n\n", rst_count);
                rst_count = 0;
                event_count = 0;
            }
            else if (protocol_count)
            {
                calculate_protocol_usage(proto_stats, 256, 5);
            }
            else if (redis_stat)
            {
                map_fd = bpf_map__fd(skel->maps.key_count);
                if (map_fd < 0)
                {
                    perror("Failed to get map FD");
                    return 1;
                }
                print_top_5_keys();
            }
            gettimeofday(&start, NULL);
        }
    }
cleanup:
    ring_buffer__free(rb);
    ring_buffer__free(udp_rb);
    ring_buffer__free(netfilter_rb);
    ring_buffer__free(kfree_rb);
    ring_buffer__free(icmp_rb);
    ring_buffer__free(tcp_rb);
    ring_buffer__free(dns_rb);
    ring_buffer__free(trace_rb);
    ring_buffer__free(mysql_rb);
    ring_buffer__free(redis_rb);
    ring_buffer__free(rtt_rb);
    ring_buffer__free(events);
    ring_buffer__free(port_rb);
    ring_buffer__free(redis_stat_rb);
    ring_buffer__free(rate_rb);
    net_watcher_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

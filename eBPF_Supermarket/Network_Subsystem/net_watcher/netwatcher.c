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
// netwatcher libbpf 用户态代码

#include "netwatcher.h"
#include "netwatcher.skel.h"
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
#include <unistd.h>

static volatile bool exiting = false;

static char connects_file_path[1024];
static char err_file_path[1024];
static char packets_file_path[1024];

static int sport = 0, dport = 0; // for filter
static int all_conn = 0, err_packet = 0, extra_conn_info = 0, layer_time = 0,
           http_info = 0, retrans_info = 0; // flag

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
    {}};

static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    char *end;
    switch (key) {
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

static void sig_handler(int signo) { exiting = true; }

static void bytes_to_str(char *str, unsigned long long num) {
    if (num > 1e9) {
        sprintf(str, "%.8lfG", (double)num / 1e9);
    } else if (num > 1e6) {
        sprintf(str, "%.6lfM", (double)num / 1e6);
    } else if (num > 1e3) {
        sprintf(str, "%.3lfK", (double)num / 1e3);
    } else {
        sprintf(str, "%llu", num);
    }
}

static int print_conns(struct netwatcher_bpf *skel) {

    FILE *file = fopen(connects_file_path, "w+");
    if (file == NULL) {
        fprintf(stderr, "Failed to open connects.log: (%s)\n", strerror(errno));
        return 0;
    }

    int map_fd = bpf_map__fd(skel->maps.conns_info);
    struct sock *sk = NULL;

    while (bpf_map_get_next_key(map_fd, &sk, &sk) == 0) {
        // fprintf(stdout, "next_sk: (%p)\n", sk);
        struct conn_t d = {};
        int err = bpf_map_lookup_elem(map_fd, &sk, &d);
        if (err) {
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
        
        if(http_info){
                printf("%u,%u,%llu\n",d.rcv_wnd, d.snd_cwnd,d.duration);
        }

        if (d.family == AF_INET) {
            sprintf(s_ip_port_str, "%s:%d",
                    inet_ntop(AF_INET, &d.saddr, s_str, sizeof(s_str)),
                    d.sport);
            sprintf(d_ip_port_str, "%s:%d",
                    inet_ntop(AF_INET, &d.daddr, d_str, sizeof(d_str)),
                    d.dport);
        } else { // AF_INET6
            sprintf(
                s_ip_port_str, "%s:%d",
                inet_ntop(AF_INET6, &d.saddr_v6, s_str_v6, sizeof(s_str_v6)),
                d.sport);
            sprintf(
                d_ip_port_str, "%s:%d",
                inet_ntop(AF_INET6, &d.daddr_v6, d_str_v6, sizeof(d_str_v6)),
                d.dport);
        }
        char received_bytes[11], acked_bytes[11];
        bytes_to_str(received_bytes, d.bytes_received);
        bytes_to_str(acked_bytes, d.bytes_acked);
        fprintf(file,
                "connection{pid=\"%d\",sock=\"%p\",src=\"%s\",dst=\"%s\","
                "is_server=\"%d\"",
                d.pid, d.sock, s_ip_port_str, d_ip_port_str, d.is_server);
        if (extra_conn_info) {
            fprintf(file,
                    ",backlog=\"%u\""
                    ",maxbacklog=\"%u\""
                    ",rwnd=\"%u\""
                    ",cwnd=\"%u\""
                    ",ssthresh=\"%u\""
                    ",sndbuf=\"%u\""
                    ",wmem_queued=\"%u\""
                    ",rx_bytes=\"%s\""
                    ",tx_bytes=\"%s\""
                    ",srtt=\"%u\""
                    ",duration=\"%llu\""
                    ",total_retrans=\"%u\"",
                    d.tcp_backlog, d.max_tcp_backlog, d.rcv_wnd, d.snd_cwnd,
                    d.snd_ssthresh, d.sndbuf, d.sk_wmem_queued, received_bytes,
                    acked_bytes, d.srtt, d.duration, d.total_retrans);
        } else {
            fprintf(file,
                    ",backlog=\"-\",maxbacklog=\"-\",cwnd=\"-\",ssthresh=\"-\","
                    "sndbuf=\"-\",wmem_queued=\"-\",rx_bytes=\"-\",tx_bytes=\"-"
                    "\",srtt=\"-\",duration=\"-\",total_retrans=\"-\"");
        }
        if (retrans_info) {
            fprintf(file, ",fast_retrans=\"%u\",timeout_retrans=\"%u\"",
                    d.fastRe, d.timeout);
        } else {
            fprintf(file, ",fast_retrans=\"-\",timeout_retrans=\"-\"");
        }
        fprintf(file, "} 0\n");
    }
    fclose(file);
    return 0;
}

static int print_packet(void *ctx, void *packet_info, size_t size) {

    const struct pack_t *pack_info = packet_info;
    if (pack_info->err) {
        FILE *file = fopen(err_file_path, "a");
        char reason[20];
        if (pack_info->err == 1) {
            printf("[X] invalid SEQ: sock = %p,seq= %u,ack = %u\n",
                   pack_info->sock, pack_info->seq, pack_info->ack);
            sprintf(reason, "Invalid SEQ");
        } else if (pack_info->err == 2) {
            printf("[X] invalid checksum: sock = %p\n", pack_info->sock);
            sprintf(reason, "Invalid checksum");
        } else {
            printf("UNEXPECTED packet error %d.\n", pack_info->err);
            sprintf(reason, "Unkonwn");
        }
        fprintf(file,
                "error{sock=\"%p\",seq=\"%u\",ack=\"%u\","
                "reason=\"%s\"} 0\n",
                pack_info->sock, pack_info->seq, pack_info->ack, reason);
        fclose(file);
    } else {
        FILE *file = fopen(packets_file_path, "a");
        char http_data[256];
        if (strstr((char *)pack_info->data, "HTTP/1")) {
            for (int i = 0; i < sizeof(pack_info->data); ++i) {
                if (pack_info->data[i] == '\r') {
                    http_data[i] = '\0';
                    break;
                }
                http_data[i] = pack_info->data[i];
            }
        } else {
            sprintf(http_data, "-");
        }
        if(http_info == 0){
            if (layer_time) {
                 printf("%-22p %-10u %-10u %-10llu %-10llu %-10llu %-5d %s\n",
                   pack_info->sock, pack_info->seq, pack_info->ack,
                   pack_info->mac_time, pack_info->ip_time, pack_info->tcp_time,
                   pack_info->rx, http_data);
                 fprintf(file,
                    "packet{sock=\"%p\",seq=\"%u\",ack=\"%u\","
                    "mac_time=\"%llu\",ip_time=\"%llu\",tcp_time=\"%llu\",http_"
                    "info=\"%s\",rx=\"%d\"} \n",
                    pack_info->sock, pack_info->seq, pack_info->ack,
                    pack_info->mac_time, pack_info->ip_time,
                    pack_info->tcp_time, http_data, pack_info->rx);
            } 
            if(http_info|| retrans_info||extra_conn_info){
                  printf("%-22p %-10u %-10u %-5d %s\n",
                   pack_info->sock, pack_info->seq, pack_info->ack,
                   pack_info->rx, http_data);
                  fprintf(file,
                    "packet{sock=\"%p\",seq=\"%u\",ack=\"%u\","
                    "info=\"%s\",rx=\"%d\"} \n",
                    pack_info->sock, pack_info->seq, pack_info->ack, http_data,
                    pack_info->rx);
            }

        }
        fclose(file);
    }
    return 0;
}

int main(int argc, char **argv) {
    char *last_slash = strrchr(argv[0], '/');
    if (last_slash) {
        *(last_slash+1) = '\0';
    }
    strcpy(connects_file_path, argv[0]);
    strcpy(err_file_path, argv[0]);
    strcpy(packets_file_path, argv[0]);
    strcat(connects_file_path, "data/connects.log");
    strcat(err_file_path, "data/err.log");
    strcat(packets_file_path, "data/packets.log");
    struct ring_buffer *rb = NULL;
    struct netwatcher_bpf *skel;
    int err;
    /* Parse command line arguments */
    if (argc > 1) {
        err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
        if (err)
            return err;
    }

    /* Cleaner handling of Ctrl-C */
    signal(SIGINT, sig_handler);
    signal(SIGTERM, sig_handler);

    /* Open load and verify BPF application */
    skel = netwatcher_bpf__open();
    if (!skel) {
        fprintf(stderr, "Failed to open BPF skeleton\n");
        return 1;
    }

    /* Parameterize BPF code */
    skel->rodata->filter_dport = dport;
    skel->rodata->filter_sport = sport;
    skel->rodata->all_conn = all_conn;
    skel->rodata->err_packet = err_packet;
    skel->rodata->extra_conn_info = extra_conn_info;
    skel->rodata->layer_time = layer_time;
    skel->rodata->http_info = http_info;
    skel->rodata->retrans_info = retrans_info;

    err = netwatcher_bpf__load(skel);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        goto cleanup;
    }

    /* Attach tracepoint handler */
    err = netwatcher_bpf__attach(skel);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto cleanup;
    }

    if(layer_time) {
        printf("%-22s %-10s %-10s %-10s %-10s %-10s %-5s %s\n", "SOCK", "SEQ",
           "ACK", "MAC_TIME", "IP_TIME", "TCP_TIME", "RX", "HTTP");

    }
    
    if(http_info|| retrans_info||extra_conn_info) {

        printf("%-22s %-10s %-10s %-5s \n", "SOCK", "SEQ",
           "ACK", "RX");
    }
    
    /* Set up ring buffer polling */
    rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), print_packet, NULL, NULL);
    if (!rb) {
        err = -1;
        fprintf(stderr, "Failed to create ring buffer\n");
        goto cleanup;
        }
    

    FILE *err_file = fopen(err_file_path, "w+");
    if (err_file == NULL) {
        fprintf(stderr, "Failed to open err.log: (%s)\n", strerror(errno));
        return 0;
    }
    fclose(err_file);
    FILE *packet_file = fopen(packets_file_path, "w+");
    if (packet_file == NULL) {
        fprintf(stderr, "Failed to open packets.log: (%s)\n", strerror(errno));
        return 0;
    }
    fclose(packet_file);
    
    /* Process events */
    while (!exiting) {
      
        err = ring_buffer__poll(rb, 100 /* timeout, ms */);

        if(http_info) {
            printf("==============================\n");
            print_conns(skel);
            sleep(1);
        }

        /* Ctrl-C will cause -EINTR */
        if (err == -EINTR) {
            err = 0;
            break;
        }
        if (err < 0) {
            printf("Error polling perf buffer: %d\n", err);
            break;
        }
    }

cleanup:
    netwatcher_bpf__destroy(skel);
    return err < 0 ? -err : 0;
}

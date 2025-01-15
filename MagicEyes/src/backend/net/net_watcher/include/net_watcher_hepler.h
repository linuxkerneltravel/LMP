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

#ifndef NET_WATCHER_HELPER_H
#define NET_WATCHER_HELPER_H
#include "net_watcher/include/net_watcher.h"
#include <arpa/inet.h>
#include <bpf/bpf.h>
#include <bpf/libbpf.h>
#include <string.h>

// logo
#define LOGO_STRING                                                            \
    " "                                                                        \
    "              __                          __           __               " \
    "        \n"                                                               \
    "             /\\ \\__                      /\\ \\__       /\\ \\        " \
    "              \n"                                                         \
    "  ___      __\\ \\  _\\  __  __  __     __  \\ \\  _\\   ___\\ \\ \\___ " \
    "     __   _ __   \n"                                                      \
    "/  _  \\  / __ \\ \\ \\/ /\\ \\/\\ \\/\\ \\  / __ \\ \\ \\ \\/  / ___\\ " \
    "\\  _  \\  / __ \\/\\  __\\ \n"                                           \
    "/\\ \\/\\ \\/\\  __/\\ \\ \\_\\ \\ \\_/ \\_/ \\/\\ \\_\\ \\_\\ \\ "       \
    "\\_/\\ \\__/\\ \\ \\ \\ \\/\\  __/\\ \\ \\/  \n"                          \
    "\\ \\_\\ \\_\\ \\____\\ \\__\\ \\_______ / /\\ \\__/\\ \\_\\ \\__\\ "     \
    "\\____/\\ \\_\\ \\_\\ \\____ \\ \\_\\  \n"                                \
    " \\/_/\\/_/\\/____/ \\/__/ \\/__//__ /  \\/_/  \\/_/\\/__/\\/____/ "      \
    "\\/_/\\/_/\\/____/ \\/_/  \n\n"
//
#define __ATTACH_UPROBE_GENERIC(skel, sym_name, prog_name, is_retprobe)   \
    do                                                                    \
    {                                                                     \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name, \
                    .retprobe = is_retprobe);                             \
        skel->links.prog_name = bpf_program__attach_uprobe_opts(          \
            skel->progs.prog_name, -1, binary_path, 0, &uprobe_opts);     \
        if (!skel->links.prog_name)                                       \
        {                                                                 \
            perror("no program attached for " #prog_name);                \
            return -errno;                                                \
        }                                                                 \
    } while (false)

// 入口探针
#define ATTACH_UPROBE(skel, sym_name, prog_name) \
    __ATTACH_UPROBE_GENERIC(skel, sym_name, prog_name, false)

// 返回探针
#define ATTACH_URETPROBE(skel, sym_name, prog_name) \
    __ATTACH_UPROBE_GENERIC(skel, sym_name, prog_name, true)

// 入口探针，检查是否成功附加
#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) \
    __ATTACH_UPROBE_GENERIC(skel, sym_name, prog_name, false)

// 返回探针，检查是否成功附加
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) \
    __ATTACH_UPROBE_GENERIC(skel, sym_name, prog_name, true)

extern struct SymbolEntry symbols[300000];
extern struct SymbolEntry cache[CACHEMAXSIZE];
extern int event_count, num_symbols, cache_size;
extern float ewma_values[NUM_LAYERS];
extern int count[NUM_LAYERS];

int should_filter(const char *src, const char *dst, const char *filter_src_ip, const char *filter_dst_ip);
int process_delay(float layer_delay, int layer_index);
void print_logo();
void bytes_to_str(char *str, unsigned long long num);
void readallsym();
struct SymbolEntry findfunc(unsigned long int addr);
void add_to_cache(struct SymbolEntry entry);
struct SymbolEntry find_in_cache(unsigned long int addr);
int process_delay(float layer_delay, int layer_index);
float calculate_ewma(float new_value, float old_ewma);
int process_redis_first(char flag, char *message);
int create_ring_buffer(struct ring_buffer **rb, int map_fd, void *print_fn, const char *name);
int poll_ring_buffers(struct ring_buffer *buffers[], int num_buffers, int timeout_ms);
void print_domain_name(const unsigned char *data, char *output);
int should_filter_t(const char *src, const char *dst, unsigned short sport, unsigned short dport,const char *filter_src_ip, const char *filter_dst_ip, unsigned short filter_sport, unsigned short filter_dport);

#endif

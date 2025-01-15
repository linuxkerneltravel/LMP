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

int match_filter(const char *src, const char *dst, unsigned short sport, unsigned short dport,
                 const char *filter_src_ip, const char *filter_dst_ip, unsigned short filter_sport, unsigned short filter_dport)
{
    // 未指定任何条件
    if (!filter_src_ip && !filter_dst_ip && filter_sport == 0 && filter_dport == 0)
    {
        return 1;
    }

    // 只指定源IP
    if (filter_src_ip && !filter_dst_ip && filter_sport == 0 && filter_dport == 0)
    {
        return strcmp(src, filter_src_ip) == 0;
    }

    // 只指定目的IP
    if (!filter_src_ip && filter_dst_ip && filter_sport == 0 && filter_dport == 0)
    {
        return strcmp(dst, filter_dst_ip) == 0;
    }

    // 只指定源端口
    if (!filter_src_ip && !filter_dst_ip && filter_sport != 0 && filter_dport == 0)
    {
        return sport == filter_sport;
    }

    // 只指定目的端口
    if (!filter_src_ip && !filter_dst_ip && filter_sport == 0 && filter_dport != 0)
    {
        return dport == filter_dport;
    }

    // 同时指定源IP和目的IP
    if (filter_src_ip && filter_dst_ip && filter_sport == 0 && filter_dport == 0)
    {
        return strcmp(src, filter_src_ip) == 0 && strcmp(dst, filter_dst_ip) == 0;
    }

    // 同时指定源IP和源端口
    if (filter_src_ip && !filter_dst_ip && filter_sport != 0 && filter_dport == 0)
    {
        return strcmp(src, filter_src_ip) == 0 && sport == filter_sport;
    }

    // 同时指定源IP和目的端口
    if (filter_src_ip && !filter_dst_ip && filter_sport == 0 && filter_dport != 0)
    {
        return strcmp(src, filter_src_ip) == 0 && dport == filter_dport;
    }

    // 同时指定目的IP和源端口
    if (!filter_src_ip && filter_dst_ip && filter_sport != 0 && filter_dport == 0)
    {
        return strcmp(dst, filter_dst_ip) == 0 && sport == filter_sport;
    }

    // 同时指定目的IP和目的端口
    if (!filter_src_ip && filter_dst_ip && filter_sport == 0 && filter_dport != 0)
    {
        return strcmp(dst, filter_dst_ip) == 0 && dport == filter_dport;
    }

    // 同时指定源端口和目的端口
    if (!filter_src_ip && !filter_dst_ip && filter_sport != 0 && filter_dport != 0)
    {
        return sport == filter_sport && dport == filter_dport;
    }

    // 同时指定源IP、目的IP和源端口
    if (filter_src_ip && filter_dst_ip && filter_sport != 0 && filter_dport == 0)
    {
        return strcmp(src, filter_src_ip) == 0 && strcmp(dst, filter_dst_ip) == 0 && sport == filter_sport;
    }

    // 同时指定源IP、目的IP和目的端口
    if (filter_src_ip && filter_dst_ip && filter_sport == 0 && filter_dport != 0)
    {
        return strcmp(src, filter_src_ip) == 0 && strcmp(dst, filter_dst_ip) == 0 && dport == filter_dport;
    }

    // 同时指定源IP、源端口和目的端口
    if (filter_src_ip && !filter_dst_ip && filter_sport != 0 && filter_dport != 0)
    {
        return strcmp(src, filter_src_ip) == 0 && sport == filter_sport && dport == filter_dport;
    }

    // 同时指定目的IP、源端口和目的端口
    if (!filter_src_ip && filter_dst_ip && filter_sport != 0 && filter_dport != 0)
    {
        return strcmp(dst, filter_dst_ip) == 0 && sport == filter_sport && dport == filter_dport;
    }

    // 同时指定源IP、目的IP、源端口和目的端口
    if (filter_src_ip && filter_dst_ip && filter_sport != 0 && filter_dport != 0)
    {
        return strcmp(src, filter_src_ip) == 0 && strcmp(dst, filter_dst_ip) == 0 && sport == filter_sport && dport == filter_dport;
    }

    return 0;
}
int should_filter_t(const char *src, const char *dst, unsigned short sport, unsigned short dport,
                    const char *filter_src_ip, const char *filter_dst_ip, unsigned short filter_sport, unsigned short filter_dport)
{
    return match_filter(src, dst, sport, dport, filter_src_ip, filter_dst_ip, filter_sport, filter_dport);
}

int should_filter(const char *src, const char *dst, const char *filter_src_ip, const char *filter_dst_ip)
{

    return match_filter(src, dst, 0, 0, filter_src_ip, filter_dst_ip, 0, 0);
}
void print_logo()
{
    char *logo = LOGO_STRING;
    int i = 0;
    FILE *lolcat_pipe = popen("/usr/games/lolcat", "w");
    if (lolcat_pipe == NULL)
    {
        printf("Error: Unable to execute lolcat command.\n");
        return;
    }
    // 像lolcat管道逐个字符写入字符串
    while (logo[i] != '\0')
    {
        fputc(logo[i], lolcat_pipe);
        fflush(lolcat_pipe); // 刷新管道，确保字符被立即发送给lolcat
        usleep(150);
        i++;
    }

    pclose(lolcat_pipe);
}
void bytes_to_str(char *str, unsigned long long num)
{
    if (num > 1e9)
    {
        sprintf(str, "%.8lfG", (double)num / 1e9);
    }
    else if (num > 1e6)
    {
        sprintf(str, "%.6lfM", (double)num / 1e6);
    }
    else if (num > 1e3)
    {
        sprintf(str, "%.3lfK", (double)num / 1e3);
    }
    else
    {
        sprintf(str, "%llu", num);
    }
}
// LRU
struct SymbolEntry find_in_cache(unsigned long int addr)
{
    // 查找地址是否在快表中
    for (int i = 0; i < cache_size; i++)
    {
        if (cache[i].addr == addr)
        {
            // 更新访问时间
            struct SymbolEntry temp = cache[i];
            // 将访问的元素移动到快表的最前面，即最近使用的位置
            for (int j = i; j > 0; j--)
            {
                cache[j] = cache[j - 1];
            }
            cache[0] = temp;
            return temp;
        }
    }
    // 地址不在快表中
    struct SymbolEntry empty_entry;
    empty_entry.addr = 0;
    return empty_entry;
}
void add_to_cache(struct SymbolEntry entry)
{
    // 如果快表已满，则移除最久未使用的条目
    if (cache_size == CACHEMAXSIZE)
    {
        for (int i = cache_size - 1; i > 0; i--)
        {
            cache[i] = cache[i - 1];
        }
        cache[0] = entry;
    }
    else
    {
        // 否则，直接加入快表
        for (int i = cache_size; i > 0; i--)
        {
            cache[i] = cache[i - 1];
        }
        cache[0] = entry;
        cache_size++;
    }
}
struct SymbolEntry findfunc(unsigned long int addr)
{
    struct SymbolEntry entry = find_in_cache(addr);
    if (entry.addr != 0)
    {
        return entry;
    }
    unsigned long long low = 0, high = num_symbols - 1;
    unsigned long long result = -1;

    while (low <= high)
    {
        int mid = low + (high - low) / 2;
        if (symbols[mid].addr < addr)
        {
            result = mid;
            low = mid + 1;
        }
        else
        {
            high = mid - 1;
        }
    }
    add_to_cache(symbols[result]);
    return symbols[result];
};
void readallsym()
{
    FILE *file = fopen("/proc/kallsyms", "r");
    if (!file)
    {
        perror("Error opening file");
        exit(EXIT_FAILURE);
    }
    char line[256];
    while (fgets(line, sizeof(line), file))
    {
        unsigned long addr;
        char type, name[30];
        int ret = sscanf(line, "%lx %c %s", &addr, &type, name);
        if (ret == 3)
        {
            symbols[num_symbols].addr = addr;
            strncpy(symbols[num_symbols].name, name, 30);
            num_symbols++;
        }
    }

    fclose(file);
}
/*
    指数加权移动平均算法（EWMA）
    1.使用指数加权移动平均算法（EWMA）来计算每层的指数加权移动平均值，
    公式EWMA_new = alpha * new_value + (1 - alpha) * old_ewma ,alpha
   指数加权系数，表示新数据点的权重，new_value 当前时延，old_ewma
   旧的指数加权移动平均值
    2.根据当前时延和指数加权移动平均值*预先设定的粒度阈值（GRANULARITY）对比，来判断时延是否异常
    3.可以快速适应数据的变化，并能够有效地检测异常时延

*/
float calculate_ewma(float new_value, float old_ewma)
{
    return ALPHA * new_value + (1 - ALPHA) * old_ewma;
}

// 收集时延数据并检测异常
int process_delay(float layer_delay, int layer_index)
{

    if (layer_delay == 0)
        return 0;
    count[layer_index]++;
    if (ewma_values[layer_index] == 0)
    {
        ewma_values[layer_index] = layer_delay;
        return 0;
    }
    // 计算阈值,指数加权移动平均值乘以粒度因子
    ewma_values[layer_index] =
        calculate_ewma(layer_delay, ewma_values[layer_index]);
    float threshold = ewma_values[layer_index] * GRANULARITY;
    if (count[layer_index] > 30)
    {
        // 判断当前时延是否超过阈值
        //   printf("%d %d:%f %f
        //   ",layer_index,count[layer_index]++,threshold,layer_delay);
        if (layer_delay > threshold)
        { // 异常
            return 1;
        }
        else
        {
            return 0;
        }
    }
    return 0;
}
int process_redis_first(char flag, char *message)
{
    // 映射表
    const char *reply_types[] = {
        [0] = "Unknown Type",
        ['+'] = "Status Reply",
        ['-'] = "Error Reply",
        [':'] = "Integer Reply",
        ['$'] = "Bulk String Reply",
        ['*'] = "Array Reply"};

    // 使用 'flag' 查找对应的类型消息
    const char *reply_message = reply_types[(unsigned char)flag];

    // 将找到的消息复制到 'message' 中
    strcpy(message, reply_message);

    return 0;
}

int create_ring_buffer(struct ring_buffer **rb, int map_fd, void *print_fn, const char *name)
{
    *rb = ring_buffer__new(map_fd, print_fn, NULL, NULL);
    if (!*rb)
    {
        fprintf(stderr, "Failed to create ring buffer(%s)\n", name);
        return -1;
    }
    return 0;
}

int poll_ring_buffers(struct ring_buffer *buffers[], int num_buffers, int timeout_ms)
{
    int err = 0;
    for (int i = 0; i < num_buffers; i++)
    {
        err = ring_buffer__poll(buffers[i], timeout_ms);
        if (err < 0)
        {
            printf("Error polling ring buffer: %d\n", err);
            return err;
        }
    }
    return err;
}
void print_domain_name(const unsigned char *data, char *output)
{
    const unsigned char *next = data;
    int pos = 0, first = 1;
    // 循环到尾部，标志0
    while (*next != 0)
    {
        if (!first)
        {
            output[pos++] = '.'; // 在每个段之前添加点号
        }
        else
        {
            first = 0; // 第一个段后清除标志
        }
        int len = *next++; // 下一个段长度

        for (int i = 0; i < len; ++i)
        {
            output[pos++] = *next++;
        }
    }
    output[pos] = '\0';
}

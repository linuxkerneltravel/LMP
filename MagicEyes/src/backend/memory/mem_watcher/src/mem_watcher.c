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
// author: 3174314597@qq.com
//
// mem_watcher libbpf user mode code

#include <assert.h>
#include <argp.h>
#include <errno.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <sys/select.h>
#include <unistd.h>
#include "memory/mem_watcher/paf.skel.h"
#include "memory/mem_watcher/pr.skel.h"
#include "memory/mem_watcher/procstat.skel.h"
#include "memory/mem_watcher/sysstat.skel.h"
#include "memory/mem_watcher/fraginfo.skel.h"
// #include "memleak.skel.h"
#include "memory/mem_watcher/vmasnap.skel.h"
#include "memory/mem_watcher/drsnoop.skel.h"
#include "memory/mem_watcher/oomkiller.skel.h"
// #include "../../../../../blazesym/capi/include/blazesym.h"

#include "mem_watcher/include/mem_watcher.h"
#include "mem_watcher/include/fraginfo.h"
// #include "memory/mem_watcher/mem_watcher.skel.h"

// 定义标志结构体
typedef struct
{
	int flag;
	const char *name;
} Flag;

// 定义所有组合修饰符和单独标志位
Flag gfp_combined_list[] = {
	{GFP_ATOMIC, "GFP_ATOMIC"},
	{GFP_KERNEL, "GFP_KERNEL"},
	{GFP_KERNEL_ACCOUNT, "GFP_KERNEL_ACCOUNT"},
	{GFP_NOWAIT, "GFP_NOWAIT"},
	{GFP_NOIO, "GFP_NOIO"},
	{GFP_NOFS, "GFP_NOFS"},
	{GFP_USER, "GFP_USER"},
	{GFP_DMA, "GFP_DMA"},
	{GFP_DMA32, "GFP_DMA32"},
	{GFP_HIGHUSER, "GFP_HIGHUSER"},
	{GFP_HIGHUSER_MOVABLE, "GFP_HIGHUSER_MOVABLE"},
	{GFP_TRANSHUGE_LIGHT, "GFP_TRANSHUGE_LIGHT"},
	{GFP_TRANSHUGE, "GFP_TRANSHUGE"},
};

Flag gfp_separate_list[] = {
	{___GFP_DMA, "___GFP_DMA"},
	{___GFP_HIGHMEM, "___GFP_HIGHMEM"},
	{___GFP_DMA32, "___GFP_DMA32"},
	{___GFP_MOVABLE, "___GFP_MOVABLE"},
	{___GFP_RECLAIMABLE, "___GFP_RECLAIMABLE"},
	{___GFP_HIGH, "___GFP_HIGH"},
	{___GFP_IO, "___GFP_IO"},
	{___GFP_FS, "___GFP_FS"},
	{___GFP_ZERO, "___GFP_ZERO"},
	{___GFP_ATOMIC, "___GFP_ATOMIC"},
	{___GFP_DIRECT_RECLAIM, "___GFP_DIRECT_RECLAIM"},
	{___GFP_KSWAPD_RECLAIM, "___GFP_KSWAPD_RECLAIM"},
	{___GFP_WRITE, "___GFP_WRITE"},
	{___GFP_NOWARN, "___GFP_NOWARN"},
	{___GFP_RETRY_MAYFAIL, "___GFP_RETRY_MAYFAIL"},
	{___GFP_NOFAIL, "___GFP_NOFAIL"},
	{___GFP_NORETRY, "___GFP_NORETRY"},
	{___GFP_MEMALLOC, "___GFP_MEMALLOC"},
	{___GFP_COMP, "___GFP_COMP"},
	{___GFP_NOMEMALLOC, "___GFP_NOMEMALLOC"},
	{___GFP_HARDWALL, "___GFP_HARDWALL"},
	{___GFP_THISNODE, "___GFP_THISNODE"},
	{___GFP_ACCOUNT, "___GFP_ACCOUNT"},
	{___GFP_ZEROTAGS, "___GFP_ZEROTAGS"},
	{___GFP_SKIP_KASAN_POISON, "___GFP_SKIP_KASAN_POISON"},
};

static const int perf_max_stack_depth = 127;	// stack id 对应的堆栈的深度
static const int stack_map_max_entries = 10240; // 最大允许存储多少个stack_id
static __u64 *g_stacks = NULL;
static size_t g_stacks_size = 0;

#define KERN_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP)
#define USER_STACKID_FLAGS (0 | BPF_F_FAST_STACK_CMP | BPF_F_USER_STACK)

static struct blaze_symbolizer *symbolizer;

static int attach_pid;
pid_t own_pid;
static char binary_path[128] = {0};

struct allocation
{
	int stack_id;
	__u64 size;
	size_t count;
};
// ============================= fraginfo====================================
struct order_entry
{
	struct order_zone okey;
	struct ctg_info oinfo;
};

int compare_entries(const void *a, const void *b)
{
	struct order_entry *entryA = (struct order_entry *)a;
	struct order_entry *entryB = (struct order_entry *)b;

	if (entryA->okey.zone_ptr != entryB->okey.zone_ptr)
	{
		return (entryA->okey.zone_ptr < entryB->okey.zone_ptr) ? -1 : 1;
	}
	else
	{
		return (entryA->okey.order < entryB->okey.order) ? -1 : 1;
	}
}

// ============================= fraginfo====================================
static struct allocation *allocs;

static volatile bool exiting = false;

#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)  \
	do                                                           \
	{                                                            \
		LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts,                \
					.func_name = #sym_name,                      \
					.retprobe = is_retprobe);                    \
		skel->links.prog_name = bpf_program__attach_uprobe_opts( \
			skel->progs.prog_name,                               \
			attach_pid,                                          \
			binary_path,                                         \
			0,                                                   \
			&uprobe_opts);                                       \
	} while (false)

#define __CHECK_PROGRAM(skel, prog_name)                   \
	do                                                     \
	{                                                      \
		if (!skel->links.prog_name)                        \
		{                                                  \
			perror("no program attached for " #prog_name); \
			return -errno;                                 \
		}                                                  \
	} while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
	do                                                                  \
	{                                                                   \
		__ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
		__CHECK_PROGRAM(skel, prog_name);                               \
	} while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#define PROCESS_SKEL(skel, func)                                   \
	skel = func##_bpf__open();                                     \
	if (!skel)                                                     \
	{                                                              \
		fprintf(stderr, "Failed to open and load BPF skeleton\n"); \
		return 1;                                                  \
	}                                                              \
	process_##func(skel)

#define POLL_RING_BUFFER(rb, timeout, err)                  \
	while (!exiting)                                        \
	{                                                       \
		err = ring_buffer__poll(rb, timeout);               \
		if (err == -EINTR)                                  \
		{                                                   \
			err = 0;                                        \
			break;                                          \
		}                                                   \
		if (err < 0)                                        \
		{                                                   \
			printf("Error polling perf buffer: %d\n", err); \
			break;                                          \
		}                                                   \
	}

// 为 oomkiller 使用的宏，指定 map_name
#define LOAD_AND_ATTACH_SKELETON_WITH_MAP(skel, event, map_name)                                \
	do                                                                                         \
	{                                                                                          \
		err = event##_bpf__load(skel);                                                         \
		if (err)                                                                               \
		{                                                                                      \
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");                       \
			goto event##_cleanup;                                                              \
		}                                                                                      \
                                                                                               \
		err = event##_bpf__attach(skel);                                                       \
		if (err)                                                                               \
		{                                                                                      \
			fprintf(stderr, "Failed to attach BPF skeleton\n");                                \
			goto event##_cleanup;                                                              \
		}                                                                                      \
                                                                                               \
		rb = ring_buffer__new(bpf_map__fd(skel->maps.map_name), handle_event_##event, NULL, NULL); \
		if (!rb)                                                                               \
		{                                                                                      \
			fprintf(stderr, "Failed to create ring buffer\n");                                 \
			goto event##_cleanup;                                                              \
		}                                                                                      \
	} while (0)

// 保留原有逻辑的宏
#define LOAD_AND_ATTACH_SKELETON(skel, event)                                                   \
	do                                                                                         \
	{                                                                                          \
		err = event##_bpf__load(skel);                                                         \
		if (err)                                                                               \
		{                                                                                      \
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");                       \
			goto event##_cleanup;                                                              \
		}                                                                                      \
                                                                                               \
		err = event##_bpf__attach(skel);                                                       \
		if (err)                                                                               \
		{                                                                                      \
			fprintf(stderr, "Failed to attach BPF skeleton\n");                                \
			goto event##_cleanup;                                                              \
		}                                                                                      \
                                                                                               \
		rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_##event, NULL, NULL); \
		if (!rb)                                                                               \
		{                                                                                      \
			fprintf(stderr, "Failed to create ring buffer\n");                                 \
			goto event##_cleanup;                                                              \
		}                                                                                      \
	} while (0)

static struct env
{
    int time;            // 最大运行时间，单位为秒
    bool paf;            // 是否启用内存页面状态报告
    bool pr;             // 是否启用页面回收状态报告
    bool procstat;       // 是否启用进程内存状态报告
    bool sysstat;        // 是否启用系统内存状态报告
    // bool memleak;        // 是否启用内核态/用户态内存泄漏检测
    bool fraginfo;       // 是否启用内存碎片信息
	bool nodes;
	bool zones;
    bool vmasnap;        // 是否启用虚拟内存区域信息
    bool drsnoop;
    bool kernel_trace;   // 是否启用内核态跟踪
    bool print_time;     // 是否打印地址申请时间
    int interval;        // 打印间隔，单位为秒
    int duration;        // 运行时长，单位为秒
    bool part2;          // 是否启用系统内存状态报告的扩展部分
    bool oomkiller;      // 是否启用oomkiller事件处理

    long choose_pid;     // 选择的进程号
    bool rss;            // 是否打印进程页面信息
} env = {
    .time = 0,             // 0 表示无限运行
    .paf = false,          // 默认关闭内存页面状态报告
    .pr = false,           // 默认关闭页面回收状态报告
    .procstat = false,     // 默认关闭进程内存状态报告
    .sysstat = false,      // 默认关闭系统内存状态报告
    // .memleak = false,      // 默认关闭内存泄漏检测
    .fraginfo = false,     // 默认关闭内存碎片信息
	.zones=false,
	.nodes=false,
    .vmasnap = false,      // 默认关闭虚拟内存区域信息
    .drsnoop = false,
    .kernel_trace = true,  // 默认启用内核态跟踪
    .print_time = false,   // 默认不打印地址申请时间
    .rss = false,          // 默认不打印进程页面信息
    .part2 = false,        // 默认关闭系统内存状态报告的扩展部分
    .oomkiller = false,    // 默认关闭oomkiller事件处理
    .choose_pid = 0,       // 默认不选择特定进程
    .interval = 1,         // 默认打印间隔为1秒
    .duration = 10,        // 默认持续运行10秒
};


const char argp_program_doc[] = "mem_watcher is in use ....\n";

static const struct argp_option opts[] = {
	{0, 0, 0, 0, "select function:", 1},

	{0, 0, 0, 0, "par:", 2},
	{"paf", 'a', 0, 0, "print paf (内存页面状态报告)"},

	{0, 0, 0, 0, "pr:", 3},
	{"pr", 'p', 0, 0, "print pr (页面回收状态报告)"},

	{0, 0, 0, 0, "procstat:", 4},
	{"procstat", 'r', 0, 0, "print procstat (进程内存状态报告)"},
	{"choose_pid", 'P', "PID", 0, "选择进程号打印"},
	{"Rss", 'R', NULL, 0, "打印进程页面", 5},

	{0, 0, 0, 0, "sysstat:", 6},
	{"sysstat", 's', 0, 0, "print sysstat (系统内存状态报告)"},

	{"part2", 'n', NULL, 0, "系统内存状态报告2", 7},

	// {0, 0, 0, 0, "memleak:", 8},
	// {"memleak", 'l', 0, 0, "print memleak (内核态内存泄漏检测)", 8},
	// {"choose_pid", 'P', "PID", 0, "选择进程号打印, print memleak (用户态内存泄漏检测)", 9},
	// {"print_time", 'm', 0, 0, "打印申请地址时间 (用户态)", 10},
	// {"print_time", 'f', 0, 0, "打印申请地址时间 (用户态)", 10},
	// {"time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)", 11},

	{0, 0, 0, 0, "fraginfo:", 12},
	{"fraginfo", 'f', 0, 0, "print fraginfo", 12},
	{"interval", 'i', "INTERVAL", 0, "Print interval in seconds (default 1)"},
	{"duration", 'd', "DURATION", 0, "Total duration in seconds to run (default 10)"},
	{"nodes", 'j', 0, 0, "Print nodes info"},
	{"zones", 'z', 0, 0, "Print zones info"},

	{0, 0, 0, 0, "vmasnap:", 13},
	{"vmasnap", 'v', 0, 0, "print vmasnap (虚拟内存区域信息)"},

	{0, 0, 0, 0, "drsnoop:", 14},
	{"drsnoop", 'b', 0, 0, "print drsnoop (直接回收追踪信息)"},
	{"choose_pid", 'P', "PID", 0, "选择要检测直接回收信息的进程号"},

	{0, 0, 0, 0, "oomkiller:", 15},  // 新增的 oomkiller 选项
	{"oomkiller", 'o', 0, 0, "print oomkiller (内存不足时被杀死的进程信息)"},

	{NULL, 'h', NULL, OPTION_HIDDEN, "show the full help"},
	{0},
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 't':
		env.time = strtol(arg, NULL, 10);
		if (env.time)
			alarm(env.time);
		break;
	case 'a':
		env.paf = true;
		break;
	case 'p':
		env.pr = true;
		break;
	case 'r':
		env.procstat = true;
		break;
	case 'f':
		env.fraginfo = true;
		break;
	case 'j':
		if(env.fraginfo)
			env.nodes=true;
		break;
	case 'z':
		if(env.fraginfo)
			env.zones=true;
		break;
	case 'v':
		env.vmasnap = true;
		break;
	case 's':
		env.sysstat = true;
		break;
	case 'n':
		env.part2 = true;
		break;
	case 'P':
		env.choose_pid = strtol(arg, NULL, 10);
		break;
	case 'R':
		env.rss = true;
		break;
	// case 'l':
	// 	env.memleak = true;
	// 	break;
	case 'b':
		env.drsnoop = true;
		break;
	case 'm':
		env.print_time = true;
		break;
	case 'o':  // 处理 oomkiller 选项
		env.oomkiller = true;
		break;
	case 'h':
		argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
		break;
	case 'i':
		env.interval = atoi(arg);
		break;
	case 'd':
		env.duration = atoi(arg);
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


// Function prototypes
// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args);
static void sig_handler(int sig);
static void setup_signals(void);
// static void disable_kernel_tracepoints(struct memleak_bpf *skel);
// static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info *code_info);
static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid);
// static int print_outstanding_allocs(struct memleak_bpf *skel);
// static int print_outstanding_combined_allocs(struct memleak_bpf *skel, pid_t pid);
static int get_vm_stat_addr(__u64 *addr);
static int handle_event_paf(void *ctx, void *data, size_t data_sz);
static int handle_event_pr(void *ctx, void *data, size_t data_sz);
static int handle_event_procstat(void *ctx, void *data, size_t data_sz);
static int handle_event_sysstat(void *ctx, void *data, size_t data_sz);
static int handle_event_drsnoop(void *ctx, void *data, size_t data_sz);
// static int attach_uprobes(struct memleak_bpf *skel);
static void print_flag_modifiers(int flag);
static int process_paf(struct paf_bpf *skel_paf);
static int process_pr(struct pr_bpf *skel_pr);
static int process_procstat(struct procstat_bpf *skel_procstat);
static int process_sysstat(struct sysstat_bpf *skel_sysstat);
// static int process_memleak(struct memleak_bpf *skel_memleak, struct env);
static int process_fraginfo(struct fraginfo_bpf *skel_fraginfo);
static int process_vmasnap(struct vmasnap_bpf *skel_vmasnap);
static int process_drsnoop(struct drsnoop_bpf *skel_drsnoop);
static int process_oomkiller(struct oomkiller_bpf *skel_oomkiller);  // 新增的oomkiller处理函数原型
static int handle_event_oomkiller(void *ctx, void *data, size_t data_sz);  // 新增的oomkiller事件处理函数
static __u64 adjust_time_to_program_start_time(__u64 first_query_time);
// static int update_addr_times(struct memleak_bpf *skel_memleak);
// static int print_time(struct memleak_bpf *skel_memleak);
static void print_find_event_data(int map_fd);
static void print_insert_event_data(int map_fd);

// Main function
int main(int argc, char **argv)
{
    int err;
    struct paf_bpf *skel_paf;
    struct pr_bpf *skel_pr;
    struct procstat_bpf *skel_procstat;
    struct sysstat_bpf *skel_sysstat;
    // struct memleak_bpf *skel_memleak;
    struct fraginfo_bpf *skel_fraginfo;
    struct vmasnap_bpf *skel_vmasnap;
    struct oomkiller_bpf *skel_oomkiller;
    struct drsnoop_bpf *skel_drsnoop;

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    own_pid = getpid();
    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);

    setup_signals();

    if (env.paf)
    {
        PROCESS_SKEL(skel_paf, paf);
    }
    else if (env.pr)
    {
        PROCESS_SKEL(skel_pr, pr);
    }
    else if (env.procstat)
    {
        PROCESS_SKEL(skel_procstat, procstat);
    }
    else if (env.fraginfo)
    {
        PROCESS_SKEL(skel_fraginfo, fraginfo);
    }
    else if (env.vmasnap)
    {
        PROCESS_SKEL(skel_vmasnap, vmasnap);
    }
    else if (env.sysstat)
    {
        PROCESS_SKEL(skel_sysstat, sysstat);
    }
    // else if (env.memleak)
    // {
    //     if (env.choose_pid != 0)
    //     {
    //         printf("用户态内存泄漏\n");
    //         env.kernel_trace = false;
    //         attach_pid = env.choose_pid;
    //     }
    //     else
    //         attach_pid = 0;

    //     strcpy(binary_path, "/lib/x86_64-linux-gnu/libc.so.6");

    //     allocs = calloc(ALLOCS_MAX_ENTRIES, sizeof(*allocs));

    //     skel_memleak = memleak_bpf__open();
    //     if (!skel_memleak)
    //     {
    //         fprintf(stderr, "Failed to open BPF skeleton\n");
    //         return 1;
    //     }
    //     process_memleak(skel_memleak, env);
    // }
    else if (env.oomkiller)  // 处理 oomkiller
    {
        PROCESS_SKEL(skel_oomkiller, oomkiller);  // 使用处理 oomkiller 的函数
    }
    else if (env.drsnoop)
	{
		PROCESS_SKEL(skel_drsnoop, drsnoop);
	}

    return 0;
}


int alloc_size_compare(const void *a, const void *b)
{
	const struct allocation *x = (struct allocation *)a;
	const struct allocation *y = (struct allocation *)b;

	// descending order

	if (x->size > y->size)
		return -1;

	if (x->size < y->size)
		return 1;

	return 0;
}

// static void print_frame(const char *name, uintptr_t input_addr, uintptr_t addr, uint64_t offset, const blaze_symbolize_code_info *code_info)
// {
// 	// If we have an input address  we have a new symbol.
// 	if (input_addr != 0)
// 	{
// 		printf("%016lx: %s @ 0x%lx+0x%lx", input_addr, name, addr, offset);
// 		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
// 		{
// 			printf(" %s/%s:%u\n", code_info->dir, code_info->file, code_info->line);
// 		}
// 		else if (code_info != NULL && code_info->file != NULL)
// 		{
// 			printf(" %s:%u\n", code_info->file, code_info->line);
// 		}
// 		else
// 		{
// 			printf("\n");
// 		}
// 	}
// 	else
// 	{
// 		printf("%16s  %s", "", name);
// 		if (code_info != NULL && code_info->dir != NULL && code_info->file != NULL)
// 		{
// 			printf("@ %s/%s:%u [inlined]\n", code_info->dir, code_info->file, code_info->line);
// 		}
// 		else if (code_info != NULL && code_info->file != NULL)
// 		{
// 			printf("@ %s:%u [inlined]\n", code_info->file, code_info->line);
// 		}
// 		else
// 		{
// 			printf("[inlined]\n");
// 		}
// 	}
// }

// static void show_stack_trace(__u64 *stack, int stack_sz, pid_t pid)
// {
// 	const struct blaze_symbolize_inlined_fn *inlined;
// 	const struct blaze_result *result;
// 	const struct blaze_sym *sym;
// 	int i, j;

// 	assert(sizeof(uintptr_t) == sizeof(uint64_t));

// 	if (pid)
// 	{
// 		struct blaze_symbolize_src_process src = {
// 			.type_size = sizeof(src),
// 			.pid = pid,
// 		};
// 		result = blaze_symbolize_process_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
// 	}
// 	else
// 	{
// 		struct blaze_symbolize_src_kernel src = {
// 			.type_size = sizeof(src),
// 		};
// 		result = blaze_symbolize_kernel_abs_addrs(symbolizer, &src, (const uintptr_t *)stack, stack_sz);
// 	}

// 	for (i = 0; i < stack_sz; i++)
// 	{
// 		if (!result || result->cnt <= i || result->syms[i].name == NULL)
// 		{
// 			printf("%016llx: <no-symbol>\n", stack[i]);
// 			continue;
// 		}

// 		sym = &result->syms[i];
// 		print_frame(sym->name, stack[i], sym->addr, sym->offset, &sym->code_info);

// 		for (j = 0; j < sym->inlined_cnt; j++)
// 		{
// 			inlined = &sym->inlined[j];
// 			print_frame(sym->name, 0, 0, 0, &inlined->code_info);
// 		}
// 	}

// 	blaze_result_free(result);
// }

// int print_outstanding_allocs(struct memleak_bpf *skel)
// {
// 	const size_t allocs_key_size = bpf_map__key_size(skel->maps.allocs);

// 	time_t t = time(NULL);
// 	struct tm *tm = localtime(&t);

// 	size_t nr_allocs = 0;

// 	// for each struct alloc_info "alloc_info" in the bpf map "allocs"
// 	for (__u64 prev_key = 0, curr_key = 0;; prev_key = curr_key)
// 	{
// 		struct alloc_info alloc_info = {};
// 		memset(&alloc_info, 0, sizeof(alloc_info));

// 		if (bpf_map__get_next_key(skel->maps.allocs, &prev_key, &curr_key, allocs_key_size))
// 		{
// 			if (errno == ENOENT)
// 			{
// 				break; // no more keys, done
// 			}

// 			perror("map get next key error");

// 			return -errno;
// 		}

// 		if (bpf_map__lookup_elem(skel->maps.allocs, &curr_key, allocs_key_size, &alloc_info, sizeof(alloc_info), 0))
// 		{
// 			if (errno == ENOENT)
// 				continue;

// 			perror("map lookup error");

// 			return -errno;
// 		}

		// filter invalid stacks
	// 	if (alloc_info.stack_id < 0)
	// 	{
	// 		continue;
	// 	}

	// 	// when the stack_id exists in the allocs array,
	// 	//   increment size with alloc_info.size
	// 	bool stack_exists = false;

	// 	for (size_t i = 0; !stack_exists && i < nr_allocs; ++i)
	// 	{
	// 		struct allocation *alloc = &allocs[i];

	// 		if (alloc->stack_id == alloc_info.stack_id)
	// 		{
	// 			alloc->size += alloc_info.size;
	// 			alloc->count++;

	// 			stack_exists = true;
	// 			break;
	// 		}
	// 	}

	// 	if (stack_exists)
	// 		continue;

	// 	// when the stack_id does not exist in the allocs array,
	// 	//   create a new entry in the array
	// 	struct allocation alloc = {
	// 		.stack_id = alloc_info.stack_id,
	// 		.size = alloc_info.size,
	// 		.count = 1,
	// 	};

	// 	memcpy(&allocs[nr_allocs], &alloc, sizeof(alloc));
	// 	nr_allocs++;
	// }

	// sort the allocs array in descending order
	//sqsort(allocs, nr_allocs, sizeof(allocs[0]), alloc_size_compare);

	// get min of allocs we stored vs the top N requested stacks
// 	size_t nr_allocs_to_show = nr_allocs < 10 ? nr_allocs : 10;

// 	printf("[%d:%d:%d] Top %zu stacks with outstanding allocations:\n",
// 		   tm->tm_hour, tm->tm_min, tm->tm_sec, nr_allocs_to_show);

// 	for (size_t i = 0; i < nr_allocs_to_show; i++)
// 	{
// 		if (bpf_map__lookup_elem(skel->maps.stack_traces,
// 								 &allocs[i].stack_id, sizeof(allocs[i].stack_id), g_stacks, g_stacks_size, 0))
// 		{
// 			perror("failed to lookup stack traces!");
// 			return -errno;
// 		}
// 	}

// 	show_stack_trace(g_stacks, nr_allocs_to_show, 0);

// 	return 0;
// }

// int print_outstanding_combined_allocs(struct memleak_bpf *skel, pid_t pid)
// {
// 	const size_t combined_allocs_key_size = bpf_map__key_size(skel->maps.combined_allocs);
// 	const size_t stack_traces_key_size = bpf_map__key_size(skel->maps.stack_traces);

// 	for (__u64 prev_key = 0, curr_key = 0;; prev_key = curr_key)
// 	{

// 		if (bpf_map__get_next_key(skel->maps.combined_allocs,
// 								  &prev_key, &curr_key, combined_allocs_key_size))
// 		{
// 			if (errno == ENOENT)
// 			{
// 				break; // no more keys, done!
// 			}
// 			perror("map get next key failed!");

// 			return -errno;
// 		}

// 		// stack_id = curr_key
// 		union combined_alloc_info cinfo;
// 		memset(&cinfo, 0, sizeof(cinfo));

// 		if (bpf_map__lookup_elem(skel->maps.combined_allocs,
// 								 &curr_key, combined_allocs_key_size, &cinfo, sizeof(cinfo), 0))
// 		{
// 			if (errno == ENOENT)
// 			{
// 				continue;
// 			}

// 			perror("map lookup failed!");
// 			return -errno;
// 		}

// 		if (bpf_map__lookup_elem(skel->maps.stack_traces,
// 								 &curr_key, stack_traces_key_size, g_stacks, g_stacks_size, 0))
// 		{
// 			perror("failed to lookup stack traces!");
// 			return -errno;
// 		}

// 		printf("stack_id=0x%llx with outstanding allocations: total_size=%llu nr_allocs=%llu\n",
// 			   curr_key, (__u64)cinfo.total_size, (__u64)cinfo.number_of_allocs);

// 		int stack_sz = 0;
// 		for (int i = 0; i < perf_max_stack_depth; i++)
// 		{
// 			if (g_stacks[i] == 0)
// 			{
// 				break;
// 			}
// 			stack_sz++;
// 			// printf("[%3d] 0x%llx\n", i, g_stacks[i]);
// 		}

// 		show_stack_trace(g_stacks, stack_sz, pid);
// 	}

// 	return 0;
// }

// // 在更新时间之前获取当前时间并调整为相对于程序启动时的时间
// static __u64 adjust_time_to_program_start_time(__u64 first_query_time)
// {
// 	struct timespec current_time;
// 	clock_gettime(CLOCK_MONOTONIC, &current_time);
// 	// printf("current_time: %ld\n", current_time.tv_sec);
// 	__u64 adjusted_time;
// 	adjusted_time = current_time.tv_sec - first_query_time;

// 	// printf("adjusted_time: %lld\n", adjusted_time);
// 	return adjusted_time;
// }

// // 在更新时间时，先将时间调整为相对于程序启动的时间
// static int update_addr_times(struct memleak_bpf *skel)
// {
// 	const size_t addr_times_key_size = bpf_map__key_size(skel->maps.addr_times);
// 	const size_t first_time_key_size = bpf_map__key_size(skel->maps.first_time);
// 	for (__u64 prev_key = 0, curr_key = 0;; prev_key = curr_key)
// 	{
// 		if (bpf_map__get_next_key(skel->maps.addr_times, &prev_key, &curr_key, addr_times_key_size))
// 		{
// 			if (errno == ENOENT)
// 			{
// 				break; // no more keys, done!
// 			}

// 			perror("map get next key failed!");
// 			return -errno;
// 		}

// 		// Check if the address exists in the first_time map
// 		__u64 first_query_time;
// 		if (bpf_map__lookup_elem(skel->maps.first_time, &curr_key, first_time_key_size, &first_query_time, sizeof(first_query_time), 0))
// 		{
// 			// Address doesn't exist in the first_time map, add it with the current time
// 			struct timespec first_time_alloc;
// 			clock_gettime(CLOCK_MONOTONIC, &first_time_alloc);
// 			if (bpf_map__update_elem(skel->maps.first_time, &curr_key, first_time_key_size, &first_time_alloc.tv_sec, sizeof(first_time_alloc.tv_sec), 0))
// 			{
// 				perror("map update failed!");
// 				return -errno;
// 			}
// 		}
// 		else
// 		{
// 			// Address exists in the first_time map
// 			// This is the first time updating timestamp
// 			__u64 adjusted_time = adjust_time_to_program_start_time(first_query_time);
// 			// printf("update_addr_times adjusted_time: %lld\n", adjusted_time);

// 			// Save the adjusted time to addr_times map
// 			__u64 timestamp = adjusted_time;

// 			// write the updated timestamp back to the map
// 			if (bpf_map__update_elem(skel->maps.addr_times, &curr_key, addr_times_key_size, &timestamp, sizeof(timestamp), 0))
// 			{
// 				perror("map update failed!");
// 				return -errno;
// 			}
// 		}
// 	}
// 	return 0;
// }

// // 在打印时间时，先将时间调整为相对于程序启动的时间
// int print_time(struct memleak_bpf *skel)
// {
// 	const size_t addr_times_key_size = bpf_map__key_size(skel->maps.addr_times);

// 	printf("%-16s %12s\n", "AL_ADDR", "AL_Time(s)");

// 	// Iterate over the addr_times map to print address and time
// 	for (__u64 prev_key = 0, curr_key = 0;; prev_key = curr_key)
// 	{
// 		if (bpf_map__get_next_key(skel->maps.addr_times, &prev_key, &curr_key, addr_times_key_size))
// 		{
// 			if (errno == ENOENT)
// 			{
// 				break; // no more keys, done!
// 			}
// 			perror("map get next key failed!");
// 			return -errno;
// 		}

// 		// Read the timestamp for the current address
// 		__u64 timestamp;
// 		if (bpf_map__lookup_elem(skel->maps.addr_times, &curr_key, addr_times_key_size, &timestamp, sizeof(timestamp), 0) == 0)
// 		{
// 			printf("0x%-16llx %lld\n", curr_key, timestamp);
// 		}
// 		else
// 		{
// 			perror("map lookup failed!");
// 			return -errno;
// 		}
// 	}
// 	return 0;
// }

// void disable_kernel_tracepoints(struct memleak_bpf *skel)
// {
// 	bpf_program__set_autoload(skel->progs.memleak__kmalloc, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kmalloc_node, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kfree, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_alloc_node, false);
// 	bpf_program__set_autoload(skel->progs.memleak__kmem_cache_free, false);
// 	bpf_program__set_autoload(skel->progs.memleak__mm_page_alloc, false);
// 	bpf_program__set_autoload(skel->progs.memleak__mm_page_free, false);
// }

static int get_vm_stat_addr(__u64 *addr)
{
    FILE *file = fopen(KALLSYMS_PATH, "r");
    if (!file) {
        perror("fopen");
        return -1;
    }

    char line[256];
    while (fgets(line, sizeof(line), file)) {
        unsigned long address;
        char symbol[256];
        if (sscanf(line, "%lx %*s %s", &address, symbol) == 2) {
            if (strcmp(symbol, VM_STAT_SYMBOL) == 0 || strcmp(symbol, VM_ZONE_STAT_SYMBOL) == 0) {
                *addr = address;
                fclose(file);
                return 0;
            }
        }
    }

    fclose(file);
    return -1; // Symbol not found
}

// static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
// {
// 	return vfprintf(stderr, format, args);
// }

static void sig_handler(int sig)
{
	exiting = true;
	exit(EXIT_SUCCESS);
}

static void setup_signals(void)
{
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
	signal(SIGALRM, sig_handler);
}

static void print_flag_modifiers(int flag)
{
	char combined[512] = {0}; // 用于保存组合修饰符
	char separate[512] = {0}; // 用于保存单独标志位

	// 检查组合修饰符
	for (int i = 0; i < sizeof(gfp_combined_list) / sizeof(gfp_combined_list[0]); ++i)
	{
		if ((flag & gfp_combined_list[i].flag) == gfp_combined_list[i].flag)
		{
			strcat(combined, gfp_combined_list[i].name);
			strcat(combined, " | ");
		}
	}

	// 移除最后一个 " | " 字符串的末尾
	if (strlen(combined) > 3)
	{
		combined[strlen(combined) - 3] = '\0';
	}

	// 检查单独标志位
	for (int i = 0; i < sizeof(gfp_separate_list) / sizeof(gfp_separate_list[0]); ++i)
	{
		if (flag & gfp_separate_list[i].flag)
		{
			strcat(separate, gfp_separate_list[i].name);
			strcat(separate, " | ");
		}
	}

	// 移除最后一个 " | " 字符串的末尾
	if (strlen(separate) > 3)
	{
		separate[strlen(separate) - 3] = '\0';
	}

	// 打印组合修饰符和单独标志位
	printf("%-50s %-100s\n", combined, separate);
}

static int handle_event_paf(void *ctx, void *data, size_t data_sz)
{
	const struct paf_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8lu %-8lu %-8lu %-8lu %-8x ",
		   e->min, e->low, e->high, e->present, e->flag);
	print_flag_modifiers(e->flag);
	printf("\n");

	return 0;
}

static int handle_event_pr(void *ctx, void *data, size_t data_sz)
{
	const struct pr_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8lu %-8lu  %-8u %-8u %-8u\n",
		   e->reclaim, e->reclaimed, e->unqueued_dirty, e->congested, e->writeback);

	return 0;
}

static int handle_event_procstat(void *ctx, void *data, size_t data_sz)
{
	const struct procstat_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	if (env.choose_pid)
	{
		if (e->pid == env.choose_pid)
		{
			if (env.rss == true)
				printf("%-8s %-8d %-8ld %-8ld %-8ld %-8lld %-8lld\n", ts, e->pid, e->vsize, e->Vdata, e->Vstk, e->VPTE, e->vswap);
			else
				printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
		}
	}
	else
	{
		if (env.rss == true)
			printf("%-8s %-8d %-8ld %-8ld %-8ld %-8lld %-8lld\n", ts, e->pid, e->vsize, e->Vdata, e->Vstk, e->VPTE, e->vswap);
		else
			printf("%-8s %-8d %-8ld %-8lld %-8lld %-8lld\n", ts, e->pid, e->size, e->rssanon, e->rssfile, e->rssshmem);
	}

	return 0;
}

static int handle_event_sysstat(void *ctx, void *data, size_t data_sz)
{
	const struct sysstat_event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	if (env.part2 == true)
		printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu\n", e->slab_reclaimable + e->kernel_misc_reclaimable, e->slab_reclaimable + e->slab_unreclaimable, e->slab_reclaimable, e->slab_unreclaimable, e->unstable_nfs, e->writeback_temp, e->anon_thps, e->shmem_thps, e->pmdmapped);
	else
		printf("%-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu %-8lu\n", e->anon_active + e->file_active, e->file_inactive + e->anon_inactive, e->anon_active, e->anon_inactive, e->file_active, e->file_inactive, e->unevictable, e->file_dirty, e->writeback, e->anon_mapped, e->file_mapped, e->shmem);

	return 0;
}

static int handle_event_drsnoop(void *ctx, void *data, size_t data_sz)
{
    const struct data_t *e = data;
    struct tm *tm;
    char ts[32];
	time_t t;

	// 检查是否选择了特定的 PID，并且事件的 PID 是否匹配
    if (env.choose_pid != 0 && e->id >> 32 != env.choose_pid) {
        return 0;  // 忽略不匹配的事件
    }

    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    __u64 delta_us = e->delta / 1000;
    __u64 delta_ms = delta_us / 1000;
    __u64 fractional_us = delta_us % 1000;

    printf("%-8s %-16s %-7llu %-9llu %llu.%02llu\n", ts, e->name, e->id >> 32, K(e->vm_stat[NR_FREE_PAGES]), delta_ms, fractional_us);

    return 0;
}

static int handle_event_oomkiller(void *ctx, void *data, size_t data_sz)
{
    const struct event *e = data;  // 假设事件结构为 struct event
    static int header_printed = 0; // 标记是否已经打印表头
    struct tm *tm;
    char ts[32];
    time_t t;

    // 获取当前时间戳
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);

    // 打印表头，说明输出内容 (只打印一次)
    if (!header_printed) {
        printf("%-20s %-20s %-20s %-20s\n", 
               "触发 OOM 的进程 (PID)", "被杀进程 (PID)", "内存页数", "被杀进程的命令名");
        printf("----------------------------------------------------------------------------------------\n");
        header_printed = 1;
    }

    // 打印事件数据，包含 OOM 事件的关键信息
    printf("%-20d %-20d %-20u %-20s\n", 
           e->triggered_pid, e->oomkill_pid, e->mem_pages, e->comm);

    return 0;
}

// int attach_uprobes(struct memleak_bpf *skel)
// {
// 	ATTACH_UPROBE_CHECKED(skel, malloc, malloc_enter);
// 	ATTACH_URETPROBE_CHECKED(skel, malloc, malloc_exit);
// 	ATTACH_UPROBE_CHECKED(skel, free, free_enter);

// 	ATTACH_UPROBE_CHECKED(skel, posix_memalign, posix_memalign_enter);
// 	ATTACH_URETPROBE_CHECKED(skel, posix_memalign, posix_memalign_exit);

// 	ATTACH_UPROBE_CHECKED(skel, calloc, calloc_enter);
// 	ATTACH_URETPROBE_CHECKED(skel, calloc, calloc_exit);

// 	ATTACH_UPROBE_CHECKED(skel, realloc, realloc_enter);
// 	ATTACH_URETPROBE_CHECKED(skel, realloc, realloc_exit);

// 	ATTACH_UPROBE_CHECKED(skel, mmap, mmap_enter);
// 	ATTACH_URETPROBE_CHECKED(skel, mmap, mmap_exit);

// 	ATTACH_UPROBE_CHECKED(skel, memalign, memalign_enter);
// 	ATTACH_URETPROBE_CHECKED(skel, memalign, memalign_exit);

// 	ATTACH_UPROBE_CHECKED(skel, free, free_enter);
// 	ATTACH_UPROBE_CHECKED(skel, munmap, munmap_enter);

// 	// the following probes are intentinally allowed to fail attachment

// 	// deprecated in libc.so bionic
// 	ATTACH_UPROBE(skel, valloc, valloc_enter);
// 	ATTACH_URETPROBE(skel, valloc, valloc_exit);

// 	// deprecated in libc.so bionic
// 	ATTACH_UPROBE(skel, pvalloc, pvalloc_enter);
// 	ATTACH_URETPROBE(skel, pvalloc, pvalloc_exit);

// 	// added in C11
// 	ATTACH_UPROBE(skel, aligned_alloc, aligned_alloc_enter);
// 	ATTACH_URETPROBE(skel, aligned_alloc, aligned_alloc_exit);

// 	return 0;
// }
// // Functions to process different BPF programs
static int process_paf(struct paf_bpf *skel_paf)
{
	int err;
	struct ring_buffer *rb;

	LOAD_AND_ATTACH_SKELETON(skel_paf, paf);

	printf("%-8s %-8s  %-8s %-8s %-8s\n", "MIN", "LOW", "HIGH", "PRESENT", "FLAG");

	POLL_RING_BUFFER(rb, 1000, err);

paf_cleanup:
	ring_buffer__free(rb);
	paf_bpf__destroy(skel_paf);
	return err;
}

static int process_pr(struct pr_bpf *skel_pr)
{
	int err;
	struct ring_buffer *rb;

	LOAD_AND_ATTACH_SKELETON(skel_pr, pr);

	printf("%-8s %-8s %-8s %-8s %-8s\n", "RECLAIM", "RECLAIMED", "UNQUEUE", "CONGESTED", "WRITEBACK");

	POLL_RING_BUFFER(rb, 1000, err);

pr_cleanup:
	ring_buffer__free(rb);
	pr_bpf__destroy(skel_pr);
	return err;
}

static int process_procstat(struct procstat_bpf *skel_procstat)
{
	int err;
	struct ring_buffer *rb;

	LOAD_AND_ATTACH_SKELETON(skel_procstat, procstat);

	if (env.rss)
	{
		printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "VMSIZE", "VMDATA", "VMSTK", "VMPTE", "VMSWAP");
	}
	else
	{
		printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
	}

	POLL_RING_BUFFER(rb, 1000, err);

procstat_cleanup:
	ring_buffer__free(rb);
	procstat_bpf__destroy(skel_procstat);
	return err;
}

static int process_sysstat(struct sysstat_bpf *skel_sysstat)
{
	int err;
	struct ring_buffer *rb;

	LOAD_AND_ATTACH_SKELETON(skel_sysstat, sysstat);

	if (env.part2)
	{
		printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "KRECLM", "SLAB", "SRECLM", "SUNRECL", "NFSUNSTB", "WRITEBACKTMP", "KMAP", "UNMAP", "PAGE");
	}
	else
	{
		printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "CPU", "MEM", "READ", "WRITE", "IOWAIT", "SWAP");
	}
	POLL_RING_BUFFER(rb, 1000, err);

sysstat_cleanup:
	ring_buffer__free(rb);
	sysstat_bpf__destroy(skel_sysstat);
	return err;
}

// static int process_memleak(struct memleak_bpf *skel_memleak, struct env env)
// {
// 	skel_memleak->rodata->stack_flags = env.kernel_trace ? KERN_STACKID_FLAGS : USER_STACKID_FLAGS;

// 	bpf_map__set_value_size(skel_memleak->maps.stack_traces, perf_max_stack_depth * sizeof(__u64));
// 	bpf_map__set_max_entries(skel_memleak->maps.stack_traces, stack_map_max_entries);

// 	if (!env.kernel_trace)
// 		disable_kernel_tracepoints(skel_memleak);

// 	int err = memleak_bpf__load(skel_memleak);
// 	if (err)
// 	{
// 		fprintf(stderr, "Failed to load BPF skeleton\n");
// 		goto memleak_cleanup;
// 	}

// 	if (!env.kernel_trace)
// 	{
// 		err = attach_uprobes(skel_memleak);
// 		if (err)
// 		{
// 			fprintf(stderr, "Failed to attach uprobes\n");
// 			goto memleak_cleanup;
// 		}
// 	}

// 	err = memleak_bpf__attach(skel_memleak);
// 	if (err)
// 	{
// 		fprintf(stderr, "Failed to auto-attach BPF skeleton: %d\n", err);
// 		goto memleak_cleanup;
// 	}

// 	g_stacks_size = perf_max_stack_depth * sizeof(*g_stacks);
// 	g_stacks = (__u64 *)malloc(g_stacks_size);
// 	if (!g_stacks)
// 	{
// 		fprintf(stderr, "Failed to allocate memory\n");
// 		err = -1;
// 		goto memleak_cleanup;
// 	}
// 	memset(g_stacks, 0, g_stacks_size);

// 	symbolizer = blaze_symbolizer_new();
// 	if (!symbolizer)
// 	{
// 		fprintf(stderr, "Fail to create a symbolizer\n");
// 		err = -1;
// 		goto memleak_cleanup;
// 	}

// 	for (;;)
// 	{
// 		if (!env.kernel_trace)
// 			if (env.print_time)
// 			{
// 				system("clear");
// 				update_addr_times(skel_memleak);
// 				print_time(skel_memleak);
// 			}
// 			else
// 				print_outstanding_combined_allocs(skel_memleak, attach_pid);
// 		else
// 			print_outstanding_allocs(skel_memleak);

// 		sleep(1);
// 	}

// 	while (!exiting)
// 	{
// 		/* Ctrl-C will cause -EINTR */
// 		if (err == -EINTR)
// 		{
// 			err = 0;
// 			break;
// 		}
// 		if (err < 0)
// 		{
// 			printf("Error polling perf buffer: %d\n", err);
// 			break;
// 		}
// 	}

// memleak_cleanup:
// 	memleak_bpf__destroy(skel_memleak);
// 	if (symbolizer)
// 		blaze_symbolizer_free(symbolizer);
// 	if (g_stacks)
// 		free(g_stacks);
// 	if (allocs)
// 		free(allocs);
// 	return err;
// }

static int process_oomkiller(struct oomkiller_bpf *skel_oomkiller)
{
	int err;
	struct ring_buffer *rb;

	// 使用指定 map_name 的宏
	LOAD_AND_ATTACH_SKELETON_WITH_MAP(skel_oomkiller, oomkiller, events);

	printf("Waiting for OOM events...\n");

	POLL_RING_BUFFER(rb, 1000, err);

oomkiller_cleanup:
	ring_buffer__free(rb);
	oomkiller_bpf__destroy(skel_oomkiller);
	return err;
}


// ================================================== fraginfo====================================================================
// compute order
static int __fragmentation_index(unsigned int order, long unsigned int total, long unsigned int suitable, long unsigned int free)
{
	unsigned long requested = 1UL << order;
	// 无可用内存返回0
	if (order > MAX_ORDER)
		return 0;
	if (!total)
		return 0;
	// 有可用内存返回-1000
	if (suitable)
		return -1000;
	double res1, res2;
	res1 = (double)(free * 1000ULL) / requested;
	// res1 +=1000;
	res2 = (double)res1 / total;
	return res2;
}
static int unusable_free_index(unsigned int order, long unsigned int total, long unsigned int suitable, long unsigned int free)
{
	/* No free memory is interpreted as all free memory is unusable */
	if (free == 0)
		return 1000;

	/*
	 * Index should be a value between 0 and 1. Return a value to 3
	 * decimal places.
	 *
	 * 0 => no fragmentation
	 * 1 => high fragmentation
	 */
	long unsigned int res1 = free - (suitable << order);
	double res = (res1 * 1000ULL) / free;
	return res;
}
void print_zones(int fd)
{
	struct zone_info zinfo;
	__u64 key = 0, next_key;
	printf("%-15s %-30s %-23s %-23s %-20s %-20s", "NODE_ID","ZONE_COMM", "ZONE_PTR", "ZONE_PFN ", " SUM_PAGES", "FACT_PAGES ");
	printf("\n");
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
	{
		bpf_map_lookup_elem(fd, &next_key, &zinfo);
		printf(" %-15d %-25s 0x%-25llx %-25llu %-20llu %-15llu\n",zinfo.node_id, zinfo.comm, zinfo.zone_ptr, zinfo.zone_start_pfn, zinfo.spanned_pages, zinfo.present_pages);
		key = next_key;
	}
}
void print_nodes(int fd)
{
	struct pgdat_info pinfo;
	__u64 key = 0, next_key;
	printf("%-25s %-30s %-23s", "NODE_ID","PGDAT_PTR", "NR_ZONES");
	printf("\n");
	while (bpf_map_get_next_key(fd, &key, &next_key) == 0)
	{
		bpf_map_lookup_elem(fd, &next_key, &pinfo);
		printf(" %-15d       0x%-33llx  %-25d\n",
			   pinfo.node_id, pinfo.pgdat_ptr, pinfo.nr_zones);
		key = next_key;
	}
}
void print_orders(int fd)
{
	struct order_zone okey = {};
	struct ctg_info oinfo;
	struct order_entry entries[256];
	int entry_count = 0;

	while (bpf_map_get_next_key(fd, &okey, &okey) == 0)
	{
		if (bpf_map_lookup_elem(fd, &okey, &oinfo) == 0)
		{
			entries[entry_count].okey = okey;
			entries[entry_count].oinfo = oinfo;
			entry_count++;
		}
	}

	// 排序
	qsort(entries, entry_count, sizeof(struct order_entry), compare_entries);

	// 打印排序后的
	printf("%-13s %-32s %-20s %-21s %-20s %-24s %-15s %-20s", "NODE_ID"," Order", "ZONE_PTR", "Free Pages  ", "Free Blocks Total", "Free Blocks Suitable","SCOREA","SCOREB");
	printf("\n");
	for (int i = 0; i < entry_count; i++)
	{
		int res = __fragmentation_index(entries[i].okey.order, entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable, entries[i].oinfo.free_pages);
		int tmp = unusable_free_index(entries[i].okey.order, entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable, entries[i].oinfo.free_pages);
	
		int part2 = tmp / 1000;
		int dec2 = tmp % 1000;
		printf(" %-15d %-25u 0x%-25llx %-25lu %-20lu %-15lu  %-15d   %d.%03d\n",entries[i].okey.node_id,
			   entries[i].okey.order, entries[i].okey.zone_ptr, entries[i].oinfo.free_pages,
			   entries[i].oinfo.free_blocks_total, entries[i].oinfo.free_blocks_suitable, res, part2, dec2);
	}
}

static int process_fraginfo(struct fraginfo_bpf *skel_fraginfo)
{

	int err = fraginfo_bpf__load(skel_fraginfo);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto fraginfo_cleanup;
	}

	err = fraginfo_bpf__attach(skel_fraginfo);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto fraginfo_cleanup;
	}
	while (1)
	{
		sleep(env.interval);
		if(env.zones){
			print_zones(bpf_map__fd(skel_fraginfo->maps.zones));
			printf("\n");
			break;
		}else if(env.nodes){
			print_nodes(bpf_map__fd(skel_fraginfo->maps.nodes));
			printf("\n");
			break;
		}else{
			print_orders(bpf_map__fd(skel_fraginfo->maps.orders));
		printf("\n");
		break;
		}
		
		// print_zones(bpf_map__fd(skel_fraginfo->maps.zones));
		// printf("\n");
		// print_orders(bpf_map__fd(skel_fraginfo->maps.orders));
		// printf("\n");
	}

fraginfo_cleanup:
	fraginfo_bpf__destroy(skel_fraginfo);
	return -err;
}


// ================================================== vmasnap ====================================================================
static void print_find_event_data(int map_fd)
{
	__aligned_u64 key = 0;
	__aligned_u64 next_key;
	struct find_event_t event;

	printf("Reading find events...\n");

	// Print header
	printf("%-10s %-20s %-15s %-20s %-20s %-20s %-20s\n",
		   "PID", "Address", "Duration", "VMACache Hit", "RB Subtree Last", "VM Start", "VM End");

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
	{
		if (bpf_map_lookup_elem(map_fd, &next_key, &event) == 0)
		{
			printf("%-10llu %-20lu %-15llu %-20d %-20llu %-20llu %-20llu\n",
				   next_key, event.addr, event.duration, event.vmacache_hit,
				   event.rb_subtree_last, event.vm_start, event.vm_end);

			// Delete the element from the map after printing
			if (bpf_map_delete_elem(map_fd, &next_key) != 0)
			{
				perror("Failed to delete element from map");
			}
		}

		// Use a temporary variable to handle key update
		__aligned_u64 temp_key = next_key;
		key = temp_key;
	}
}

static void print_insert_event_data(int map_fd)
{
	__aligned_u64 key = 0;
	__aligned_u64 next_key;
	struct insert_event_t event;

	printf("Reading insert events...\n");

	// Print header
	printf("%-10s %-15s %-15s %-20s %-20s %-20s %-20s %-20s\n",
		   "PID", "Duration", "List", "RB", "Interval Tree", "List Time", "RB Time", "Interval Tree Time");

	while (bpf_map_get_next_key(map_fd, &key, &next_key) == 0)
	{
		if (bpf_map_lookup_elem(map_fd, &next_key, &event) == 0)
		{
			printf("%-10llu %-15llu %-15d %-20d %-20d %-20llu %-20llu %-20llu\n",
				   next_key, event.duration, event.inserted_to_list, event.inserted_to_rb,
				   event.inserted_to_interval_tree, event.link_list_duration,
				   event.link_rb_duration, event.interval_tree_duration);

			// Delete the element from the map after printing
			if (bpf_map_delete_elem(map_fd, &next_key) != 0)
			{
				perror("Failed to delete element from map");
			}
		}

		// Use a temporary variable to handle key update
		__aligned_u64 temp_key = next_key;
		key = temp_key;
	}
}

static int process_vmasnap(struct vmasnap_bpf *skel_vmasnap)
{
	int err;

	// Load and verify BPF application
	skel_vmasnap = vmasnap_bpf__open();
	if (!skel_vmasnap)
	{
		fprintf(stderr, "Failed to open BPF skeleton\n");
		return 1;
	}

	// Load & verify BPF programs
	err = vmasnap_bpf__load(skel_vmasnap);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto vmasnap_cleanup;
	}

	// Attach tracepoints
	err = vmasnap_bpf__attach(skel_vmasnap);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto vmasnap_cleanup;
	}

	printf("Successfully started! Press Ctrl-C to exit.\n");

	// Get the file descriptors for the maps
	int find_map_fd = bpf_map__fd(skel_vmasnap->maps.find_events);
	int insert_map_fd = bpf_map__fd(skel_vmasnap->maps.insert_events);

	if (find_map_fd < 0 || insert_map_fd < 0)
	{
		fprintf(stderr, "Failed to get file descriptor for maps\n");
		goto vmasnap_cleanup;
	}

	// Main loop
	while (!exiting)
	{
		// Print events data every second
		print_find_event_data(find_map_fd);
		print_insert_event_data(insert_map_fd);
		sleep(1);
	}

vmasnap_cleanup:
    vmasnap_bpf__destroy(skel_vmasnap);
    return 0;
}

static int process_drsnoop(struct drsnoop_bpf *skel_drsnoop) {
	int err;
	struct ring_buffer *rb;

	__u64 vm_stat_addr;
    __u32 key = 0;  // Key for the vm_stat_map

	if (get_vm_stat_addr(&vm_stat_addr) != 0) {
        fprintf(stderr, "Failed to get vm_stat or vm_zone_stat address\n");
        return 1;
    }

	err = drsnoop_bpf__load(skel_drsnoop);
    if (err) {
        fprintf(stderr, "Failed to load and verify BPF skeleton\n");
        return 1;
    }

    // Update BPF map with the address of vm_stat
    err = bpf_map_update_elem(bpf_map__fd(skel_drsnoop->maps.vm_stat_map), &key, &vm_stat_addr, BPF_ANY);
    if (err) {
        fprintf(stderr, "Failed to update BPF map: %s\n", strerror(errno));
        goto drsnoop_cleanup;
    }

    err = drsnoop_bpf__attach(skel_drsnoop);
    if (err) {
        fprintf(stderr, "Failed to attach BPF skeleton\n");
        goto drsnoop_cleanup;
    }

	rb = ring_buffer__new(bpf_map__fd(skel_drsnoop->maps.rb), handle_event_drsnoop, NULL, NULL);
	if (!rb) {
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto drsnoop_cleanup;
	}

	printf("%-8s %-16s %-7s %-9s %-7s\n", "TIME", "COMM", "PID", "FREE(KB)", "LAT(ms)");

	POLL_RING_BUFFER(rb, 1000, err);\

drsnoop_cleanup:
    /* 清理 */
    ring_buffer__free(rb);
    drsnoop_bpf__destroy(skel_drsnoop);

    return err < 0 ? -err : 0;
}
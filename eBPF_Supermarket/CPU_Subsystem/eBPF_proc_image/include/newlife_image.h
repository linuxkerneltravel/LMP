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
// author: zhangziheng0525@163.com
//
// Variable definitions and help functions for newlife in the process

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "proc_image.h"

struct bind_pid{
    int pid;
    int newlife_pid;
};

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, struct bind_pid);
	__type(value, struct event);
} newlife SEC(".maps");

// 记录开始时间，并输出
static int newlife_create(void *ctx, int type, pid_t newlife_pid, pid_t target_pid, void *events)
{
	struct bind_pid bind_pid = {};
    struct event *event;

	bind_pid.pid = target_pid;
	bind_pid.newlife_pid = newlife_pid;
	
    if (bpf_map_update_elem(&newlife, &bind_pid, &empty_event, BPF_NOEXIST))
            return 0;

    event = bpf_map_lookup_elem(&newlife, &bind_pid);
    if (!event)
        return 0;

	event->type = type;
    event->pid = newlife_pid;
    event->ppid = target_pid;
    event->cpu_id = bpf_get_smp_processor_id();
//  bpf_get_current_comm(&event->comm, sizeof(event->comm));
    event->start = bpf_ktime_get_ns();

    output_event(ctx,event,events);

    return 0;
}

// 记录退出时间，并输出
static int newlife_exit(void *ctx, pid_t target_pid, void *events)
{
	struct bind_pid bind_pid = {};
	struct event *event;

	bind_pid.pid = target_pid;
	bind_pid.newlife_pid = bpf_get_current_pid_tgid();

	event = bpf_map_lookup_elem(&newlife, &bind_pid);
	if(!event)
        return 0;
	
    event->type ++;
    event->exit = bpf_ktime_get_ns();

    output_event(ctx,event,events);

    bpf_map_delete_elem(&newlife, &bind_pid);

	return 0;
}

// SPDX-License-Identifier: GPL-2.0 OR BSD-3-Clause
/* Copyright (c) 2021 Sartura */
#include "vmlinux_arm.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct whole_alloc_info {
	u64 size;
        u64 number_allocs;
	};

struct alloc_info {
	u64 single_size;
	u64 times;
	u64 stack_id;
};

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256 * 1024);
        __type(key, u64);
        __type(value, struct alloc_info);
} allocs SEC(".maps");

struct {
        __uint(type, BPF_MAP_TYPE_HASH);
        __uint(max_entries, 256 * 1024);
        __type(key, u64);
        __type(value, struct whole_alloc_info);
} whole_allocs SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_STACK_TRACE);
	__uint(max_entries, 256 * 1024);
	__uint(key_size, sizeof(u32));
	__uint(value_size, 127 * sizeof(u64));
}stack_traces SEC(".maps");

SEC("tracepoint/kmem/kmalloc")
int tracepoint__kmem__kmalloc(struct trace_event_raw_kmem_alloc* ctx)	
{
	u64 ip[20];
	u64 i, stack_size, stack;
	struct whole_alloc_info *pre_info, info={0};
	struct alloc_info ai={0};

	u64 addr = (u64)ctx->ptr;
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	u64 ts = bpf_ktime_get_ns();

	u64 size = (u64)ctx->bytes_alloc;
	if(size == 0)
		return 0;

	ai.single_size = size;

	if(addr != 0) {
		ai.times = bpf_ktime_get_ns();

//		ai.stack_id = bpf_get_stackid(ctx, &stack_traces, 0);

		ai.stack_id = bpf_get_stackid(ctx, &stack_traces, BPF_F_USER_STACK);
		bpf_map_update_elem(&allocs, &addr, &ai, BPF_ANY);

		pre_info = bpf_map_lookup_elem(&whole_allocs, &(ai.stack_id));
		if(pre_info != 0)
			info = *pre_info;

		info.size += ai.single_size;
		info.number_allocs += 1;
		bpf_map_update_elem(&whole_allocs, &(ai.stack_id), &info, BPF_ANY);
	
	}

	bpf_printk("========================kmalloc==========================");

	stack_size = bpf_get_stack(ctx, ip, sizeof(ip), 0);
	if(stack_size < 0)
		return 0;

	stack = stack_size / sizeof(ip[0]);
	for(i = 1; i < (20 & stack); i++) 
		bpf_printk("tack = %x, stack_size = %d, addr = %lx\n", ai.stack_id, stack_size, ip[i]);

	bpf_printk("pid = %d, size = %ld, addr = %p\n", pid, size, addr);
	
	return 0;
}

SEC("tracepoint/kmem/kfree")
int tracepoint__kmem__kfree(struct trace_event_raw_kfree* ctx)
{
	u64 ip[20];
	u64 i, stack_size, stack;
	pid_t pid;
	struct alloc_info *ai_info, ai = {0};
	struct whole_alloc_info *pre_info, info={0};

	u64 addr =(u64)ctx->ptr;
	pid = bpf_get_current_pid_tgid() >> 32;

	ai_info = bpf_map_lookup_elem(&allocs, &addr);
	if(ai_info == 0)
		return 0;

	ai = *ai_info;
	bpf_map_delete_elem(&allocs, &addr);

	pre_info = bpf_map_lookup_elem(&whole_allocs, &(ai.stack_id));
	if(pre_info != 0)
		info = *pre_info;

	if(ai.single_size > info.size)
		info.size = 0;
	else
		info.size -=ai.single_size;

	if(info.number_allocs > 0)
		info.number_allocs -= 1;

	bpf_map_update_elem(&whole_allocs, &(ai.stack_id), &info, BPF_ANY);

	stack_size = bpf_get_stack(ctx, ip, sizeof(ip), 0);
	if(stack_size < 0)
		return 0;

	bpf_printk("========================kfree==========================");

	stack = stack_size / sizeof(ip[0]);
	for(i = 1; i < (20 & stack); i++) 
		bpf_printk("tack = %x, stack_size = %d, addr = %lx\n", ai.stack_id, stack_size, ip[i]);	

	bpf_printk("fexit: pid = %d, addr = %p", pid, addr);
	bpf_printk("size = %ld, sizes = %ld\n", ai.single_size, info.size);

	return 0;
}

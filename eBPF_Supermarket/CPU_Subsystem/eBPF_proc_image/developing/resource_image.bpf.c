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
// eBPF kernel-mode code that collects process resource usage

#include <vmlinux.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "include/proc_image.h"

const volatile pid_t target_pid = -1;
const volatile int target_cpu_id = -1;

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 7000);
	__type(key, struct proc_id);
	__type(value, struct start_rsc);
} start SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 7000);
	__type(key, struct proc_id);
	__type(value, struct total_rsc);
} total SEC(".maps");

SEC("kprobe/finish_task_switch.isra.0")
int kprobe__finish_task_switch(struct pt_regs *ctx)
{
	struct task_struct *prev = (struct task_struct *)PT_REGS_PARM1(ctx);
	pid_t prev_pid = BPF_CORE_READ(prev,pid);
	int prev_cpu = bpf_get_smp_processor_id();
	struct task_struct *next = (struct task_struct *)bpf_get_current_task();
	pid_t next_pid = BPF_CORE_READ(next,pid);
	int next_cpu = prev_cpu;
	
	if(target_pid==-1 || (target_pid!=0 && prev_pid==target_pid) || 
	   (target_pid==0 && prev_pid==target_pid && prev_cpu==target_cpu_id)){
		struct proc_id prev_pd = {0};
		prev_pd.pid = prev_pid;
		prev_pd.cpu_id = prev_cpu;
		
		if(bpf_map_lookup_elem(&start,&prev_pd) != NULL){
			struct start_rsc *prev_start = bpf_map_lookup_elem(&start,&prev_pd);
			if (prev_start == NULL) {
				return 0; 
			}
			
			if(bpf_map_lookup_elem(&total,&prev_pd) == NULL){
				struct total_rsc prev_total = {0};
				struct mm_rss_stat rss = {};
				long long *c;
				long unsigned int memused;
				
				rss = BPF_CORE_READ(prev, mm, rss_stat);
				c = (long long *)(rss.count);
				memused = *c + *(c + 1) + *(c + 3);
				
				prev_total.pid = prev_pd.pid;
				prev_total.time = bpf_ktime_get_ns() - prev_start->time;
				prev_total.memused = memused;
				prev_total.readchar = BPF_CORE_READ(prev,ioac.rchar) - prev_start->readchar;
				prev_total.writechar = BPF_CORE_READ(prev,ioac.wchar) - prev_start->writechar;
				
				bpf_map_update_elem(&total,&prev_pd, &prev_total, BPF_ANY);
			}else{
				struct total_rsc *prev_total = bpf_map_lookup_elem(&total,&prev_pd);
				if (prev_total == NULL) {
					return 0; 
				}
				
				struct mm_rss_stat rss = {};
				long long *c;
				long unsigned int memused;
				
				rss = BPF_CORE_READ(prev, mm, rss_stat);
				c = (long long *)(rss.count);
				memused = *c + *(c + 1) + *(c + 3);
				
				//prev_total->pid = prev_pd.pid;
				prev_total->time += bpf_ktime_get_ns() - prev_start->time;
				prev_total->memused = memused;
				prev_total->readchar += BPF_CORE_READ(prev,ioac.rchar) - prev_start->readchar;
				prev_total->writechar += BPF_CORE_READ(prev,ioac.wchar) - prev_start->writechar;
				
				bpf_map_update_elem(&total,&prev_pd, &(*prev_total), BPF_ANY);
			}
		}
	}

	if(target_pid==-1 || (target_pid!=0 && next_pid==target_pid) || 
	   (target_pid==0 && next_pid==target_pid && next_cpu==target_cpu_id)){
		struct proc_id next_pd = {0};
		struct start_rsc next_start={0};

		next_pd.pid = next_pid;
		next_pd.cpu_id = next_cpu;
		
		next_start.time = bpf_ktime_get_ns();
		next_start.readchar = BPF_CORE_READ(next,ioac.rchar);
		next_start.writechar = BPF_CORE_READ(next,ioac.wchar);
		
		bpf_map_update_elem(&start,&next_pd, &next_start, BPF_ANY);
	}

	return 0;
}
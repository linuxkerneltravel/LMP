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
// author: yys2020haha@163.com
//
// Kernel space BPF program used for counting container sys_entry/sys_exit info.

#ifndef __CONTAINER_H
#define __CONTAINER_H

#include "common.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#define MAX_NODENAME_LEN 13
struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
}time_info SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value, u64);
}id SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, pid_t);
    __type(value,struct container_id);   
}container_id_map SEC(".maps");

struct {
    __uint(type,BPF_MAP_TYPE_HASH);
    __uint(max_entries, 80);
    __type(key, pid_t);
    __type(value,struct syscall_value); //记录容器ID、进程名、系统调用号、每个调用号的次数、单位时间内的总延迟   
}proc_syscall_info SEC(".maps");

static int trace_container_sys_entry(struct trace_event_raw_sys_enter *args){
    u64 st = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    u64 syscall_id = (u64)args->id; 
    bpf_map_update_elem(&time_info,&pid,&st,BPF_ANY);
    bpf_map_update_elem(&id,&pid,&syscall_id,BPF_ANY);
    return 0;
}
static int trace_container_sys_exit(struct trace_event_raw_sys_exit *args,void *rb,struct common_event *e){
    u64 exit_time = bpf_ktime_get_ns();
    pid_t pid = bpf_get_current_pid_tgid();
    u64 delay,start_time,syscallid;
    u64 *st = bpf_map_lookup_elem(&time_info,&pid);
    if( st !=0){
        start_time = *st;
	 	delay = (exit_time - start_time)/1000;
	 	bpf_map_delete_elem(&time_info, &pid);
	}else{ 
		return 0;
	}
    u64 *sc_id = bpf_map_lookup_elem(&id,&pid);
    if( sc_id != 0){
        syscallid = *sc_id;
		bpf_map_delete_elem(&id, &pid);
	}else{ 
	    return 0;
	}
    const void *contain_id = bpf_map_lookup_elem(&container_id_map,&pid);
    if(contain_id == NULL){
        return 0;
    }
    //用指针去获取用户定义好的结构体，不然结构体过大会导致栈溢出
    struct syscall_value *syscall_value = bpf_map_lookup_elem(&proc_syscall_info, &pid);
    if (!syscall_value) {
        return 0;
    }

    // 读取 container_id
    int ret = bpf_probe_read_kernel_str(syscall_value->container_id, sizeof(syscall_value->container_id), contain_id);
    if (ret < 0) {
        bpf_printk("Failed to read container_id from kernel space, error code: %d\n", ret);
        return 0;
    }

    // 打印读取的 container_id
    bpf_printk("container_id: %s\n", syscall_value->container_id);

    // 获取进程名并存储
    ret = bpf_get_current_comm(syscall_value->proc_name, sizeof(syscall_value->proc_name));
    if (ret < 0) {
        bpf_printk("Failed to read process name, error code: %d\n", ret);
        return 0;
    }
    //检查 syscallid 是否超出范围
    if (syscallid >= MAX_SYSCALL_NUM || syscallid < 0) {
        return 0;  // 如果超出范围，直接返回
    }
    syscall_value->syscall_total_delay[syscallid] += delay;  // 加上 delay 的值
    syscall_value->syscall_id_counts[syscallid] += 1;  // 计数加 1 
    return 0;
}

struct data_t {
    char nodename[MAX_NODENAME_LEN];
};
#endif /* __CONTAINER_H */

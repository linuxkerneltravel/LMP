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
// author: nanshuaibo811@163.com
//
// Kernel space BPF program used for monitoring data for KVM event.

#include "../include/vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>
#include "../include/kvm_watcher.h"
#include "../include/kvm_vcpu.h"
#include "../include/kvm_exits.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t vm_pid = -1;
const volatile bool execute_vcpu_wakeup=false;
const volatile bool execute_exit=false;
const volatile bool execute_halt_poll_ns=false;

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("tp/kvm/kvm_vcpu_wakeup")
int tp_vcpu_wakeup(struct vcpu_wakeup *ctx)
{   
    if(execute_vcpu_wakeup){
        trace_kvm_vcpu_wakeup(ctx,&rb,vm_pid);
    }
    return 0;
}

SEC("tp/kvm/kvm_halt_poll_ns")
int tp_kvm_halt_poll_ns(struct halt_poll_ns *ctx)
{   
    if(execute_halt_poll_ns){
        trace_kvm_halt_poll_ns(ctx,&rb,vm_pid);
    }
    return 0;
}

SEC("tp/kvm/kvm_exit")
int tp_exit(struct exit *ctx)
{   
    if(execute_exit){
        trace_kvm_exit(ctx,vm_pid);
    }
    return 0;
}

SEC("tp/kvm/kvm_entry")
int tp_entry(struct exit *ctx)
{   
    if(execute_exit){
        trace_kvm_entry(&rb);
    }
    return 0;
}

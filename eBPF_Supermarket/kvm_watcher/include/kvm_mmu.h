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
// Kernel space BPF program used for monitoring data for KVM MMU.

#ifndef __KVM_MMU_H
#define __KVM_MMU_H

#include "kvm_watcher.h"
#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u64);
} pf_delay SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 8192);
    __type(key, u64);
    __type(value, u32);
} pf_count SEC(".maps");

struct page_fault {
    struct trace_entry ent;
    unsigned int vcpu_id;
    long unsigned int guest_rip;
    u64 fault_address;
    u64 error_code;
    char __data[0];
};

static int trace_page_fault(struct page_fault *ctx, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    u64 ts = bpf_ktime_get_ns();
    u64 addr = ctx->fault_address;
    bpf_map_update_elem(&pf_delay, &addr, &ts, BPF_ANY);
    return 0;
}

static int trace_direct_page_fault(struct kvm_vcpu *vcpu,
                                   struct kvm_page_fault *fault, void *rb,
                                   struct common_event *e) {
    u64 addr;
    bpf_probe_read_kernel(&addr, sizeof(u64), &fault->addr);
    u64 *ts;
    ts = bpf_map_lookup_elem(&pf_delay, &addr);
    if (!ts) {
        return 0;
    }
    u32 *count;
    u32 new_count = 1;
    u32 error_code;
    u64 hva, pfn;
    bpf_probe_read_kernel(&error_code, sizeof(u32), &fault->error_code);
    bpf_probe_read_kernel(&hva, sizeof(u64), &fault->hva);
    bpf_probe_read_kernel(&pfn, sizeof(u64), &fault->pfn);
    short memslot_id = BPF_CORE_READ(fault, slot, id);
    u64 delay = bpf_ktime_get_ns() - *ts;
    bpf_map_delete_elem(&pf_delay, &addr);
    RESERVE_RINGBUF_ENTRY(rb, e);
    count = bpf_map_lookup_elem(&pf_count, &addr);
    if (count) {
        (*count)++;
        e->page_fault_data.count = *count;
        bpf_map_update_elem(&pf_count, &addr, count, BPF_ANY);
    } else {
        e->page_fault_data.count = 1;
        bpf_map_update_elem(&pf_count, &addr, &new_count, BPF_ANY);
    }
    e->page_fault_data.delay = delay;
    e->page_fault_data.addr = addr;
    e->page_fault_data.error_code = error_code;
    e->page_fault_data.hva = hva;
    e->page_fault_data.pfn = pfn;
    e->page_fault_data.memslot_id = memslot_id;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    e->time = *ts;
    bpf_ringbuf_submit(e, 0);
    return 0;
}

static int trace_kvm_mmu_page_fault(struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
                                    u64 error_code, pid_t vm_pid) {
    CHECK_PID(vm_pid);
    if (error_code & PFERR_RSVD_MASK) {
        u64 ts = bpf_ktime_get_ns();
        u64 addr = cr2_or_gpa;
        bpf_map_update_elem(&pf_delay, &addr, &ts, BPF_ANY);
    }
    return 0;
}

static int trace_handle_mmio_page_fault(struct kvm_vcpu *vcpu, u64 addr,
                                        bool direct, void *rb,
                                        struct common_event *e) {
    u64 *ts;
    ts = bpf_map_lookup_elem(&pf_delay, &addr);
    if (!ts) {
        return 0;
    }
    u32 *count;
    u32 new_count = 1;
    u64 delay = bpf_ktime_get_ns() - *ts;
    bpf_map_delete_elem(&pf_delay, &addr);
    RESERVE_RINGBUF_ENTRY(rb, e);
    count = bpf_map_lookup_elem(&pf_count, &addr);
    if (count) {
        (*count)++;
        e->page_fault_data.count = *count;
        bpf_map_update_elem(&pf_count, &addr, count, BPF_ANY);
    } else {
        e->page_fault_data.count = 1;
        bpf_map_update_elem(&pf_count, &addr, &new_count, BPF_ANY);
    }
    e->page_fault_data.delay = delay;
    e->page_fault_data.addr = addr;
    e->page_fault_data.error_code = PFERR_RSVD_MASK;
    e->process.pid = bpf_get_current_pid_tgid() >> 32;
    bpf_get_current_comm(&e->process.comm, sizeof(e->process.comm));
    e->time = *ts;
    bpf_ringbuf_submit(e, 0);
    return 0;
}
#endif /* __KVM_MMU_H */
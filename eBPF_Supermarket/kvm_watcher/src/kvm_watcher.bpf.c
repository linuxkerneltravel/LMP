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

#include "vmlinux.h"
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include "common.h"
#include "kvm_exits.h"
#include "kvm_ioctl.h"
#include "kvm_vcpu.h"
#include "kvm_mmu.h"
#include "kvm_irq.h"
#include "kvm_hypercall.h"
#include "container.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

const volatile pid_t vm_pid = -1;
const volatile char hostname[13] = "";
static struct common_event *e;

// 定义环形缓冲区maps
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} rb SEC(".maps");

// 获取vcpu的id
SEC("fentry/kvm_vcpu_halt")
int BPF_PROG(fentry_kvm_vcpu_halt, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return trace_kvm_vcpu_halt(vcpu);
}

SEC("kprobe/kvm_vcpu_halt")
int BPF_KPROBE(kp_kvm_vcpu_halt, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return trace_kvm_vcpu_halt(vcpu);
}

// 追踪vcpu运行信息
SEC("tp/kvm/kvm_vcpu_wakeup")
int tp_vcpu_wakeup(struct vcpu_wakeup *ctx) {
    return trace_kvm_vcpu_wakeup(ctx, &rb, e);
}
// 记录vcpu的halt_poll（暂停轮询）时间变化
SEC("tp/kvm/kvm_halt_poll_ns")
int tp_kvm_halt_poll_ns(struct halt_poll_ns *ctx) {
    CHECK_PID(vm_pid);
    return trace_kvm_halt_poll_ns(ctx, &rb, e);
}
// 记录vm_exit的时间
SEC("tp/kvm/kvm_exit")
int tp_exit(struct exit *ctx) {
    CHECK_PID(vm_pid);
    return trace_kvm_exit(ctx);
}
// 记录vm_entry和vm_exit的时间差
SEC("tp/kvm/kvm_entry")
int tp_entry(struct exit *ctx) {
    return trace_kvm_entry();
}

// 记录VCPU调度的信息--进入
SEC("fentry/vmx_vcpu_load")
int BPF_PROG(fentry_vmx_vcpu_load, struct kvm_vcpu *vcpu, int cpu) {
    CHECK_PID(vm_pid);
    return trace_vmx_vcpu_load(vcpu, cpu);
}

SEC("kprobe/vmx_vcpu_load")
int BPF_KPROBE(kp_vmx_vcpu_load, struct kvm_vcpu *vcpu, int cpu) {
    CHECK_PID(vm_pid);
    return trace_vmx_vcpu_load(vcpu, cpu);
}

// 记录VCPU调度的信息--退出
SEC("fentry/vmx_vcpu_put")
int BPF_PROG(fentry_vmx_vcpu_put) {
    return trace_vmx_vcpu_put();
}

SEC("kprobe/vmx_vcpu_put")
int BPF_KPROBE(kp_vmx_vcpu_put) {
    return trace_vmx_vcpu_put();
}

SEC("fentry/mark_page_dirty_in_slot")
int BPF_PROG(fentry_mark_page_dirty_in_slot, struct kvm *kvm,
             const struct kvm_memory_slot *memslot, gfn_t gfn) {
    CHECK_PID(vm_pid);
    return trace_mark_page_dirty_in_slot(kvm, memslot, gfn, &rb, e);
}

SEC("kprobe/mark_page_dirty_in_slot")
int BPF_KPROBE(kp_mark_page_dirty_in_slot, struct kvm *kvm,
               const struct kvm_memory_slot *memslot, gfn_t gfn) {
    CHECK_PID(vm_pid);
    return trace_mark_page_dirty_in_slot(kvm, memslot, gfn, &rb, e);
}

SEC("tp/kvm/kvm_page_fault")
int tp_page_fault(struct page_fault *ctx) {
    CHECK_PID(vm_pid);
    return trace_page_fault(ctx);
}

SEC("fexit/kvm_tdp_page_fault")
int BPF_PROG(fexit_tdp_page_fault, struct kvm_vcpu *vcpu,
             struct kvm_page_fault *fault) {
    return trace_tdp_page_fault(vcpu, fault, &rb, e);
}

SEC("fentry/kvm_mmu_page_fault")
int BPF_PROG(fentry_kvm_mmu_page_fault, struct kvm_vcpu *vcpu, gpa_t cr2_or_gpa,
             u64 error_code) {
    CHECK_PID(vm_pid);
    return trace_kvm_mmu_page_fault(vcpu, cr2_or_gpa, error_code);
}

SEC("tp/kvmmmu/handle_mmio_page_fault")
int tp_handle_mmio_page_fault(struct mmio_page_fault *ctx) {
    return trace_handle_mmio_page_fault(ctx, &rb, e);
}

SEC("fentry/kvm_pic_set_irq")
int BPF_PROG(fentry_kvm_pic_set_irq, struct kvm_pic *s, int irq,
             int irq_source_id, int level) {
    CHECK_PID(vm_pid);
    return entry_kvm_pic_set_irq(irq);
}

SEC("fexit/kvm_pic_set_irq")
int BPF_PROG(fexit_kvm_pic_set_irq, struct kvm_pic *s, int irq,
             int irq_source_id, int level, int ret) {
    return exit_kvm_pic_set_irq(s, irq, ret, &rb, e);
}

SEC("fentry/ioapic_set_irq")
int BPF_PROG(fentry_kvm_ioapic_set_irq, struct kvm_ioapic *ioapic, int irq,
             int irq_level, bool line_status) {
    CHECK_PID(vm_pid);
    return entry_kvm_ioapic_set_irq(irq);
}

SEC("fexit/ioapic_set_irq")
int BPF_PROG(fexit_kvm_ioapic_set_irq, struct kvm_ioapic *ioapic, int irq,
             int irq_level, bool line_status, int ret) {
    return exit_kvm_ioapic_set_irq(ioapic, irq, ret, &rb, e);
}

SEC("fentry/kvm_set_msi")
int BPF_PROG(fentry_kvm_set_msi,
             struct kvm_kernel_irq_routing_entry *routing_entry,
             struct kvm *kvm, int irq_source_id, int level, bool line_status) {
    CHECK_PID(vm_pid);
    return entry_kvm_set_msi(kvm, routing_entry, level);
}

SEC("fexit/kvm_set_msi")
int BPF_PROG(fexit_kvm_set_msi,
             struct kvm_kernel_irq_routing_entry *routing_entry,
             struct kvm *kvm, int irq_source_id, int level, bool line_status) {
    return exit_kvm_set_msi(kvm, routing_entry, &rb, e);
}

SEC("fentry/vmx_inject_irq")
int BPF_PROG(fentry_vmx_inject_irq, struct kvm_vcpu *vcpu, bool reinjected) {
    CHECK_PID(vm_pid);
    return entry_vmx_inject_irq(vcpu);
}

SEC("fexit/vmx_inject_irq")
int BPF_PROG(fexit_vmx_inject_irq, struct kvm_vcpu *vcpu, bool reinjected) {
    return exit_vmx_inject_irq(vcpu, &rb, e);
}

SEC("fentry/kvm_emulate_hypercall")
int BPF_PROG(fentry_kvm_emulate_hypercall, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return trace_emulate_hypercall(vcpu, &rb, e);
}

SEC("kprobe/kvm_emulate_hypercall")
int BPF_KPROBE(kp_kvm_emulate_hypercall, struct kvm_vcpu *vcpu) {
    CHECK_PID(vm_pid);
    return trace_emulate_hypercall(vcpu, &rb, e);
}

SEC("tp/syscalls/sys_enter_ioctl")
int tp_ioctl(struct trace_event_raw_sys_enter *args) {
    CHECK_PID(vm_pid);
    return trace_kvm_ioctl(args);
}

SEC("uprobe")
int BPF_KPROBE(up_kvm_vcpu_ioctl, void *cpu, int type) {
    CHECK_PID(vm_pid);
    if (type != KVM_RUN)
        return 0;
    return trace_kvm_vcpu_ioctl();
}

SEC("tp/kvm/kvm_userspace_exit")
int tp_kvm_userspace_exit(struct userspace_exit *ctx) {
    return trace_kvm_userspace_exit(ctx);
}

SEC("fentry/start_hv_timer")
int BPF_PROG(fentry_start_hv_timer, struct kvm_lapic *apic) {
    CHECK_PID(vm_pid);
    return trace_start_hv_timer(apic);
}

SEC("kprobe/start_hv_timer")
int BPF_KPROBE(kp_start_hv_timer, struct kvm_lapic *apic) {
    CHECK_PID(vm_pid);
    return trace_start_hv_timer(apic);
}

SEC("fentry/start_sw_timer")
int BPF_PROG(fentry_start_sw_timer, struct kvm_lapic *apic) {
    CHECK_PID(vm_pid);
    return trace_start_sw_timer(apic);
}

SEC("kprobe/start_sw_timer")
int BPF_KPROBE(kp_start_sw_timer, struct kvm_lapic *apic) {
    CHECK_PID(vm_pid);
    return trace_start_sw_timer(apic);
}

//采集容器的系统用调用信息
SEC("tracepoint/raw_syscalls/sys_enter")
int tp_container_sys_entry(struct trace_event_raw_sys_enter *args) {
    //过滤进程
    if (hostname == NULL || hostname[0] == '\0') {
        
        return false; // 提前返回
    }
    struct task_struct *task;
    struct nsproxy *ns;
    struct uts_namespace *uts;
    struct data_t data = {};
    // 获取当前任务的 task_struct
    task = (struct task_struct *)bpf_get_current_task();
    
    // 获取 nsproxy
    bpf_probe_read_kernel(&ns, sizeof(ns), &task->nsproxy);
    if (!ns) {
        return false;
    }
    
    // 获取 uts_namespace
    bpf_probe_read_kernel(&uts, sizeof(uts), &ns->uts_ns);
    if (!uts) {
        return false;
    }
    // 读取主机名
    bpf_probe_read_kernel_str(&data.nodename, sizeof(data.nodename), uts->name.nodename);
    // 打印主机名
    
    for(int i = 0;i<MAX_NODENAME_LEN;i++){
        if(data.nodename[i] != hostname[i]){
            return 0;
        }
        if(data.nodename[i]=='\0'||hostname[i]=='\0'){
            break;
        }
    }
    pid_t pid = bpf_get_current_pid_tgid();
    bpf_map_update_elem(&container_id_map,&pid,&data.nodename,BPF_ANY);
    return trace_container_sys_entry(args);
}
SEC("tracepoint/raw_syscalls/sys_exit")
int tracepoint__syscalls__sys_exit(struct trace_event_raw_sys_exit *args) {
    //过滤进程
    if (hostname == NULL || hostname[0] == '\0') {
        return false; 
    }
    struct task_struct *task;
    struct nsproxy *ns;
    struct uts_namespace *uts;
    struct data_t data = {};
    // 获取当前任务的 task_struct
    task = (struct task_struct *)bpf_get_current_task();
    
    // 获取 nsproxy
    bpf_probe_read_kernel(&ns, sizeof(ns), &task->nsproxy);
    if (!ns) {
        return false;
    }
    
    // 获取 uts_namespace
    bpf_probe_read_kernel(&uts, sizeof(uts), &ns->uts_ns);
    if (!uts) {
        return false;
    }
    // 读取主机名
    bpf_probe_read_kernel_str(&data.nodename, sizeof(data.nodename), uts->name.nodename);
    // 打印主机名
    
    for(int i = 0;i<MAX_NODENAME_LEN;i++){
        if(data.nodename[i] != hostname[i]){
            return 0;
        }
        if(data.nodename[i]=='\0'||hostname[i]=='\0'){
            break;
        }
    }
    return trace_container_sys_exit(args, &rb, e);
}
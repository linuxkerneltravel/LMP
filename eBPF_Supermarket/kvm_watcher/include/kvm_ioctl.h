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
// Kernel space BPF program used for KVM ioctl

#ifndef __KVM_IOCTL_H
#define __KVM_IOCTL_H

#include "kvm_watcher.h"
#include "vmlinux.h"
#include <asm-generic/ioctl.h>
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_core_read.h>
#include <bpf/bpf_tracing.h>

#define KVMIO 0xAE
#define KVM_CREATE_VM _IO(KVMIO, 0x01) /* returns a VM fd */
#define KVM_CREATE_VCPU _IO(KVMIO, 0x41)
#define KVM_GET_VCPU_EVENTS _IOR(KVMIO, 0x9f, struct kvm_vcpu_events)
#define KVM_SET_VCPU_EVENTS _IOW(KVMIO, 0xa0, struct kvm_vcpu_events)
#define KVM_SET_USER_MEMORY_REGION \
    _IOW(KVMIO, 0x46, struct kvm_userspace_memory_region)
#define KVM_GET_REGS _IOR(KVMIO, 0x81, struct kvm_regs)
#define KVM_SET_REGS _IOW(KVMIO, 0x82, struct kvm_regs)
#define KVM_TRANSLATE _IOWR(KVMIO, 0x85, struct kvm_translation)
#define KVM_INTERRUPT _IOW(KVMIO, 0x86, struct kvm_interrupt)

static int trace_kvm_ioctl(struct trace_event_raw_sys_enter *args) {
    int fd = (int)args->args[0];
    unsigned int cmd = (unsigned int)args->args[1];
    unsigned long arg = (unsigned long)args->args[2];
    switch (cmd) {
        case KVM_CREATE_VM:
            bpf_printk("KVM_CREATE_VM: fd=%d\n", fd);
            break;
        case KVM_CREATE_VCPU: {
            int vcpu_id;
            bpf_probe_read(&vcpu_id, sizeof(vcpu_id), (void *)arg);
            bpf_printk("KVM_CREATE_VCPU: fd=%d, vcpu_id=%d\n", fd, vcpu_id);
            break;
        }
        case KVM_SET_USER_MEMORY_REGION: {
            struct kvm_userspace_memory_region region;
            bpf_probe_read(&region, sizeof(region), (void *)arg);
            // 打印或处理 region 数据
            bpf_printk(
                "KVM_SET_USER_MEMORY_REGION: fd=%d, slot=%u, flags=%u, "
                "guest_phys_addr=%llx, memory_size=%lluK,userspace_addr=%llx\n",
                fd, region.slot, region.flags, region.guest_phys_addr,
                region.memory_size / 1024,region.userspace_addr);
            break;
        }
        case KVM_GET_VCPU_EVENTS:
        case KVM_SET_VCPU_EVENTS: {
            struct kvm_vcpu_events events;
            bpf_probe_read(&events, sizeof(events), (void *)arg);
            // 打印或处理 events 数据
            bpf_printk(
                "KVM_SET/GET_VCPU_EVENTS: fd=%d, exception=%u, interrupt=%u\n",
                fd, events.exception.nr, events.interrupt.nr);
            break;
        }
        case KVM_GET_REGS:
        case KVM_SET_REGS: {
            struct kvm_regs regs;
            bpf_probe_read(&regs, sizeof(regs), (void *)arg);
            // 此处仅展示部分寄存器值的打印
            bpf_printk(
                "KVM_GET/SET_REGS: fd=%d, rax=%llx, rbx=%llx, rcx=%llx, "
                "rdx=%llx, rsi=%llx\n",
                fd, regs.rax, regs.rbx, regs.rcx, regs.rdx, regs.rsi);

            break;
        }
        case KVM_TRANSLATE: {
            struct kvm_translation tr;
            bpf_probe_read(&tr, sizeof(tr), (void *)arg);
            bpf_printk(
                "KVM_TRANSLATE: fd=%d,linear_address=%llx, "
                "physical_address=%llx\n",
                fd, tr.linear_address, tr.physical_address);
            break;
        }
        case KVM_INTERRUPT: {
            struct kvm_interrupt irq;
            bpf_probe_read(&irq, sizeof(irq), (void *)arg);
            bpf_printk("KVM_INTERRUPT:fd=%d,interrupt vector:%d\n", fd,
                       irq.irq);
            break;
        }
        default:
            break;
    }
    return 0;
}

#endif /* __KVM_IOCTL_H */
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
// BPF program used for monitoring KVM event.

#ifndef __KVM_WATCHER_H
#define __KVM_WATCHER_H

#define SET_KP_OR_FENTRY_LOAD(function_name, module_name)                    \
    do {                                                                     \
        if (fentry_can_attach(#function_name, #module_name)) {                \
            bpf_program__set_autoload(skel->progs.fentry_##function_name,    \
                                      true);                                 \
        } else {                                                             \
            bpf_program__set_autoload(skel->progs.kp_##function_name, true); \
        }                                                                    \
    } while (0)

static const char binary_path[] = "/bin/qemu-system-x86_64";
#define __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe)               \
    do {                                                                      \
        LIBBPF_OPTS(bpf_uprobe_opts, uprobe_opts, .func_name = #sym_name,     \
                    .retprobe = is_retprobe);                                 \
        skel->links.prog_name = bpf_program__attach_uprobe_opts(              \
            skel->progs.prog_name, env.vm_pid, binary_path, 0, &uprobe_opts); \
    } while (false)

#define __CHECK_PROGRAM(skel, prog_name)                   \
    do {                                                   \
        if (!skel->links.prog_name) {                      \
            perror("no program attached for " #prog_name); \
            return -errno;                                 \
        }                                                  \
    } while (false)

#define __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, is_retprobe) \
    do {                                                                \
        __ATTACH_UPROBE(skel, sym_name, prog_name, is_retprobe);        \
        __CHECK_PROGRAM(skel, prog_name);                               \
    } while (false)

#define ATTACH_UPROBE(skel, sym_name, prog_name) \
    __ATTACH_UPROBE(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE(skel, sym_name, prog_name) \
    __ATTACH_UPROBE(skel, sym_name, prog_name, true)

#define ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name) \
    __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, false)
#define ATTACH_URETPROBE_CHECKED(skel, sym_name, prog_name) \
    __ATTACH_UPROBE_CHECKED(skel, sym_name, prog_name, true)

#define TASK_COMM_LEN 16
#define KVM_MEM_LOG_DIRTY_PAGES (1UL << 0)

#define PAGE_SHIFT 12

#define NS_TO_US_FACTOR 1000.0
#define NS_TO_MS_FACTOR 1000000.0

#define NS_TO_US_WITH_DECIMAL(ns) ((double)(ns) / NS_TO_US_FACTOR)
#define NS_TO_MS_WITH_DECIMAL(ns) ((double)(ns) / NS_TO_MS_FACTOR)

#define OUTPUT_INTERVAL(SECONDS) sleep(SECONDS)

#define OPTIONS_LIST "-w, -d, -f, -c, -i, -l , -o , -h , -T or -e"

#define PFERR_PRESENT_BIT 0
#define PFERR_WRITE_BIT 1
#define PFERR_USER_BIT 2
#define PFERR_RSVD_BIT 3
#define PFERR_FETCH_BIT 4
#define PFERR_PK_BIT 5
#define PFERR_SGX_BIT 15

#define KVM_IRQCHIP_PIC 0
#define KVM_IRQCHIP_IOAPIC 1
#define KVM_MSI 2

#define PIC_NUM_PINS 16
#define IOAPIC_NUM_PINS 24

#define PFERR_RSVD_MASK (1UL << 3)  // mmio


// 定时器模式
#define APIC_LVT_TIMER_ONESHOT (0 << 17)      // 单次触发
#define APIC_LVT_TIMER_PERIODIC (1 << 17)     // 周期性触发模式
#define APIC_LVT_TIMER_TSCDEADLINE (2 << 17)  // TSC 截止模式

// IOCTL
#include <asm-generic/ioctl.h>
#define KVMIO 0xAE
#define KVM_CREATE_VM _IO(KVMIO, 0x01)
#define KVM_CREATE_VCPU _IO(KVMIO, 0x41)
#define KVM_GET_VCPU_EVENTS _IOR(KVMIO, 0x9f, struct kvm_vcpu_events)
#define KVM_SET_VCPU_EVENTS _IOW(KVMIO, 0xa0, struct kvm_vcpu_events)
#define KVM_SET_USER_MEMORY_REGION \
    _IOW(KVMIO, 0x46, struct kvm_userspace_memory_region)
#define KVM_TRANSLATE _IOWR(KVMIO, 0x85, struct kvm_translation)
#define KVM_INTERRUPT _IOW(KVMIO, 0x86, struct kvm_interrupt)
#define KVM_RUN _IO(KVMIO, 0x80)

#define PRINT_USAGE_ERR()                                               \
    do {                                                                \
        fprintf(stderr, "Please specify exactly one option from %s.\n", \
                OPTIONS_LIST);                                          \
        argp_state_help(state, stdout, ARGP_HELP_STD_HELP);             \
    } while (0)

#define SET_OPTION_AND_CHECK_USAGE(option, value) \
    do {                                          \
        if (option == 0) {                        \
            value = true;                         \
            option = 1;                           \
        } else {                                  \
            PRINT_USAGE_ERR();                    \
        }                                         \
    } while (0)

#define RING_BUFFER_TIMEOUT_MS 100

#define RESERVE_RINGBUF_ENTRY(rb, e)                             \
    do {                                                         \
        typeof(e) _tmp = bpf_ringbuf_reserve(rb, sizeof(*e), 0); \
        if (!_tmp)                                               \
            return 0;                                            \
        e = _tmp;                                                \
    } while (0)

#define CHECK_PID(vm_pid)                                                 \
    if ((vm_pid) > 0 && (bpf_get_current_pid_tgid() >> 32) != (vm_pid)) { \
        return 0;                                                         \
    }
#define LOGO_STRING                                                \
    " _  ____     ____  __  __        ___  _____ ____ _   _ "      \
    "_____ ____  \n"                                               \
    "| |/ /\\ \\   / /  \\/  | \\ \\      / / \\|_   _/ "          \
    "___| | | | ____|  _ \\ \n"                                    \
    "| ' /  \\ \\ / /| |\\/| |  \\ \\ /\\ / / _ \\ | || |   "      \
    "| |_| |  _| | |_) |\n"                                        \
    "| . \\   \\ V / | |  | |   \\ V  V / ___ \\| || "             \
    "|___|  _  | |___|  _ < \n"                                    \
    "|_|\\_\\   \\_/  |_|  |_|    \\_/\\_/_/   \\_\\_| \\____|_| " \
    "|_|_____|_| \\_|\\\n"

struct reason_info {
    __u64 time;
    __u64 reason;
};
struct exit_key {
    __u64 reason;
    __u32 pid;
    __u32 tid;
};

struct load_key {
    __u32 pid;
    __u32 tid;
};
struct load_value {
    __u64 max_time;
    __u64 total_time;
    __u64 min_time;
    __u32 count;
    __u32 vcpu_id;
    __u32 pcpu_id;
    __u32 pad;
};
struct time_value {
    __u64 time;
    __u32 vcpu_id;
    __u32 pcpu_id;
};
struct exit_value {
    __u64 max_time;
    __u64 total_time;
    __u64 min_time;
    __u32 count;
    __u32 pad;
};
struct container_id{
    char container_id[20];
};
//记录进程系统调用的详细信息
#define MAX_SYSCALL_NUM 462
struct syscall_value{
    char container_id[20]; //容器ID
    char proc_name[20]; //进程名
    __u32 syscall_id_counts[MAX_SYSCALL_NUM];
    __u64 syscall_total_delay[MAX_SYSCALL_NUM];
};
struct dirty_page_info {
    __u64 gfn;
    __u64 rel_gfn;
    __u16 slot_id;
    __u16 pad;
    __u32 pid;
};

struct hc_value {
    __u64 a0;
    __u64 a1;
    __u64 a2;
    __u64 a3;
    __u64 hypercalls;  // vcpu上hypercall发生的次数
    __u32 counts;      // 特定hypercall发生的次数
    __u32 pad;
};

struct hc_key {
    __u64 nr;
    pid_t pid;
    __u32 vcpu_id;
};

struct timer_key {
    pid_t pid;
    __u32 timer_mode;
    bool hv;
    bool pad[3];
};

struct timer_value {
    __u32 counts;
};

struct process {
    __u32 pid;
    __u32 tid;
    char comm[TASK_COMM_LEN];
};


enum EventType {
    NONE_TYPE,
    VCPU_WAKEUP,
    VCPU_LOAD,
    EXIT,
    HALT_POLL,
    MARK_PAGE_DIRTY,
    PAGE_FAULT,
    IRQCHIP,
    IRQ_INJECT,
    HYPERCALL,
    IOCTL,
    CONTAINER_SYSCALL,
    TIMER,
} event_type;

enum NameType {
    UNKNOWN_NAME_TYPE,
    HYPERCALL_NR,
    EXIT_NR,
    EXIT_USERSPACE_NR,
    TIMER_MODE_NR,
} name_type;

struct common_event {
    struct process process;
    __u64 time;

    // 成员特定于每个事件类型的数据
    union {
        struct {
            __u64 dur_hlt_ns;
            bool waited;
            __u32 vcpu_id;
            bool valid;
            // VCPU_WAKEUP 特有成员
        } vcpu_wakeup_data;

        struct {
            __u32 reason_number;
            __u64 duration_ns;
            __u32 count;
            __u32 total;
            // EXIT 特有成员
        } exit_data;

        struct {
            bool grow;
            __u32 new;
            __u32 old;
            __u32 vcpu_id;
            // HALT_POLL 特有成员
        } halt_poll_data;

        struct {
            __u64 npages;
            __u64 userspace_addr;
            __u64 rel_gfn;
            __u64 gfn;
            __u16 slot_id;
            // MARK_PAGE_DIRTY 特有成员
        } mark_page_dirty_data;

        struct {
            __u64 delay;
            __u64 error_code;
            __u64 addr;
            __u64 pfn;
            __u64 hva;
            __u32 count;
            __u16 memslot_id;
            // PAGE_FAULT 特有成员
        } page_fault_data;

        struct {
            __u64 delay;
            __u32 ret;
            __u32 irqchip_type;
            /*pic*/
            __u16 chip;
            __u32 pin;
            __u16 elcr;
            __u16 imr;
            /*ioapic*/
            __u64 ioapic_bits;
            __u32 irq_nr;
            /*msi*/
            __u64 address;
            __u64 data;
            // IRQCHIP 特有成员
        } irqchip_data;

        struct {
            __u64 delay;
            bool soft;
            __u32 irq_nr;
            __u32 vcpu_id;
            __u64 injections;
            // IRQ_INJECT 特有成员
        } irq_inject_data;

        struct {
            __u64 hc_nr;
            __u64 a0;
            __u64 a1;
            __u64 a2;
            __u64 a3;
            __u64 hypercalls;
            __u32 vcpu_id;
            // HYPERCALL 特有成员
        } hypercall_data;

        struct{
            __u64 pid;
            __u64 syscall_id;
            __u64 delay;
            char comm[20];
            char container_id[20];
        } syscall_data;
    };
};

#endif /* __KVM_WATCHER_H */
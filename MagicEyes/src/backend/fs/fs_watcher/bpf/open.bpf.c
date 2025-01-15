#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "GPL";

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, struct event_open);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps"); // 环形缓冲区

SEC("tracepoint/syscalls/sys_enter_openat")
int do_syscall_trace(struct trace_event_raw_sys_enter *ctx)
{
	struct event_open e = {};
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	e.pid = pid;
	e.dfd = ctx->args[0];// 目录文件描述符
	bpf_probe_read_user_str(e.filename, sizeof(e.filename), (const char *)ctx->args[1]);  // 文件路径
 	e.flags = ctx->args[2];  // 打开标志

	bpf_map_update_elem(&data,&pid,&e,BPF_ANY);
	return 0;
}

//跟踪文件描述符分配过程
SEC("kretprobe/get_unused_fd_flags")
int kretprobe_get_unused_fd_flags(struct pt_regs *ctx){
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct event_open *e = bpf_map_lookup_elem(&data,&pid);
	if(!e){
		bpf_printk("get_unused_fd_flags is failed to found fd\n");
		return 0;
	}
    //获取分配的文件描述符
    int fd = PT_REGS_RC(ctx);

    if (fd <= 0) {
        bpf_printk("get_unused_fd_flags: syscall failed with error %d\n", fd);
		return 0;
    } else {
        bpf_printk("get_unused_fd_flags: allocated fd %d\n", fd);
        e->fd = fd;
        bpf_map_update_elem(&data, &pid, e, BPF_ANY);
    }
	return 0;
}

// 跟踪 openat 系统调用的退出
SEC("tracepoint/syscalls/sys_exit_openat")
int do_syscall_exit(struct trace_event_raw_sys_exit *ctx)
{
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	struct event_open *e = bpf_map_lookup_elem(&data,&pid);
	if(!e){
		bpf_printk("sys_exit_openat is failed to found fd\n");
		return 0;
	}

	e->ret = ctx->ret;

	// 分配 ringbuf 空间
    struct event_open *new_e = bpf_ringbuf_reserve(&rb, sizeof(*new_e), 0);
    if (!new_e) {
        return 0;  // 如果分配失败，提前返回
    }

	//复制数据
	new_e->dfd = e->dfd;
	new_e->flags = e->flags;
	new_e->fd = e->fd;
	new_e->ret = e->ret;
	new_e->pid = e->pid;

	// 手动读取文件路径，确保不超过最大长度，并添加 '\0' 结束符
    int filename_len = 0;
    while (filename_len < sizeof(new_e->filename) - 1) {
        char c = 0;
        // 读取路径中的每个字符
        bpf_probe_read(&c, sizeof(c), e->filename + filename_len);
        if (c == '\0') break;  // 如果遇到 null 字符就停止读取
        new_e->filename[filename_len++] = c;
    }
    // 确保字符串以 '\0' 结束
    new_e->filename[filename_len] = '\0';
	bpf_printk("Opening file: %s, pid: %d, flags: %d\n", new_e->filename, pid, e->flags);
	bpf_ringbuf_submit(new_e, 0);
	return 0;
}

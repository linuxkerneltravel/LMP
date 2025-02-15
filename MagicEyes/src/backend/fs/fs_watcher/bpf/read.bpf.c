#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

// 手动定义文件类型宏
#define S_IFMT  0170000 // 文件类型掩码  
#define S_IFREG 0100000 // 普通文件  
#define S_IFCHR 0020000 // 字符设备  
#define S_IFDIR 0040000 // 目录  
#define S_IFLNK 0120000 // 符号链接  
#define S_IFBLK 0060000 // 块设备  
#define S_IFIFO 0010000 // FIFO（命名管道）  
#define S_IFSOCK 0140000 // 套接字

struct {
	__uint(type, BPF_MAP_TYPE_HASH);
	__uint(max_entries, 1024);
	__type(key, pid_t);
	__type(value, struct event_read);
} data SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

SEC("kprobe/vfs_read")
int kprobe_enter_read(struct pt_regs *ctx)
{
	struct event_read e = {};
	struct file *filp = (struct file *)PT_REGS_PARM1(ctx);
	pid_t pid = bpf_get_current_pid_tgid() >> 32;
	e.pid = pid; //获取进程pid
	size_t count = (size_t)PT_REGS_PARM3(ctx);               // 获取请求读取的字节数

	//获取文件路径结构体
	struct dentry *dentry = BPF_CORE_READ(filp, f_path.dentry);
	if(!dentry){
		bpf_printk("Failed to read dentry\n");
		return 0;
	}
	struct qstr d_name = BPF_CORE_READ(dentry,d_name);
	bpf_probe_read_str(e.filename, sizeof(e.filename), d_name.name);  // 读取文件名
	// 判断文件类型，并过滤掉设备文件
    unsigned short file_type = BPF_CORE_READ(dentry, d_inode, i_mode) & S_IFMT;
	e.file_type = file_type;
	bpf_map_update_elem(&data,&pid,&e,BPF_ANY);
    return 0;
}

SEC("kretprobe/vfs_read")
int kretprobe_exit_read(struct pt_regs *ctx)
{
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    ssize_t real_count = PT_REGS_RC(ctx);  // 获取实际返回的字节数
	struct event_read *e = bpf_map_lookup_elem(&data, &pid);
	if(!e){
		bpf_printk("Failed to found read event\n");
		return 0;
	}
	e->count_size = real_count;

	// 使用 ring buffer 向用户态传递数据
	struct event_read *e_ring = bpf_ringbuf_reserve(&rb, sizeof(*e), 0);
	if (!e_ring) {
		return 0;  // 如果 ring buffer 没有足够空间，直接返回
	}

	// 将数据填充到 ring buffer 中
	*e_ring = *e;

	// 提交数据到 ring buffer
	bpf_ringbuf_submit(e_ring, 0);

	// 删除哈希表中的该事件数据，避免泄露
	bpf_map_delete_elem(&data, &pid);
	
	return 0;
}
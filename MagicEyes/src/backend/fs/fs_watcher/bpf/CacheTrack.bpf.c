#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>
#include "fs_watcher.h"

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024); 
    __type(key, u64);  // 使用inode作为key
    __type(value, struct event_CacheTrack); //存储事件结构体
} data_map SEC(".maps");

struct {
	__uint(type, BPF_MAP_TYPE_RINGBUF);
	__uint(max_entries, 256 * 1024);
} rb SEC(".maps");

//事件会在脏 inode 开始进行写回时触发
SEC("tracepoint/writeback/writeback_dirty_inode_start")
int trace_writeback_start(struct trace_event_raw_writeback_dirty_inode_template  *ctx){
    pid_t pid = bpf_get_current_pid_tgid() >> 32;
    u64 timestamp = bpf_ktime_get_ns();
    ino_t inode;
    char comm[16];
    struct event_CacheTrack event_info ={};
    char name[32];
    // 获取当前进程的命令名称
    bpf_get_current_comm(&comm, sizeof(comm));

    // 将 comm 字符串复制到 event_info.comm
    __builtin_memcpy(event_info.comm, comm, sizeof(comm));

    event_info.ino = inode = ctx->ino;

    event_info.state = ctx->state;

    event_info.flags = ctx->flags;

    event_info.time = timestamp;

    bpf_map_update_elem(&data_map,&inode,&event_info,BPF_ANY);
    return 0;
}

// 事件会在每个 inode 进行单独写回时触发
SEC("tracepoint/writeback/writeback_single_inode")
int trace_writeback_single_inode(struct trace_event_raw_writeback_single_inode_template *ctx){
    ino_t inode = ctx->ino;
    u64 timestamp_conmplete = bpf_ktime_get_ns();
    struct event_CacheTrack *event_info;

    //从map中获取该inode对应的事件信息
    event_info = bpf_map_lookup_elem(&data_map,&inode);
    if(!event_info){
        bpf_printk("failed to found event_info\n");
        return 0;
    }
    //更新inode写回完成的信息
    event_info->wrote = ctx->wrote; //已写回的字节数
    event_info->nr_to_write = ctx->nr_to_write; //待写回的字节数
    event_info->writeback_index = ctx->writeback_index; //表示写回操作的索引或序号
    event_info->time_complete = timestamp_conmplete;

    // 将事件信息提交到 ring buffer
    struct event_CacheTrack *ring_event = bpf_ringbuf_reserve(&rb, sizeof(struct event_CacheTrack), 0);
    if (!ring_event) {
        bpf_printk("Failed to reserve space in ring buffer for inode %llu\n", inode);
        return 0;
    }

    // 将事件信息从 map 拷贝到 ring buffer
    __builtin_memcpy(ring_event, event_info, sizeof(struct event_CacheTrack));
    bpf_ringbuf_submit(ring_event, 0);

    return 0;
}
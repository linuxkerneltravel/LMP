// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <stdint.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <unistd.h>
#include <stdlib.h>
#include <inttypes.h>
#include <linux/fs.h>
#include <errno.h>
#include <fcntl.h>  // 包含文件打开标志宏
#include <argp.h>
#include "fs/fs_watcher/open.skel.h"
#include "fs/fs_watcher/read.skel.h"
#include "fs/fs_watcher/write.skel.h"
#include "fs/fs_watcher/disk_io_visit.skel.h"
#include "fs/fs_watcher/block_rq_issue.skel.h"
#include "fs/fs_watcher/CacheTrack.skel.h"
#include "fs_watcher/include/fs_watcher.h"

const char argp_program_doc[] = "fs_watcher is used to monitor various system calls and disk I/O events.\n\n"
           "Usage: fs_watcher [OPTION...]\n\n"
           "Options:";

#define PROCESS_SKEL(skel, func) \
    skel = func##_bpf__open(); \
    if (!skel) { \
        fprintf(stderr, "Failed to open and load BPF skeleton\n"); \
        return 1; \
    } \
    process_##func(skel)


#define POLL_RING_BUFFER(rb, timeout, err)     \
    while (!exiting) {  \
        sleep(1);                       \
        err = ring_buffer__poll(rb, timeout);  \
        if (err == -EINTR) {                   \
            err = 0;                           \
            break;                             \
        }                                      \
        if (err < 0) {                         \
            printf("Error polling perf buffer: %d\n", err); \
            break;                             \
        }                                      \
    }

#define LOAD_AND_ATTACH_SKELETON(skel, event) \
    do {                                             \
        err = event##_bpf__load(skel);               \
        if (err) {                                   \
            fprintf(stderr, "Failed to load and verify BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        err = event##_bpf__attach(skel);             \
        if (err) {                                   \
            fprintf(stderr, "Failed to attach BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_##event, NULL, NULL); \
        if (!rb) {                                   \
            fprintf(stderr, "Failed to create ring buffer\n"); \
            goto event##_cleanup;                     \
        }                                            \
    } while(0)


#define LOAD_AND_ATTACH_SKELETON_MAP(skel, event) \
    do {                                             \
        err = event##_bpf__load(skel);               \
        if (err) {                                   \
            fprintf(stderr, "Failed to load and verify BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        err = event##_bpf__attach(skel);             \
        if (err) {                                   \
            fprintf(stderr, "Failed to attach BPF skeleton\n"); \
            goto event##_cleanup;                     \
        }                                            \
                                                     \
        int map_fd = bpf_map__fd(skel->maps.data);    \
        if(!map_fd){                                   \
            fprintf(stderr, "Failed to find BPF map\n");        \
            return -1;                                           \
        }                                                          \
        rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event_##event, &map_fd, NULL); \
        if (!rb) {                                   \
            fprintf(stderr, "Failed to create ring buffer\n"); \
            goto event##_cleanup;                     \
        }                                            \
    } while(0)

static struct env{
    bool open;
    bool read;
    bool write;
    bool disk_io_visit;
    bool block_rq_issue;
    bool CacheTrack;
}env = {
    .open = false,
    .read = false,
    .write = false,
    .disk_io_visit = false,
    .block_rq_issue = false,
    .CacheTrack = false,
};

static const struct argp_option opts[] = {
    {"open", 'o', 0, 0, "Print open system call report"},
    {"read", 'r', 0, 0, "Print read system call report"},
    {"write", 'w', 0, 0, "Print write system call report"},
    {"disk_io_visit", 'd', 0, 0, "Print disk I/O visit report"},
    {"block_rq_issue", 'b', 0, 0, "Print block I/O request submission events. Reports when block I/O requests are submitted to device drivers."},
    {"CacheTrack", 't' , 0 ,0 , "WriteBack dirty lagency and other information"},
    {0} // 结束标记，用于指示选项列表的结束
};


static error_t parse_arg(int key, char *arg, struct argp_state *state) {
    switch(key){
        case 'o':
        env.open = true;break;
        case 'r':
        env.read = true;break;
        case 'w':
        env.write = true;break;
        case 'd':
        env.disk_io_visit = true;break;
        case 'b':
        env.block_rq_issue = true;break;
        case 't':
        env.CacheTrack = true;break;
        default: 
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
    .help_filter = NULL
};
#define warn(...) fprintf(stderr, __VA_ARGS__)

static int libbpf_print_fn(enum libbpf_print_level level, const char *format,
			   va_list args)
{
	// return vfprintf(stderr, format, args);
    return 0;
}

static volatile bool exiting = false;

static void sig_handler(int sig)
{
	exiting = true;
}

static int handle_event_open(void *ctx, void *data, size_t data_sz);
static int handle_event_read(void *ctx, void *data, size_t data_sz);
static int handle_event_write(void *ctx, void *data, size_t data_sz);
static int handle_event_disk_io_visit(void *ctx, void *data, size_t data_sz);
static int handle_event_block_rq_issue(void *ctx, void *data, size_t data_sz);
static int handle_event_CacheTrack(void *ctx, void *data, size_t data_sz);

static int process_open(struct open_bpf *skel_open);
static int process_read(struct read_bpf *skel_read);
static int process_write(struct write_bpf *skel_write);
static int process_disk_io_visit(struct disk_io_visit_bpf *skel_disk_io_visit);
static int process_block_rq_issue(struct block_rq_issue_bpf *skel_block_rq_issue);
static int process_CacheTrack(struct CacheTrack_bpf *skel_CacheTrack);



int main(int argc,char **argv){

    int err;
    struct open_bpf *skel_open;
    struct read_bpf *skel_read;
    struct write_bpf *skel_write;
    struct disk_io_visit_bpf *skel_disk_io_visit;
    struct block_rq_issue_bpf *skel_block_rq_issue;
    struct CacheTrack_bpf *skel_CacheTrack;


    libbpf_set_strict_mode(LIBBPF_STRICT_ALL);


    /* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

    /* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);
    signal(SIGALRM, sig_handler);


    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    //   printf("success!\n");
    if (err)
        return err;

    if(env.open){
        PROCESS_SKEL(skel_open,open);
    }else if(env.read){
        PROCESS_SKEL(skel_read,read);
    }else if(env.write){
        PROCESS_SKEL(skel_write,write);
    }else if(env.disk_io_visit){
        PROCESS_SKEL(skel_disk_io_visit,disk_io_visit);
    }else if(env.block_rq_issue){
        PROCESS_SKEL(skel_block_rq_issue,block_rq_issue);
    }else if(env.CacheTrack){
        PROCESS_SKEL(skel_CacheTrack,CacheTrack);
    }else{
        fprintf(stderr, "No function selected. Use -h for help.\n");
        return 1;
    }
}

const char* flags_to_str(int flags) {
    static char str[256];
    str[0] = '\0';  // 清空字符串
    
    if (flags & O_RDONLY)   strcat(str, "O_RDONLY ");
    if (flags & O_WRONLY)   strcat(str, "O_WRONLY ");
    if (flags & O_RDWR)     strcat(str, "O_RDWR ");
    if (flags & O_CREAT)    strcat(str, "O_CREAT ");
    if (flags & O_EXCL)     strcat(str, "O_EXCL ");
    if (flags & O_TRUNC)    strcat(str, "O_TRUNC ");
    if (flags & O_APPEND)   strcat(str, "O_APPEND ");
    if (flags & O_NOFOLLOW) strcat(str, "O_NOFOLLOW ");
    if (flags & O_CLOEXEC)  strcat(str, "O_CLOEXEC ");
    if (flags & O_NONBLOCK) strcat(str, "O_NONBLOCK ");
    if (flags & O_SYNC)     strcat(str, "O_SYNC ");
    if (flags & O_DSYNC)    strcat(str, "O_DSYNC ");
    if (flags & O_RSYNC)    strcat(str, "O_RSYNC ");
    if (flags & O_DIRECTORY) strcat(str, "O_DIRECTORY ");
    
    // 条件编译部分：如果系统定义了 O_NOATIME 和 O_PATH
#ifdef O_NOATIME
    if (flags & O_NOATIME)  strcat(str, "O_NOATIME ");
#endif

#ifdef O_PATH
    if (flags & O_PATH)     strcat(str, "O_PATH ");
#endif
    
    // 如果没有匹配到标志，返回 "Unknown"
    if (str[0] == '\0') {
        return "Unknown";
    }
    
    return str;
}

static int handle_event_open(void *ctx, void *data, size_t data_sz)
{
    const struct event_open *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);
    const char *ret_str;
    // 如果返回值是负数，则是错误码，使用 strerror
    if (e->ret < 0) {
        ret_str = strerror(-e->ret);  // 负数表示错误码
    } else {
        // 正数表示文件描述符，直接打印文件描述符
        ret_str = "Success";  // 如果是文件描述符，表示成功
    }

    const char *flags_str = flags_to_str(e->flags);

    printf("%-8s %-8d %-8d %-100s %-8s %-8d %-8s %-8s\n", 
           ts, e->dfd, e->pid,e->filename, flags_str, e->fd, ret_str, e->is_created ? "true" : "false");
	return 0;
}


static int handle_event_read(void *ctx, void *data, size_t data_sz)
{
	const struct event_read *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-10s %-8d %-8llu\n",ts,e->pid,e->duration_ns);
	return 0;
}

static int handle_event_write(void *ctx, void *data, size_t data_sz)
{
    const struct fs_t *e = data;
    struct tm *tm;
    char ts[32];
    time_t t;
    time(&t);
    tm = localtime(&t);
    strftime(ts, sizeof(ts), "%H:%M:%S", tm);
	printf("%-8s %-8ld %-8ld %-8ld %-8ld\n", ts, e->pid,e->inode_number,e->count,e->real_count);
    return 0;
}

static int handle_event_disk_io_visit(void *ctx, void *data,unsigned long data_sz) {
    const struct event_disk_io_visit *e = data;

    printf("%-18llu %-7d %-7d %-4d %-7d %-16s\n",
           e->timestamp, e->blk_dev, e->sectors, e->rwbs, e->count, e->comm);

    return 0;
}

static int handle_event_block_rq_issue(void *ctx, void *data,unsigned long data_sz) {
    const struct event_block_rq_issue *e = data;
    printf("%-18llu %-15d %-15d %-10d %-16s Total I/O: %" PRIu64 "\n",
           e->timestamp, e->dev, e->sector, e->nr_sectors, e->comm, e->total_io);

    return 0;
}

static int handle_event_CacheTrack(void *ctx, void *data, unsigned long data_sz) {
    const struct event_CacheTrack *event = data;

    // 计算写回操作的耗时
    long long writeback_duration = event->time_complete - event->time;

    // 打印所有相关的信息
    printf("%-19llu %-15s %-20lu %-5lu %-20ld %-20lu %-20llu %-20lld\n", 
           event->ino,              // inode 号
           event->comm,             //进程comm
           event->state,            // inode 状态
           event->flags,            // inode 标志
           event->nr_to_write,      // 待写回字节数
           event->writeback_index,  // 写回操作的索引或序号
           event->wrote,            // 已写回的字节数
           writeback_duration);     // 写回耗时

    return 0;
}


static int process_open(struct open_bpf *skel_open){
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON_MAP(skel_open,open);

    printf("%-8s %-8s %-8s %-100s %-8s %-8s %-8s %-8s\n", "TIME","dfd","PID", "filename", "flags", "fd", "ret", "is_created");
    POLL_RING_BUFFER(rb, 1000, err);

open_cleanup:
    ring_buffer__free(rb);
    open_bpf__destroy(skel_open);

    return err;
}

static int process_read(struct read_bpf *skel_read){
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_read,read);

    printf("%-10s %-8s %-8s\n","TIME","PID","DS");
    POLL_RING_BUFFER(rb, 1000, err);

read_cleanup:
    ring_buffer__free(rb);
    read_bpf__destroy(skel_read);

    return err;
}

static int process_write(struct write_bpf *skel_write){
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_write,write);

    printf("%-8s    %-8s    %-8s    %-8s    %-8s\n","ds","inode_number","pid","real_count","count");
    POLL_RING_BUFFER(rb, 1000, err);

write_cleanup:
    ring_buffer__free(rb);
    write_bpf__destroy(skel_write);

    return err;
}

static int process_disk_io_visit(struct disk_io_visit_bpf *skel_disk_io_visit){
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_disk_io_visit,disk_io_visit);
    printf("%-18s %-7s %-7s %-4s %-7s %-16s\n","TIME", "DEV", "SECTOR", "RWBS", "COUNT", "COMM");
    POLL_RING_BUFFER(rb, 1000, err);

disk_io_visit_cleanup:
    ring_buffer__free(rb);
    disk_io_visit_bpf__destroy(skel_disk_io_visit);

    return err;

}

static int process_block_rq_issue(struct block_rq_issue_bpf *skel_block_rq_issue){
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_block_rq_issue,block_rq_issue);
    printf("%-18s %-15s %-15s %-10s %-16s %-5s\n","TIME", "DEV", "SECTOR", "SECTORS","COMM","Total_Size");
    POLL_RING_BUFFER(rb, 1000, err);

block_rq_issue_cleanup:
    ring_buffer__free(rb);
    block_rq_issue_bpf__destroy(skel_block_rq_issue);

    return err;

}

static int process_CacheTrack(struct CacheTrack_bpf *skel_CacheTrack){
    int err;
    struct ring_buffer *rb;

    LOAD_AND_ATTACH_SKELETON(skel_CacheTrack,CacheTrack);
    // 打印列标题说明（解释各列的含义）
    printf("%-19s %-15s %-20s %-5s %-20s %-20s %-20s %-20s\n", 
       "INODE",                // inode号
       "COMM",                //comm进程名
       "STATE",              // inode 状态
       "FLAGS",              // inode 标志
       "NR_TO_WRITE",        // 待写回字节数
       "WRITEBACK_INDEX",    // 写回操作的索引或序号
       "WROTE",              // 已写回字节数
       "WRITEBACK_DURATION"); // 写回操作的耗时

    POLL_RING_BUFFER(rb, 1000, err);

CacheTrack_cleanup:
    ring_buffer__free(rb);
    CacheTrack_bpf__destroy(skel_CacheTrack);

    return err;

}
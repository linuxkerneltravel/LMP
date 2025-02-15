#ifndef __FS_WATCHER_H
#define __FS_WATCHER_H

/*open*/
#define path_size 256
#define TASK_COMM_LEN 16

struct event_open {
    pid_t pid;          // 进程 ID
    int dfd;            // 目录文件描述符
    char filename[256]; // 文件路径
    int flags;          // 打开标志
    int fd;             // 文件描述符
    int ret;            // 系统调用返回值
};

/*read*/
struct event_read {
    int pid;
    char filename[256]; // 文件名
    int count_size;     // 读取的字节数
    unsigned short file_type; // 文件类型
};

/*write*/
struct fs_t {
    unsigned long inode_number;
    pid_t pid;
    size_t real_count;
    size_t count;
};

/*disk_io_visit*/
struct event_disk_io_visit {
    long timestamp; // 时间戳
    int blk_dev; // 块设备号
    int sectors; // 访问的扇区数
    int rwbs; // 读写标识符，1表示读操作，0表示写操作
    int count; // I/O 操作计数
    char comm[TASK_COMM_LEN]; // 进程名
};

/*block_rq_issue*/
struct event_block_rq_issue {
    long timestamp;       // 时间戳
    int dev;           // 设备号
    int sector;         // 扇区号
    int nr_sectors;     // 扇区数
    char comm[TASK_COMM_LEN]; // 进程名
    int total_io; //I/O总大小
};


/*CacheTrack*/
struct event_CacheTrack{
    char comm[16];
    long long time; //耗时
    ino_t ino;             // inode 号
    unsigned long state;    // inode 状态
    unsigned long flags;    // inode 标志
    long int nr_to_write;  // 待写回字节数
    long unsigned int writeback_index; //写回操作的索引或序号
    long unsigned int wrote; //已写回的字节数
    long long time_complete;  // 写回开始时间
};

#endif /* __FS_WATCHER_H */
#ifndef __MEM_WATCHER_H
#define __MEM_WATCHER_H

#define TASK_COMM_LEN 16
#define MAX_FILENAME_LEN 127

#define ___GFP_DMA		0x01u
#define ___GFP_HIGHMEM		0x02u
#define ___GFP_DMA32		0x04u
#define ___GFP_MOVABLE		0x08u
#define ___GFP_RECLAIMABLE	0x10u
#define ___GFP_HIGH		0x20u
#define ___GFP_IO		0x40u
#define ___GFP_FS		0x80u
#define ___GFP_ZERO		0x100u
#define ___GFP_ATOMIC		0x200u
#define ___GFP_DIRECT_RECLAIM	0x400u
#define ___GFP_KSWAPD_RECLAIM	0x800u
#define ___GFP_WRITE		0x1000u
#define ___GFP_NOWARN		0x2000u
#define ___GFP_RETRY_MAYFAIL	0x4000u
#define ___GFP_NOFAIL		0x8000u
#define ___GFP_NORETRY		0x10000u
#define ___GFP_MEMALLOC		0x20000u
#define ___GFP_COMP		0x40000u
#define ___GFP_NOMEMALLOC	0x80000u
#define ___GFP_HARDWALL		0x100000u
#define ___GFP_THISNODE		0x200000u
#define ___GFP_ACCOUNT		0x400000u
#define ___GFP_ZEROTAGS		0x800000u
#define ___GFP_SKIP_KASAN_POISON	0x1000000u
	
#define GFP_ATOMIC      (___GFP_HIGH|___GFP_ATOMIC|___GFP_KSWAPD_RECLAIM)
#define GFP_KERNEL      (___GFP_RECLAIMABLE | ___GFP_IO | ___GFP_FS)
#define GFP_KERNEL_ACCOUNT (GFP_KERNEL | ___GFP_ACCOUNT)
#define GFP_NOWAIT      (___GFP_KSWAPD_RECLAIM)
#define GFP_NOIO        (___GFP_RECLAIMABLE)
#define GFP_NOFS        (___GFP_RECLAIMABLE | ___GFP_IO)
#define GFP_USER        (___GFP_RECLAIMABLE | ___GFP_IO | ___GFP_FS | ___GFP_HARDWALL)
#define GFP_DMA         ___GFP_DMA
#define GFP_DMA32       ___GFP_DMA32
#define GFP_HIGHUSER    (GFP_USER | ___GFP_HIGHMEM)
#define GFP_HIGHUSER_MOVABLE (GFP_HIGHUSER | ___GFP_MOVABLE | ___GFP_SKIP_KASAN_POISON)
#define GFP_TRANSHUGE_LIGHT ((GFP_HIGHUSER_MOVABLE | ___GFP_COMP | ___GFP_NOMEMALLOC | ___GFP_NOWARN) & ~___GFP_RECLAIMABLE)
#define GFP_TRANSHUGE   (GFP_TRANSHUGE_LIGHT | ___GFP_DIRECT_RECLAIM)

struct paf_event {
	unsigned long min;
	unsigned long low;
	unsigned long high;
	unsigned long present;
	unsigned long protection;
	int flag;
};

struct pr_event {
	unsigned long reclaim;
	unsigned long reclaimed;
	unsigned int unqueued_dirty;
	unsigned int congested;
	unsigned int writeback;
};

struct procstat_event {
	/*进程内存状态报告*/
	pid_t pid;
	long nvcsw;
	long nivcsw;
	long vsize;              //虚拟内存
	long size;               //物理内存
	long long rssanon;       //匿名页面
	long long rssfile;       //文件页面
	long long rssshmem;      //共享页面
	long long vswap;         //交换页面
	long long Hpages;        //hugetlbPages
	long Vdata;              //Private data segments
	long Vstk;               //User stack
	long long VPTE;
};

struct sysstat_event {
	/*系统内存状态报告*/
	unsigned long present;
	unsigned long anon_inactive; // 0
	unsigned long anon_active;	 // 1
	unsigned long file_inactive; // 2
	unsigned long file_active;	 // 3
	unsigned long unevictable;	 // 不可回收页面
	unsigned long slab_reclaimable;
	unsigned long slab_unreclaimable;
	unsigned long anon_isolated; // 匿名隔离页面
	unsigned long file_isolated; // 文件隔离页面

	unsigned long working_nodes; // 12
	unsigned long working_refault;
	unsigned long working_activate;
	unsigned long working_restore;
	unsigned long working_nodereclaim;

	unsigned long anon_mapped; // 17
	unsigned long file_mapped;

	unsigned long file_pages; // 19
	unsigned long file_dirty;
	unsigned long writeback;
	unsigned long writeback_temp;

	unsigned long shmem; // 共享内存23
	unsigned long shmem_thps;
	unsigned long pmdmapped;
	unsigned long anon_thps;
	unsigned long unstable_nfs;
	unsigned long vmscan_write;
	unsigned long vmscan_immediate;

	unsigned long diried;
	unsigned long written;
	unsigned long kernel_misc_reclaimable;
};

/*memleak.h*/
#define ALLOCS_MAX_ENTRIES 1000000
#define COMBINED_ALLOCS_MAX_ENTRIES 10240
 
struct alloc_info {
    __u64 size;
    int stack_id;
};

union combined_alloc_info {
    struct {
        __u64 total_size : 40;
        __u64 number_of_allocs : 24;
    };
    __u64 bits;
};

/* vmasnap.h */
// 记录插入操作的事件数据
struct insert_event_t {
    unsigned long long timestamp;
    unsigned long long duration;
    int inserted_to_list;
    int inserted_to_rb;
    int inserted_to_interval_tree;
    unsigned long long link_list_start_time;
    unsigned long long link_rb_start_time;
    unsigned long long interval_tree_start_time;
    unsigned long long link_list_duration;
    unsigned long long link_rb_duration;
    unsigned long long interval_tree_duration;
};

// 记录查找操作的事件数据
struct find_event_t {
    unsigned long long timestamp;
    unsigned long long duration;
    unsigned long addr;
    int vmacache_hit;
    unsigned long long rb_subtree_last;
    unsigned long long vm_start;
    unsigned long long vm_end;
};

/* drsnoop.h */
#define KALLSYMS_PATH "/proc/kallsyms"
#define VM_STAT_SYMBOL "vm_stat"
#define VM_ZONE_STAT_SYMBOL "vm_zone_stat"

#define NR_VM_ZONE_STAT_ITEMS 5
#define TASK_COMM_LEN 16
#define NR_FREE_PAGES 0

#define PAGE_SHIFT 12
#define K(x) ((x) << (PAGE_SHIFT - 10))

// Define structures used in maps and tracepoints
struct val_t {
    unsigned long long id;
    unsigned long long ts; // start time
    char name[TASK_COMM_LEN];
    unsigned long long vm_stat[NR_VM_ZONE_STAT_ITEMS];
};

struct data_t {
    unsigned long long id;
    unsigned long uid;
    unsigned long long nr_reclaimed;
    unsigned long long delta;
    unsigned long long ts;    // end time
    char name[TASK_COMM_LEN];
    unsigned long long vm_stat[NR_VM_ZONE_STAT_ITEMS];
};

/* OOM Killer Event */
struct event {
    uint32_t triggered_pid;    // 触发 OOM 的进程 PID
    uint32_t oomkill_pid;      // 被 OOM 杀死的进程 PID
    uint32_t mem_pages;        // 没有被杀掉的进程所使用的内存页数
    char comm[TASK_COMM_LEN];  // 被杀死进程的命令名
};

/* slabrate.h */
#define CACHE_NAME_SIZE 32

struct slabrate_info {
	char name[CACHE_NAME_SIZE];
	__u64 count;
	__u64 size;
};

#endif /* __MEM_WATCHER_H */

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
// author: albert_xuu@163.com zhangxy1016304@163.com zhangziheng0525@163.com


#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include <sys/sysinfo.h>
#include <sys/select.h>
#include <unistd.h> 
#include <bpf/bpf.h>
#include <stdlib.h>
#include <errno.h>
#include <string.h>
#include <linux/perf_event.h>
#include <asm/unistd.h>
#include "cpu_watcher_helper.h"
#include "sar.skel.h"
#include "cs_delay.skel.h"
#include "sc_delay.skel.h"
#include "preempt.skel.h"
#include "schedule_delay.skel.h"
#include "mq_delay.skel.h"
#include "mutrace.skel.h"

typedef long long unsigned int u64;
typedef unsigned int u32;



struct list_head {
	struct list_head *next;
	struct list_head *prev;
};
struct msg_msg {
	struct list_head m_list;
	long int m_type;
	size_t m_ts;
	struct msg_msgseg *next;
	void *security;
};

static struct env {
    int time;
    int period;
    bool enable_proc;
    bool SAR;
    bool CS_DELAY;
    bool SYSCALL_DELAY;
    bool PREEMPT;
    bool SCHEDULE_DELAY;
    bool MQ_DELAY;
    int freq;
    bool EWMA;
    int cycle;
	int MUTRACE;
} env = {
    .time = 0,
    .period = 1,
    .enable_proc = false,
    .SAR = false,
    .CS_DELAY = false,
    .SYSCALL_DELAY = false,
    .PREEMPT = false,
    .SCHEDULE_DELAY = false,
    .MQ_DELAY = false,
    .freq = 99,
    .EWMA = false,
    .cycle = 0,
	.MUTRACE = false,
};



struct cs_delay_bpf *cs_skel;
struct sar_bpf *sar_skel;
struct sc_delay_bpf *sc_skel;
struct preempt_bpf *preempt_skel;
struct schedule_delay_bpf *sd_skel;
struct mq_delay_bpf *mq_skel;
struct mutrace_bpf *mu_skel;

static int csmap_fd;
static int sarmap_fd;
struct sar_ctrl sar_ctrl= {};
static int scmap_fd;
static int preemptmap_fd;
static int schedulemap_fd;
struct schedule_ctrl sd_ctrl = {};
static int mqmap_fd;
static int mumap_fd;
struct mu_ctrl mu_ctrl = {};

//static int prev_watcher = 0;//上一个使用的工具，用于在切换使用功能时，打印不用功能的表头；

u64 softirq = 0;
u64 irqtime = 0;
u64 idle = 0;
u64 sched = 0;
u64 proc = 0;
unsigned long ktTime = 0;
unsigned long utTime = 0;
u64 tick_user = 0;


int sc_sum_time = 0 ;
int sc_max_time = 0 ;
int sc_min_time = SYSCALL_MIN_TIME ;
int sys_call_count = 0;
bool ifprint = 0;


int preempt_count = 0 ;
int sum_preemptTime = 0 ;
int preempt_start_print = 0 ;

/*设置传参*/
const char argp_program_doc[] = "cpu watcher is in use ....\n";
static const struct argp_option opts[] = {
    { "time", 't', "TIME-SEC", 0, "Max Running Time(0 for infinite)" },
    { "period", 'i', "INTERVAL", 0, "Period interval in seconds" },
    {"libbpf_sar", 's', 0, 0, "Print sar_info (the data of cpu)" },
    {"cs_delay", 'c', 0, 0, "Print cs_delay (the data of cpu)" },
    {"syscall_delay", 'S', 0, 0, "Print syscall_delay (the data of syscall)" },
    {"preempt_time", 'p', 0, 0, "Print preempt_time (the data of preempt_schedule)" },
    {"schedule_delay", 'd', 0, 0, "Print schedule_delay (the data of cpu)" },
    {"mq_delay", 'm', 0, 0, "Print mq_delay(the data of proc)" },
	{"mutrace", 'x', 0, 0, "Print mutrace data(the data of cpu)" },
    {"ewma", 'E',0,0,"dynamic filte the data"},
    {"cycle", 'T',"CYCLE",0,"Periods of the ewma"},
    { NULL, 'h', NULL, OPTION_HIDDEN, "Show the full help" },
    { 0 },
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    switch (key) {
        case 't':
            env.time = strtol(arg, NULL, 10);
            if (env.time) alarm(env.time);
            break;
        case 'i':
            env.period = strtol(arg, NULL, 10);
            break;
        case 's':
            env.SAR = true;
            break;
        case 'c':
            env.CS_DELAY = true;
            break;
        case 'S':
            env.SYSCALL_DELAY = true;
            break;
        case 'p':
            env.PREEMPT = true;
            break;
        case 'd':
            env.SCHEDULE_DELAY = true;
            break;
        case 'm':
            env.MQ_DELAY = true;
            break;
		case 'x':
			env.MUTRACE = true;
			break;
		case 'E':
			env.EWMA = true;
			break;
		case 'T':
			env.cycle = strtol(arg, NULL, 10);
			break;			
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }
    return 0;
}

static const struct argp argp = {
    .options = opts,
    .parser = parse_arg,
    .doc = argp_program_doc,
};



static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting=false;
bool syscall_start_print = false;

static void sig_handler(int sig)
{
	exiting = true;
}

/*perf_event*/
static int nr_cpus;
static int open_and_attach_perf_event(int freq, struct bpf_program *prog,
				struct bpf_link *links[])
{
	struct perf_event_attr attr = {
		.type = PERF_TYPE_SOFTWARE,
		.freq = 99,
		.sample_period = freq,
		.config = PERF_COUNT_SW_CPU_CLOCK,
	};
	int i, fd;
	for (i = 0; i < nr_cpus; i++) {
		fd = syscall(__NR_perf_event_open, &attr, -1, i, -1, 0);
		if (fd < 0) {
			/* Ignore CPU that is offline */
			if (errno == ENODEV)
				continue;
			fprintf(stderr, "failed to init perf sampling: %s\n",
				strerror(errno));
			return -1;
		}
		links[i] = bpf_program__attach_perf_event(prog, fd);
		if (libbpf_get_error(links[i])) {
			fprintf(stderr, "failed to attach perf event on cpu: "
				"%d\n", i);
			links[i] = NULL;
			close(fd);
			return -1;
		}
	}
	return 0;
}


u64 find_ksym(const char* target_symbol) {
    FILE *file = fopen("/proc/kallsyms", "r");
    if (file == NULL) {
        perror("Failed to open /proc/kallsyms");
        return 1;
    }
    char symbol_name[99];
    u64 symbol_address = 0;
    while (fscanf(file, "%llx %*c %s\n", &symbol_address, symbol_name) != EOF) {
        if (strcmp(symbol_name, target_symbol) == 0) {
            break;
        }
    }
    fclose(file);
    return symbol_address;
}

static int print_all()
{
	int err,key=0;
	err = bpf_map_lookup_elem(sarmap_fd, &key, &sar_ctrl);
	if (err < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err);
		return -1;
	}
	if(!sar_ctrl.sar_func)	return 0;
	if(sar_ctrl.prev_watcher == SAR_WACTHER + 1) {
		printf("  time       proc/s  cswch/s  runqlen  irqTime/%%  softirq/%%  idle/%%    kthread/%%    sysc/%%     utime/%%     sys/%% \n");
		sar_ctrl.prev_watcher = SAR_WACTHER + 2;
		err = bpf_map_update_elem(sarmap_fd, &key, &sar_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}
	}else if (sar_ctrl.prev_watcher == SAR_WACTHER){
		printf("  time    proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms  sys/ms \n");
		sar_ctrl.prev_watcher = SAR_WACTHER + 2;
		err = bpf_map_update_elem(sarmap_fd, &key, &sar_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}
	}
	int nprocs = get_nprocs();
	/*proc:*/
	int key_proc = 1;
	int err_proc, fd_proc = bpf_map__fd(sar_skel->maps.countMap);
	u64 total_forks;
	err_proc = bpf_map_lookup_elem(fd_proc, &key_proc, &total_forks); 
	if (err_proc < 0) {
		fprintf(stderr, "failed to lookup infos of total_forks: %d\n", err_proc);
		return -1;
	}
	u64 __proc;
	__proc = total_forks - proc;
	proc = total_forks;

	/*cswch:*/
	int key_cswch = 0;
	int err_cswch, fd_cswch = bpf_map__fd(sar_skel->maps.countMap);
	u64 sched_total;
	err_cswch = bpf_map_lookup_elem(fd_cswch, &key_cswch, &sched_total);
	if (err_cswch < 0) {
		fprintf(stderr, "failed to lookup infos of sched_total: %d\n", err_cswch);
		return -1;
	}
	u64 __sched;
	__sched = sched_total - sched;
	sched = sched_total;

	 /*runqlen:*/ 
	int key_runqlen = 0;
	int err_runqlen, fd_runqlen = bpf_map__fd(sar_skel->maps.runqlen);
	int runqlen;
	err_runqlen = bpf_map_lookup_elem(fd_runqlen, &key_runqlen, &runqlen);
	if (err_runqlen < 0) {
		fprintf(stderr, "failed to lookup infos of runqlen: %d\n", err_runqlen);
		return -1;
	}

	/*irqtime:*/
	int key_irqtime = 0;
	int err_irqtime, fd_irqtime = bpf_map__fd(sar_skel->maps.irq_Last_time);
	u64 __irqtime;
    __irqtime = irqtime;
	err_irqtime = bpf_map_lookup_elem(fd_irqtime, &key_irqtime, &irqtime);
	if (err_irqtime < 0) {
		fprintf(stderr, "failed to lookup infos of irqtime: %d\n", err_irqtime);
		return -1;
	}
    u64 dtairqtime = (irqtime - __irqtime);

	/*softirq:*/
	int key_softirq = 0;
	int err_softirq, fd_softirq = bpf_map__fd(sar_skel->maps.softirqLastTime);
	u64 __softirq;
    __softirq = softirq;
	err_softirq = bpf_map_lookup_elem(fd_softirq, &key_softirq, &softirq); 
	if (err_softirq < 0) {
		fprintf(stderr, "failed to lookup infos of softirq: %d\n", err_softirq);
		return -1;
	}
    u64 dtasoftirq = (softirq - __softirq);

	/*idle*/
	int key_idle = 0;
	int err_idle, fd_idle = bpf_map__fd(sar_skel->maps.idleLastTime);
	u64 __idle;
    __idle = idle;
	err_idle = bpf_map_lookup_elem(fd_idle, &key_idle, &idle);
	if (err_idle < 0) {
		fprintf(stderr, "failed to lookup infos of idle: %d\n", err_idle);
		return -1;
	}
    u64 dtaidle = (idle - __idle);	

	/*kthread*/
	int key_kthread = 0;
	int err_kthread, fd_kthread = bpf_map__fd(sar_skel->maps.kt_LastTime);
	unsigned long  _ktTime=0; 
	_ktTime = ktTime;
	err_kthread = bpf_map_lookup_elem(fd_kthread, &key_kthread,&ktTime);
	if (err_kthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_kthread);
		return -1;
	}
	unsigned long dtaKT = ktTime -_ktTime;

	/*Uthread*/
	int key_uthread = 0;
	int err_uthread, fd_uthread = bpf_map__fd(sar_skel->maps.ut_LastTime);
	unsigned long  _utTime=0; 
	_utTime = utTime;
	err_uthread = bpf_map_lookup_elem(fd_uthread, &key_uthread,&utTime);
	if (err_uthread < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err_uthread);
		return -1;
	}
	unsigned long dtaUT = utTime -_utTime;

	/*sys*/
	int key_sys = 0;
	int err_sys, fd_sys = bpf_map__fd(sar_skel->maps.tick_user);
	u64 __tick_user =0 ;// 用于存储从映射中查找到的值
	__tick_user = tick_user;
	//tick_user = 0;
	err_sys = bpf_map_lookup_elem(fd_sys, &key_sys, &tick_user);
	if (err_sys < 0) {
		fprintf(stderr, "failed to lookup infos of sys: %d\n", err_sys);
		return -1;
	}
	u64 dtaTickUser = tick_user - __tick_user;
	u64 dtaUTRaw = dtaTickUser/(99.0000) * 1000000000; 
	u64 dtaSysc = abs(dtaUT - dtaUTRaw);
	u64 dtaSys = dtaKT + dtaSysc ;

	if(env.enable_proc){
		time_t now = time(NULL);
		struct tm *localTime = localtime(&now);
		if (sar_ctrl.percent == true){
			printf("%02d:%02d:%02d %8llu %8llu %6d  ",localTime->tm_hour, localTime->tm_min, localTime->tm_sec,__proc, __sched, runqlen);
			// 大于百分之60的标红输出
			double values[7] = {
				(double)dtairqtime / 10000000 / nprocs / env.period,
				(double)dtasoftirq / 10000000 / nprocs / env.period,
				(double)dtaidle / 10000000 / nprocs / env.period,
				(double)dtaKT / 10000000 / nprocs / env.period,
				(double)dtaSysc / 10000000 / nprocs / env.period,
				(double)dtaUTRaw / 10000000 / nprocs / env.period,
				(double)dtaSys / 10000000 / nprocs / env.period
			};
			for (int i = 0; i < 7; i++) {
				if (values[i] > 60.0) {
					printf("\033[1;31m");  // 设置为红色
				}
				printf("%10.2f ", values[i]);
				printf("\033[0m");  // 重置为默认颜色
			}
			printf("\n");
		}else{printf("%02d:%02d:%02d %8llu %8llu %6d %8llu %10llu  %8llu  %10lu  %8llu %8llu %8llu\n",
				localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
				__proc,__sched,runqlen,dtairqtime/1000,dtasoftirq/1000,dtaidle/1000000,
				dtaKT/1000,dtaSysc / 1000000,dtaUTRaw/1000000,dtaSys / 1000000);}
	}
	else{
		env.enable_proc = true;
	}
    return 0;
}

int count[25]={0} , cs_flag=0;//定义一个count数组，用于汇总schedul()调度时间，以log2(时间间隔)为统计依据；
static int handle_event(void *ctx, void *data,unsigned long data_sz)
{
	const struct event *e = data;
	printf("t1:%llu  t2:%llu  delay:%llu\n",e->t1,e->t2,e->delay);
	int dly=(int)(e->delay),i=0;
	while (dly > 1){
		dly /= 2;
		i ++;
	}
	count[i]++;
	if(!cs_flag) 
		cs_flag = 1;
	return 0;
}
static int print_hstgram(int i,int max,int per_len)
{
	int cnt=count[i];
	if(per_len==1){
		while(cnt>0){
			printf("*");
			cnt--;
		}
	}
	while(cnt-per_len>=0){
		printf("*");
		cnt-=per_len;
	}
	printf("\n");
	return per_len;
}
double my_pow(int n,int k)//实现pow函数
{
	if (k > 0)
		return n * my_pow(n, k - 1);
	else if (k == 0)
		return 1;
	else
		return 1.0 / my_pow(n, -k);
}
static void histogram()
{
	int log10[15]={0},max=0,per_len=1;
	for(int i=0;i<10;i++){
		int tmp=count[i],cnt=0;
		while (tmp >= 10){
			tmp /= 10;
			cnt ++;
		}
		log10[cnt]++;
	}

	for(int i=0;i<10;i++){//找log10里的最大值；
		if(max<log10[i])
			max=i;
	}

	while(max>0){
		per_len *=10 ;
		max--;
	}

	time_t now = time(NULL);
	struct tm *localTime = localtime(&now);
	printf("\nTime : %02d:%02d:%02d \n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
	printf("%-24s \t%-12s \t%-12s \n","cs_delay","Count","Distribution");
	printf("%d\t=>\t%-8d \t%-12d \t|",0,1,count[0]);
	print_hstgram(0,max,per_len);
	printf("%d\t=>\t%-8d \t%-12d \t|",2,3,count[1]);
	print_hstgram(1,max,per_len);
	for(int i=2;i<20;i++){
		printf("%d\t=>\t%-8d \t%-12d \t|",(int)my_pow(2,i),(int)my_pow(2,(i+1))-1,count[i]);
		print_hstgram(i,max,per_len);
	}
	printf("per_len = %d\n",per_len);
}


struct ewma_info ewma_syscall_delay = {};
static int syscall_delay_print(void *ctx, void *data,unsigned long data_sz)
{
	int err,key = 0;
	struct sc_ctrl sc_ctrl ={};

	err = bpf_map_lookup_elem(scmap_fd,&key,&sc_ctrl);
	if (err < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err);
		return -1;
	}
	if(!sc_ctrl.sc_func)	return 0;

	const struct syscall_events *e = data;
	if(e->delay<0||e->delay>1000000) return 0;
	time_t now = time(NULL);// 获取当前时间
	struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构	

	if(env.EWMA==0){
		printf("%02d:%02d:%02d     %-8u %-15lld %-15lld\n",
			localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
			e->pid,e->syscall_id,e->delay);
	}
	else{
		ewma_syscall_delay.cycle = env.cycle;
		if(dynamic_filter(&ewma_syscall_delay,e->delay)){
			printf("%02d:%02d:%02d     %-8u %-15lld %-15lld\n",
					localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
					e->pid,e->syscall_id,e->delay);
		}
	}

	return 0;
}


//抢占时间输出
static int preempt_print(void *ctx, void *data, unsigned long data_sz)
{
    const struct preempt_event *e = data;
    printf("%-16s %-7d %-7d %-11llu\n", e->comm, e->prev_pid, e->next_pid, e->duration);
    preempt_count++;
    sum_preemptTime += e->duration;
    return 0;
}

static int attach(struct mutrace_bpf *mu_skel)
{
	int err;
	ATTACH_UPROBE_CHECKED(mu_skel,pthread_mutex_lock,pthread_mutex_lock);
	ATTACH_UPROBE_CHECKED(mu_skel,__pthread_mutex_trylock,__pthread_mutex_trylock);
	ATTACH_URETPROBE_CHECKED(mu_skel,__pthread_mutex_trylock,ret_pthread_mutex_trylock);
	ATTACH_UPROBE_CHECKED(mu_skel,pthread_mutex_unlock,pthread_mutex_unlock);
	err = mutrace_bpf__attach(mu_skel);
	CHECK_ERR(err, "Failed to attach BPF skeleton");	
	return 0;

}


//mutrace输出
static int mutrace_print(void *ctx, void *data, unsigned long data_sz) {
	int err,key = 0;
	err = bpf_map_lookup_elem(mumap_fd,&key,&mu_ctrl);
	if (err < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err);
		return -1;
	}
	if(!mu_ctrl.mu_func)	return 0;
	if(mu_ctrl.prev_watcher == MUTEX_WATCHER ){
		printf("%s\n","    lock_ptr               owner_pid       owner_comm       owner_prio   contender_pid     contender_comm  contender_prio   contender_count");
		mu_ctrl.prev_watcher = MUTEX_WATCHER + 9;//打印表头功能关
		err = bpf_map_update_elem(mumap_fd, &key, &mu_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}
	}else if (mu_ctrl.prev_watcher == MUTEX_WATCHER +1) {
		printf("%s\n","    lock_ptr              locked_total       locked_max     contended_total       count     last_owner        last_owmer_name");
		mu_ctrl.prev_watcher = MUTEX_WATCHER + 9;//打印表头功能关
		err = bpf_map_update_elem(mumap_fd, &key, &mu_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}
	}else if (mu_ctrl.prev_watcher == MUTEX_WATCHER +2) {
		printf("%s\n","    lock_ptr              locked_total       locked_max     contended_total       count     last_owner        last_owmer_name");
		mu_ctrl.prev_watcher = MUTEX_WATCHER + 9;//打印表头功能关
		err = bpf_map_update_elem(mumap_fd, &key, &mu_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}
	}
	if(!mu_ctrl.mutex_detail&& (!mu_ctrl.umutex)){
		const struct mutex_contention_event *e = data;
		if (e->owner_pid == 0 || e->contender_pid == 0||e->owner_pid == 1) {
			return 0;
		}
		// 增加锁争用次数
		increment_lock_count(e->ptr);
		uint64_t contention_count = get_lock_count(e->ptr);
		printf("%15llu %15d %15s %15d %15d %15s %15d %15ld\n", e->ptr, e->owner_pid, e->owner_name, e->owner_prio,e->contender_pid, e->contender_name, e->contender_prio,contention_count);
	}
    return 0;
}

static int kmutex_detail() {
    int fd = bpf_map__fd(mu_skel->maps.kmutex_info_map);
    u64 key, next_key;
    struct mutex_info info;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        int err = bpf_map_lookup_elem(fd, &next_key, &info);
        if (err == 0 && info.contended_total != 0) { // 添加过滤条件
            printf(" %15llu %15lluns %15lluns %15lluns %15d %15d %20s\n",
                   next_key, info.locked_total, info.locked_max, info.contended_total, info.count, info.last_owner, info.last_name);
        }
        key = next_key;
    }
    return 0;
}

static int umutex_detail() {
    int fd = bpf_map__fd(mu_skel->maps.umutex_info_map);
    u64 key, next_key;
    struct mutex_info info;
    while (bpf_map_get_next_key(fd, &key, &next_key) == 0) {
        int err = bpf_map_lookup_elem(fd, &next_key, &info);
        if (err == 0 && info.contended_total != 0) { // 添加过滤条件
            printf(" %15llu %15llums %15llums %15llums %15d %15d %20s\n",
                   next_key, info.locked_total/1000000, info.locked_max/1000000, info.contended_total/1000000, info.count, info.last_owner, info.last_name);
        }
        key = next_key;
    }
    return 0;
}

static int schedule_print()
{
    int err,key = 0;
	err = bpf_map_lookup_elem(schedulemap_fd,&key,&sd_ctrl);
	if (err < 0) {
		fprintf(stderr, "failed to lookup infos: %d\n", err);
		return -1;
	}
	if(!sd_ctrl.schedule_func)	return 0;	

	if(sd_ctrl.prev_watcher == SCHEDULE_WACTHER ){
		printf("%-8s %s\n",  "  TIME ", "avg_delay/μs     max_delay/μs    max_proc_name    min_delay/μs   min_proc_name");
		sd_ctrl.prev_watcher = SCHEDULE_WACTHER + 9;//打印表头功能关
		err = bpf_map_update_elem(schedulemap_fd, &key, &sd_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}
	}
	else if(sd_ctrl.prev_watcher == SCHEDULE_WACTHER +1){
			// printf("sd_ctrl.prev_watcher = %d\n",sd_ctrl.prev_watcher);
			printf("调度延时大于%dms的进程:\n",sd_ctrl.min_us/1000);
			printf("%s\n","pid        COMM                   schedule_delay/us");
		sd_ctrl.prev_watcher = SCHEDULE_WACTHER + 9;//打印表头功能关.
		err = bpf_map_update_elem(schedulemap_fd, &key, &sd_ctrl, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
		}		
	}

	if(!sd_ctrl.min_us_set){
		struct sum_schedule info;
		int err, fd = bpf_map__fd(sd_skel->maps.sys_schedule);
		time_t now = time(NULL);
		struct tm *localTime = localtime(&now);
		int hour = localTime->tm_hour;
		int min = localTime->tm_min;
		int sec = localTime->tm_sec;
		unsigned long long avg_delay; 
		err = bpf_map_lookup_elem(fd, &key, &info);
		if (err < 0) {
			fprintf(stderr, "failed to lookup infos: %d\n", err);
			return -1;
		}
		avg_delay = info.sum_delay / info.sum_count;
		if (!ifprint) {
			ifprint=1;
		}else{
			printf("%02d:%02d:%02d  %-15lf %-15lf  %10s %15lf  %15s\n",
			hour, min, sec, avg_delay / 1000.0, info.max_delay / 1000.0,info.proc_name_max,info.min_delay / 1000.0,info.proc_name_min);
		}
	}
	else{
		struct proc_schedule info;
		struct proc_id id_key;
		struct proc_history prev_info;
        int key = 0;  
        int err, fd1 = bpf_map__fd(sd_skel->maps.threshold_schedule),fd2 = bpf_map__fd(sd_skel->maps.proc_histories);
        err = bpf_map_lookup_elem(fd1, &key, &info);
        if (err < 0) {
            fprintf(stderr, "failed to lookup infos: %d\n", err);
            return -1;
        }
        if (info.delay / 1000 > sd_ctrl.min_us&&info.id.pid!=0) {
			id_key.pid = info.id.pid;
    		id_key.cpu_id = info.id.cpu_id;
			err = bpf_map_lookup_elem(fd2, &id_key, &prev_info);
			if (err < 0) {
				fprintf(stderr, "Failed to lookup proc_histories with PID %d and CPU ID %d: %d\n", id_key.pid, id_key.cpu_id, err);
				return -1;
			}
            if (!entry_exists(info.id.pid, info.proc_name, info.delay / 1000)) {
                printf("%-10d %-16s %15lld", info.id.pid, info.proc_name, info.delay / 1000);
                add_entry(info.id.pid, info.proc_name, info.delay / 1000);
				for (int i = 0; i < 2; i++) {
					if (prev_info.last[i].pid != 0) {
						printf("          Previous Process %d: PID=%-10d Name=%-16s ", i+1, prev_info.last[i].pid, prev_info.last[i].comm);
					}
				}
				printf("\n"); 
            }

        }
	}

    return 0;
}


static int mq_event(void *ctx, void *data,unsigned long data_sz)
{
	time_t now = time(NULL);// 获取当前时间
	struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
	const struct mq_events *e = data;
	float send_delay,rcv_delay,delay;
	if(!e->send_enter_time || !e->send_exit_time || !e->rcv_enter_time || !e->rcv_exit_time) {
		printf("erro!\n");
		return 0;
	}
	send_delay = (e->send_exit_time - e->send_enter_time)/1000000.0;
	rcv_delay = (e->rcv_exit_time - e->rcv_enter_time)/1000000.0;	
	if(e->send_enter_time < e->rcv_enter_time){
		delay = (e->rcv_exit_time - e->send_enter_time)/1000000.0;
	}else{
		delay = (e->rcv_exit_time - e->send_enter_time)/1000000.0 + send_delay + rcv_delay;		
	}
	printf("%02d:%02d:%02d   %-8u %-8u %-8u \t%-16llu %-16llu %-16llu %-16llu\t%-15.5f %-15.5f %-15.5f\n",
		localTime->tm_hour, localTime->tm_min, localTime->tm_sec,
		e->mqdes,e->send_pid,e->rcv_pid,
		e->send_enter_time,e->send_exit_time,e->rcv_enter_time,e->rcv_exit_time,
		send_delay,rcv_delay,delay);

	return 0;
}


int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct bpf_map *cs_ctrl_map = NULL;
	struct bpf_map *sar_ctrl_map = NULL;
	struct bpf_map *sc_ctrl_map = NULL;
	struct bpf_map *preempt_ctrl_map = NULL;
	struct bpf_map *schedule_ctrl_map = NULL;
	struct bpf_map *mq_ctrl_map = NULL;
	struct bpf_map *mu_ctrl_map = NULL;
	int key = 0;
	int err;
	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	const char* symbol_name = "total_forks";
	struct bpf_link *links[MAX_CPU_NR] = {};
	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	libbpf_set_print(libbpf_print_fn);
	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	nr_cpus = libbpf_num_possible_cpus();
	if (nr_cpus < 0) {
		fprintf(stderr, "failed to get # of possible cpus: '%s'!\n",
			strerror(-nr_cpus));
		return 1;
	}
	if (nr_cpus > MAX_CPU_NR) {
		fprintf(stderr, "the number of cpu cores is too big, please "
			"increase MAX_CPU_NR's value and recompile");
		return 1;
	}


	if (env.CS_DELAY)
	{
		/* Load and verify BPF application */
		cs_skel = cs_delay_bpf__open();
		if (!cs_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		/* Load & verify BPF programs */
		err = cs_delay_bpf__load(cs_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto cs_delay_cleanup;
		}

		err = common_pin_map(&cs_ctrl_map,cs_skel->obj,"cs_ctrl_map",cs_ctrl_path);
		if(err < 0){
			goto cs_delay_cleanup;
		}
		csmap_fd = bpf_map__fd(cs_ctrl_map);
		struct cs_ctrl init_value = {false,CS_WACTHER};
		err = bpf_map_update_elem(csmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto cs_delay_cleanup;
		}

		/* Attach tracepoints */
		err = cs_delay_bpf__attach(cs_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto cs_delay_cleanup;
		}
		rb = ring_buffer__new(bpf_map__fd(cs_skel->maps.rb), handle_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto cs_delay_cleanup;
		}
	}else if (env.PREEMPT) {
		preempt_skel = preempt_bpf__open();
		if (!preempt_skel) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		err = preempt_bpf__load(preempt_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto preempt_cleanup;
		}

		err = common_pin_map(&preempt_ctrl_map,preempt_skel->obj,"preempt_ctrl_map",preempt_ctrl_path);
		if(err < 0){
			goto preempt_cleanup;
		}
		preemptmap_fd = bpf_map__fd(preempt_ctrl_map);
		struct preempt_ctrl init_value = {false,PREEMPT_WACTHER};
		err = bpf_map_update_elem(preemptmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto preempt_cleanup;
		}
		err = preempt_bpf__attach(preempt_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto preempt_cleanup;
		}

		rb = ring_buffer__new(bpf_map__fd(preempt_skel->maps.rb), preempt_print, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto preempt_cleanup;
		}
	}else if (env.SYSCALL_DELAY){
		/* Load and verify BPF application */
		sc_skel = sc_delay_bpf__open();
		if (!sc_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		/* Load & verify BPF programs */
		err = sc_delay_bpf__load(sc_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto sc_delay_cleanup;
		}
		err = common_pin_map(&sc_ctrl_map,sc_skel->obj,"sc_ctrl_map",sc_ctrl_path);
		if(err < 0){
			goto sc_delay_cleanup;
		}
		scmap_fd = bpf_map__fd(sc_ctrl_map);
		struct sc_ctrl init_value = {false,SC_WACTHER};
		err = bpf_map_update_elem(scmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto sc_delay_cleanup;
		}
		/* Attach tracepoints */
		err = sc_delay_bpf__attach(sc_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto sc_delay_cleanup;
		}
		printf("%-8s   %-8s   %-15s %-15s\n","Time","Pid","syscall_id","delay/ms");
		rb = ring_buffer__new(bpf_map__fd(sc_skel->maps.rb), syscall_delay_print, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto sc_delay_cleanup;		
		}


	}else if(env.SCHEDULE_DELAY){

	
		sd_skel = schedule_delay_bpf__open();
		if (!sd_skel) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		err = schedule_delay_bpf__load(sd_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto schedule_cleanup;
		}
		err = common_pin_map(&schedule_ctrl_map,sd_skel->obj,"schedule_ctrl_map",schedule_ctrl_path);
		if(err < 0){
			goto schedule_cleanup;
		}
		schedulemap_fd = bpf_map__fd(schedule_ctrl_map);
		struct schedule_ctrl init_value = {false,false,10000,SCHEDULE_WACTHER};

		err = bpf_map_update_elem(schedulemap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto schedule_cleanup;
		}
		err = schedule_delay_bpf__attach(sd_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto schedule_cleanup;
		}
	}else if (env.SAR){
		/* Load and verify BPF application */
		sar_skel = sar_bpf__open();
		if (!sar_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		sar_skel->rodata->forks_addr = (u64)find_ksym(symbol_name);
		/* Load & verify BPF programs */
		err = sar_bpf__load(sar_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto sar_cleanup;
		}

		/*perf_event加载*/
		err = open_and_attach_perf_event(env.freq, sar_skel->progs.tick_update, links);
		if (err)
			goto sar_cleanup;

		err = common_pin_map(&sar_ctrl_map,sar_skel->obj,"sar_ctrl_map",sar_ctrl_path);
		if(err < 0){
			goto sar_cleanup;
		}
		sarmap_fd = bpf_map__fd(sar_ctrl_map);
		struct sar_ctrl init_value = {false,false,SAR_WACTHER};
		err = bpf_map_update_elem(sarmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto sar_cleanup;
		}

		err = sar_bpf__attach(sar_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto sar_cleanup;
		}
	}else if(env.MQ_DELAY){
		/* Load and verify BPF application */
		mq_skel = mq_delay_bpf__open();
		if (!mq_skel)
		{
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}
		/* Load & verify BPF programs */
		err = mq_delay_bpf__load(mq_skel);
		if (err)
		{
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto mq_delay_cleanup;
		}

		err = common_pin_map(&mq_ctrl_map,mq_skel->obj,"mq_ctrl_map",mq_ctrl_path);
		if(err < 0){
			goto mq_delay_cleanup;
		}
		mqmap_fd = bpf_map__fd(mq_ctrl_map);
		struct mq_ctrl init_value = {false,MQ_WACTHER};
		err = bpf_map_update_elem(mqmap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto mq_delay_cleanup;
		}

		/* Attach tracepoints */
		err = mq_delay_bpf__attach(mq_skel);
		if (err)
		{
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto mq_delay_cleanup;
		}
		printf("%-8s   %-8s %-8s %-8s \t%-16s %-16s %-16s %-16s\t%-15s %-15s %-15s\n","Time","Mqdes","SND_PID","RCV_PID","SND_Enter","SND_EXit","RCV_Enter","RCV_EXit","SND_Delay/ms","RCV_Delay/ms","Delay/ms");		
		rb = ring_buffer__new(bpf_map__fd(mq_skel->maps.rb), mq_event, NULL, NULL);	//ring_buffer__new() API，允许在不使用额外选项数据结构下指定回调
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto mq_delay_cleanup;
		}
	}else if (env.MUTRACE) {
		mu_skel = mutrace_bpf__open();
		if (!mu_skel) {
			fprintf(stderr, "Failed to open and load BPF skeleton\n");
			return 1;
		}

		err = mutrace_bpf__load(mu_skel);
		if (err) {
			fprintf(stderr, "Failed to load and verify BPF skeleton\n");
			goto mutrace_cleanup;
		}
		err = common_pin_map(&mu_ctrl_map,mu_skel->obj,"mu_ctrl_map",mu_ctrl_path);
		if(err < 0){
			goto mutrace_cleanup;
		}
		mumap_fd = bpf_map__fd(mu_ctrl_map);
		struct mu_ctrl init_value = {false,false,false,MUTEX_WATCHER};

		err = bpf_map_update_elem(mumap_fd, &key, &init_value, 0);
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto mutrace_cleanup;
		}
		//ctrl
		if(err < 0){
			goto mutrace_cleanup;
		}
		//ctrl
		if(err < 0){
			fprintf(stderr, "Failed to update elem\n");
			goto mutrace_cleanup;
		}
		err = attach(mu_skel);
		if (err) {
			fprintf(stderr, "Failed to attach BPF skeleton\n");
			goto mutrace_cleanup;
		}

		rb = ring_buffer__new(bpf_map__fd(mu_skel->maps.rb), mutrace_print, NULL, NULL);
		if (!rb) {
			err = -1;
			fprintf(stderr, "Failed to create ring buffer\n");
			goto mutrace_cleanup;
		}
	}
	while (!exiting) {
		if(env.SAR){
			sleep(env.period);
			err = print_all();
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
		}
        else if(env.CS_DELAY){
			sleep(1);
			err = ring_buffer__poll(rb, 1000 /* timeout, s */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
    		struct cs_ctrl *cs_ctrl;
			int ctrl_key = 0 ;
			if(cs_flag){
				histogram();
			}
		}
		else if(env.SYSCALL_DELAY){
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);		//ring_buffer__poll(),轮询打开ringbuf缓冲区。如果有事件，handle_event函数会执行	
			/* Ctrl-C will cause -EINTR */
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling perf buffer: %d\n", err);
				break;
			}
			// time_t now = time(NULL);// 获取当前时间
			// struct tm *localTime = localtime(&now);// 将时间转换为本地时间结构
			// printf("\n\nTime: %02d:%02d:%02d\n",localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
			// printf("----------------------------------------------------------------------------------------------------------\n");
			// sleep(1);			
		}
		else if (env.PREEMPT) {
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling perf buffer: %d\n", err);
				break;
			}
			time_t now = time(NULL);
			struct tm *localTime = localtime(&now);
			if (!preempt_start_print) {
				preempt_start_print = 1;
			} else {
				printf("----------------------------------------------------------------------------------------------------------\n");
				printf("\nAverage_preempt_Time: %8d ns\n", sum_preemptTime / preempt_count);
			}
			printf("\nTime: %02d:%02d:%02d\n", localTime->tm_hour, localTime->tm_min, localTime->tm_sec);
			printf("%-12s %-8s %-8s %11s\n", "COMM", "prev_pid", "next_pid", "duration_ns");
			preempt_count = 0;
			sum_preemptTime = 0;
			sleep(2);
		}
		else if (env.SCHEDULE_DELAY){
			err = schedule_print();
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				break;
			}
			if(env.SCHEDULE_DELAY&&!sd_ctrl.min_us_set){
				sleep(1);
			}	
		}
        else if(env.MQ_DELAY){
			err = ring_buffer__poll(rb, 1000 /* timeout, s */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
        	    printf("Error polling perf buffer: %d\n", err);
				break;
			}
		}
		else if (env.MUTRACE) {
			err = ring_buffer__poll(rb, 100 /* timeout, ms */);
			if (err == -EINTR) {
				err = 0;
				break;
			}
			if (err < 0) {
				printf("Error polling perf buffer: %d\n", err);
				break;
			}
			if(env.MUTRACE&&mu_ctrl.mutex_detail){
				err = kmutex_detail();
				sleep(1);
				printf("-------------------------------------------------------------\n");
			}else if(env.MUTRACE&&mu_ctrl.umutex){
				err = umutex_detail();
				sleep(1);
				printf("-------------------------------------------------------------\n");
			}

		}
		else {
			printf("正在开发中......\n-c	打印cs_delay:\t对内核函数schedule()的执行时长进行测试;\n-s	sar工具;\n-y	打印sc_delay:\t系统调用运行延迟进行检测; \n-p	打印preempt_time:\t对抢占调度时间输出;\n");
			break;
		}
	}

cs_delay_cleanup:
	bpf_map__unpin(cs_ctrl_map, cs_ctrl_path);
	ring_buffer__free(rb);
	cs_delay_bpf__destroy(cs_skel);
	return err < 0 ? -err : 0;

sar_cleanup:
	bpf_map__unpin(sar_ctrl_map, sar_ctrl_path);
	sar_bpf__destroy(sar_skel);
	return err < 0 ? -err : 0;

sc_delay_cleanup:
	bpf_map__unpin(sc_ctrl_map, sc_ctrl_path);
	ring_buffer__free(rb);
	sc_delay_bpf__destroy(sc_skel);
	return err < 0 ? -err : 0;

preempt_cleanup:
	bpf_map__unpin(preempt_ctrl_map, preempt_ctrl_path);	
	ring_buffer__free(rb);
	preempt_bpf__destroy(preempt_skel);
	return err < 0 ? -err : 0;

schedule_cleanup:
	bpf_map__unpin(schedule_ctrl_map, schedule_ctrl_path);
	schedule_delay_bpf__destroy(sd_skel);
	return err < 0 ? -err : 0;

mq_delay_cleanup:
	bpf_map__unpin(mq_ctrl_map, mq_ctrl_path);
	ring_buffer__free(rb);
	mq_delay_bpf__destroy(mq_skel);
	return err < 0 ? -err : 0;

mutrace_cleanup:
	ring_buffer__free(rb);
	mutrace_bpf__destroy(mu_skel);
	return err < 0 ? -err : 0;
}

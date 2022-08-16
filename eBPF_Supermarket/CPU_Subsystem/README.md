## CPU子系统指标捕获例程

### 0. 介绍

本目录是由一系列捕获CPU子系统指标（主要是调度指标）的例程组成的。

bpftrace_application 是一些 Bpftrace 构建的例程，需要预装 bpftrace，其特点是代码简单，能很快上手，缺点是不能支撑高复杂性的 eBPF 应用。

其余以 go_ 开头的各个文件夹是用 go语言 + eBPF 构建的eBPF例程，使用了开源的cilium/eBPF库，可以支撑高复杂性、模块化的 eBPF 应用。

### 1. 准备工作

环境：Ubuntu 20.04, 内核版本 5.13.0-30-generic

注：由于 eBPF 的 kprobe 逻辑与内核数据结构定义高度相关，而现在 BTF 的应用（可消除不同内核版本间数据结构的不兼容）还不是很成熟，因此在使用此例程前，需首先适配内核版本。

软件：

* go SDK（安装cilium库）

* llvm
* bpftrace

### 2. 应用实例介绍

#### 2.1 bpftrace应用

**runqlen_percpu.c**: 打印每个CPU的runqlen分布情况。使用了kprobe，挂载点是update_rq_clock.

**runqlen_se.c**: 打印每个CPU的 CFS 调度的队列长度分布情况。使用了kprobe，挂载点是update_rq_clock.

挂载点说明：update_rq_clock() 函数在内核中的作用是用来更新rq主运行队列的运行时间的，不涉及到具体的某种调度策略（如CFS），因而能够得到通用的调度数据。执行栈是内核的时钟中断函数->update_process_time()->scheduler_tick()->update_rq_clock()，使用update_rq_clock()的优势在于该函数的参数内携带了rq结构体，可直接查阅运行队列rq的数据。执行频率为800~1000Hz，较低，不会影响到内核的运行性能。

使用方法：

```shell
cd bpftrace_application
sudo ./runqlen_percpu.c
```

#### 2.2 go_* 应用

**go_migrate_info**: 以事件的形式打印CPU间进程迁移的情况。每次迁移都打印一条信息，包括时间戳、进程pid、源CPU、目标CPU、进程优先级。这可用于后期前端开发可视化地显示进程迁移情况。

**go_schedule**: 打印每个CPU的runqlen分布情况。

**go_schedule_uninterruptible**: 打印整个kernel所有处于**不可打断阻塞状态**的任务的数目。

**go_switch_info**：每1s打印现有所有进程的进程切换数。

**go_sar**：模仿sar工具，使用eBPF实现其功能。

使用方法：

```shell
cd go_schedule
cd schedule
./run.sh
```

如果没有run.sh脚本，那么，需要手动编译执行以下命令：

```shell
cd go_migrate_info
cd sched_migrate
go generate
sudo go run .
```

**go_sar说明**: 我预先的计划是使用go+cilium来实现sar的功能，但是由于cilium ebpf未实现perf事件挂载点，所以无法实现BPF程序的定时采样，目前我转而使用BCC实现sar的剩余功能。若之后cilium ebpf实现了perf事件挂载点，此程序有可能会更新。目前的效果如下（定时打印）：

```txt
15:35:05 proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms
15:35:06     17      920        3         260        4389        1
15:35:07      1      319        3          82        2039        1
15:35:08      0      508        3         218        2592        0
15:35:09     13      434        2          55        2368        1
15:35:10     11      413        2         105        1906        0
15:35:11      0      370        2          68        1638        1
15:35:12      0      260        2          36        1263        0
15:35:13      0      286        2          59        1450        1
```

其中idle表项目前是不准的，之后会修改。

#### 2.3 BCC_sar

BCC_sar是使用BCC构建的模仿sar进行动态CPU指标监测的程序，其位置在BCC_sar/下。此基于BCC的构建是由之前基于go+cilium的实现转化而来的，用于解决一些go+cilium组合无法解决的问题。目前，此程序能捕获sar工具能捕获的大多数参数。

```txt
  time   proc/s  cswch/s  runqlen  irqTime/us  softirq/us  idle/ms  kthread/us  sysc/ms  utime/ms
15:40:52     18      616        2          86        3426     2274        1470      108        64
15:40:53      7      394        2          83        2034     1982        2348        7        10
15:40:54      0      259        1          41        1336     1984         821        2         6
15:40:55      0      357        1         352        4370     1860        8662       90        38
15:40:56      0      324        1          48        1606     1963        1012        3         6
15:40:57     11      404        1          67        2064     1936        1859       23        18
15:40:58      7      361        1          86        1758     1954        1102        5         9
15:40:59      0      313        1          84        2023     1994        1868        3         6
15:41:00      0      280        1          61        1662     1987        1121        3         7
15:41:01      0      278        1          77        1654     1958        1931       13         6
```

对上述参数的解释：

* proc/s: 每秒创建的进程数。此数值是通过fork数来统计的。
* cswch/s: 每秒上下文切换数。
* runqlen：各cpu的运行队列总长度。
* irqtime：CPU响应irq中断所占用的时间。注意这是所有CPU时间的叠加，平均到每个CPU应该除以CPU个数。
* softirq: CPU执行**softirq**所占用的时间，是所有CPU的叠加。softirq：irq中断的下半部，优先级比irq低，可被irq抢占。
* idle: CPU处于空闲状态的时间，所有CPU的叠加。
* kthread: CPU执行**内核线程**所占用的时间，所有CPU的叠加。不包括IDLE-0进程，因为此进程只执行空闲指令使CPU闲置。
* sysc: CPU执行**用户程序系统调用**(syscall)所占用的时间，所有CPU的叠加。
* utime：CPU执行**普通用户进程**时，花在用户态的时间，是所有CPU的叠加。

实现的方式分为3类：

第一类：使用kprobe捕获内核函数的参数，从参数中提取有效信息。如runqlen就是从update_rq_clock的rq参数中提取队列长度信息的。

第二类：使用tracepoint捕获特定状态的开始和结束，计算持续时间。如idle就是利用CPU进出空闲状态的tracepoint来实现功能的。

第三类：获取内核全局变量，直接从内核全局变量读取信息。如proc/s就是通过直接读取total_forks内核全局变量来计算每秒产生进程数的。由于bpf_kallsyms_lookup_name这个helper function不能使用，因此内核符号地址是预先在用户空间从/proc/kallsyms中读取然后传递到bpf程序中的。

由于实际场景的复杂性，因此有些参数实际上是综合使用多种方法实现的。

#### 2.4 实用工具

tools/TracepointHelp.sh：用于查看tracepoint列表和特定tracepoint接收参数类型等。其优点是简化了tracepoint的查询过程。

目前支持的功能如下：

1. 打印tracepoint列表：

   ```shell
   ./TracepointHelp.sh -l
   ```

2. 打印特定tracepoint的参数：

   以sched:sched_switch为例，-d后第一个参数是tracepoint所在的类别名，第二个参数是tracepoint的名称。

   ```shell
   ./TracepointHelp.sh -d sched sched_switch
   ```

   输出结果为tracepoint参数的格式信息。在BPF的tracepoint插桩点上，这些参数会以**结构体**的指针的形式输入进来，所以需要预先定义结构体。

   ```txt
   [sudo] zrp 的密码： 
   name: sched_switch
   ID: 316
   format:
           field:unsigned short common_type;       offset:0;       size:2; signed:0;
           field:unsigned char common_flags;       offset:2;       size:1; signed:0;
           field:unsigned char common_preempt_count;       offset:3;       size:1; signed:0;
           field:int common_pid;   offset:4;       size:4; signed:1;
   
           field:char prev_comm[16];       offset:8;       size:16;        signed:1;
           field:pid_t prev_pid;   offset:24;      size:4; signed:1;
           field:int prev_prio;    offset:28;      size:4; signed:1;
           field:long prev_state;  offset:32;      size:8; signed:1;
           field:char next_comm[16];       offset:40;      size:16;        signed:1;
           field:pid_t next_pid;   offset:56;      size:4; signed:1;
           field:int next_prio;    offset:60;      size:4; signed:1;
   
   print fmt: "prev_comm=%s prev_pid=%d prev_prio=%d prev_state=%s%s ==> next_comm=%s next_pid=%d next_prio=%d", REC->prev_comm, REC->prev_pid, REC->prev_prio, (REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1)) ? __print_flags(REC->prev_state & ((((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) - 1), "|", { 0x0001, "S" }, { 0x0002, "D" }, { 0x0004, "T" }, { 0x0008, "t" }, { 0x0010, "X" }, { 0x0020, "Z" }, { 0x0040, "P" }, { 0x0080, "I" }) : "R", REC->prev_state & (((0x0000 | 0x0001 | 0x0002 | 0x0004 | 0x0008 | 0x0010 | 0x0020 | 0x0040) + 1) << 1) ? "+" : "", REC->next_comm, REC->next_pid, REC->next_prio
   ```

注：由于对tracepoint信息的访问需要root权限，所以脚本内含有sudo，在执行脚本时可能需要输入用户密码来验证。这是正常操作。

### 4. 调研及实现过程的文档

位于docs目录下，由于编码兼容性原因，文件名为英文，但文件内容是中文。

### 5. 联系方式
如对此项目有所建议，或想要参与到此项目的开发当中，欢迎联系邮箱2110459069@qq.com！希望与更多志同道合的人一道探究CPU子系统的指标检测相关问题！
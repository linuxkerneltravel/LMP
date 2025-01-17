# mem\_watcher

## mem\_watcher介绍

**memwatcher是一款基于eBPF的内存监测工具，其设计的目的就是为了可以让用户能够在主机环境上可以快捷的检测到Linux内存的详细信息。** **通过高效的数据收集和精准的监控能力，帮助用户可以有效的监控主机内存情况。** **使用了eBPF（Extended Berkeley Packet Filter）来监控内核中的几个关键事件，主要涉及到内存管理方面的几个功能：**

**本项目是内存性能分析工具集合，采用libbpf编写。现有工具procstat（进程内存状态报告），sysstat（系统内存状态报告），paf（内存页面状态报告），pr（内存回收状态报告）和memleak（内存泄漏检测）。**

**eBPF 提供了一种高效的机制来监控和追踪系统级别的事件，包括内存的分配和释放。通过 eBPF，可以跟踪内存分配和释放的请求，并收集每次分配的调用堆栈。然后，分析这些信息，找出执行了内存分配但未执行释放操作的调用堆栈，这有助于程序员找出导致内存泄漏的源头。**

---
## TODO list

- [x] 监控SLAB分配器的内存使用情况
- [ ] 跟踪共享内存的用量信息

## 背景意义

**内存子系统是Linux内核中是一个相对复杂的模块，内核中几乎所有的数据、缓存、程序指令都有内存模块参与管理。在内存不足的情况下，这些数据就会被存储在磁盘的交换空间中，但是磁盘的处理速度相对与内存非常慢，当内存和磁盘频繁进行数据交换时，缓慢的磁盘读写速度非常影响系统性能。系统可能因内存不足从而终止那些占用内存较大的进程，导致程序运行故障。因此准确的监控分析内存性能状况就变得非常重要。**

**目前，传统的内存性能分析工具通过读取proc文件系统下的数据，经过简单的处理后呈现给用户，方便管理人员随时了解系统状况。然而这些工具的灵活性非常差，单个工具输出的信息有限。系统维护人员在分析性能问题时常常需要借助多个工具才能进行。步骤繁琐且工具本身对系统性能也有一定影响。随着ebpf技术在系统可观测上的发展，利于ebpf非侵入式的数据获取方式已被大多数企业、高校认可并取得了一定的研究成果。ebpf的可编程性可以让管理人员灵活的获取系统的运行数据，而且在数据的提取粒度上有着传统工具无法比拟的优势。现在，ebpf作为Linux内核顶级子系统，已经成为实现Linux内核可观测性、网络和内核安全的理想技术。**

## 准备工作

**环境：Ubuntu 22.04, 内核版本 5.15.0-107-generic及以上**

**注：由于 eBPF 的 kprobe 逻辑与内核数据结构定义高度相关，而现在 BTF 的应用（可消除不同内核版本间数据结构的不兼容）还不是很成熟，因此在使用此例程前，需首先适配内核版本。**

**软件：**

* **go SDK（安装cilium库）**
* **llvm，clang，rust**
* **bpftrace**

## 环境搭建

1. **rust 语言编译环境安装**
   **`blazesym` 使用 `rust` 语言编写，使用前需要安装 `rust` 语言的编译环境**
   ```
   # 安装前先配置国内镜像源，可以加速下载
   # 设置环境变量 RUSTUP_DIST_SERVER （用于更新 toolchain）：
   export RUSTUP_DIST_SERVER=https://mirrors.ustc.edu.cn/rust-static
   # RUSTUP_UPDATE_ROOT （用于更新 rustup）：
   export RUSTUP_UPDATE_ROOT=https://mirrors.ustc.edu.cn/rust-static/rustup

   # 安装 https://www.rust-lang.org/tools/install
   # 请不要使用Ubuntu的安装命令: sudo apt install cargo，否则可能会出现莫名其妙的问题
   curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh

   # 修改 ~/.cargo/config 文件，配置 rust 使用的国内镜像源
   [source.crates-io]
   registry = "https://github.com/rust-lang/crates.io-index"
   replace-with = 'ustc'

   [source.ustc]
   registry = "git://mirrors.ustc.edu.cn/crates.io-index"
   ```

### 环境搭建的问题记录
   ```
   cd lmp/eBPF_Supermarket/Memory_Subsystem/mem_watcher
   make
   ```
   make后没有编译生成任何的二进制文件，只打印了logo，效果如下：
   ![alt text](../docs/image/15.png)

打开makefile，检查makefile逻辑，代码如下：
```
CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := 
TARGETS= mem_watcher
```
这段代码是检查`CARGO`变量是否为空。如果为空（即`cargo`命令不存在），则`BZS_APPS`变量将被设置为空。否则，`BZS_APPS`变量也将被设置为空，但同时定义了一个名为`TARGETS`的变量，其值为`mem_watcher`。

**修改makefile**

```
TARGETS= mem_watcher
CARGO ?= $(shell which cargo)
ifeq ($(strip $(CARGO)),)
BZS_APPS :=
else
BZS_APPS := 
```
再次执行make，发现报错为 "vmlinux.h file not find"，如下：
   ![alt text](../docs/image/16.png)

执行以下命令,生成vmlinux.h文件
```
cd /lmp/eBPF_Supermarket/Memory_Subsystem
bpftool btf dump file /sys/kernel/btf/vmlinux format c > vmlinux.h
```

**安装cargo**
```
  $ curl -sSf https://static.rust-lang.org/rustup.sh | sh
```
这里参考 [Blog](https://blog.csdn.net/somken/article/details/129145764)换源
```
# 放到 `$HOME/.cargo/config` 文件中
[source.crates-io]
registry = "https://github.com/rust-lang/crates.io-index"

# 替换成你偏好的镜像源
replace-with = 'tuna'
#replace-with = 'ustc'
#replace-with = 'zju'

[source.tuna]
registry = "https://mirrors.tuna.tsinghua.edu.cn/git/crates.io-index.git"

[source.ustc]
registry = "git://mirrors.ustc.edu.cn/crates.io-index"

[source.zju]
registry = "https://mirrors.zju.edu.cn/git/crates.io-index.git"


[source.sjtu]
registry = "https://mirrors.sjtug.sjtu.edu.cn/git/crates.io-index"

# rustcc社区
[source.rustcc]
registry = "git://crates.rustcc.cn/crates.io-index"

```
   重新安装还是会报错：

   ![alt text](../docs/image/17.png)

   在 `~/.cargo/config` 文件中添加以下内容，即可解决：
   ```
   [net]
git-fetch-with-cli = true
```
再次make编译完成，生成二进制文件 mem_watcher，并能正常运行。
   ![alt text](../docs/image/18.png)

# 工具的使用方法说明

## 功能介绍

**mem\_watcher工具可以通过一系列的命令控制参数来控制其具体的检测行为：我们可以通过sudo ./mem\_watcher -h来查看工具支持的功能**

```
mem_watcher is in use ....

 Select function:

 Memory Page Reports:
  -a, --paf                  Print paf (内存页面状态报告)

 Page Reclaim Reports:
  -p, --pr                   Print pr (页面回收状态报告)

 Process Memory Reports:
  -P, --choose_pid=PID       选择进程号打印
  -r, --procstat             Print procstat (进程内存状态报告)
  -R, --Rss                  打印进程页面

 System Memory Reports:
  -s, --sysstat              Print sysstat (系统内存状态报告)
  -n, --part2                System Memory Reports (Part 2)

 Memory Leak Detection:
  -l, --memleak              Print memleak (内核态内存泄漏检测)
      --choose_pid=PID       选择进程号打印, Print memleak (用户态内存泄漏检测)
```

* **-a 输出的信息跟踪内核中页面的回收行为。包括present(当前内存中可用的页面数量)，min(在这个阈值下，系统可能会触发内存压缩)，low(在这个阈值下，系统进行内存回收)，high(在这个阈值上，认为内存资源充足)，flag(用于内存分配的状态)。**
* **-p 跟踪内核中页面的回收行为，记录回收的各个阶段，例如要回收的页面，以回收的页面，等待回收的脏页数，要写回的页数(包括交换空间中的页数)以及当前正在写回的页数。**
* **-r 主要是用于跟踪用户空间进程的内存使用情况。具体功能是在用户空间进程切换时，记录切换前进程的内存信息。如果要选择进程进行跟踪，则输入进程的pid；输入参数R，显示进程使用的页面数量。**
* **-s 提取各种类型内存的活动和非活动页面数量，以及其他内存回收相关的统计数据，除了常规的事件信息外，程序还输出了与内存管理相关的详细信息，包括了不同类型内存的活动（active）和非活动（inactive）页面，未被驱逐（unevictable）页面，脏（dirty）页面，写回（writeback）页面，映射（mapped）页面，以及各种类型的内存回收相关统计数据。该功能分为了两部分输出，输入参数“n”，输出第二部分性能指标。**
* **-l 输出了用户态造成内存泄漏的位置，包括内存泄漏指令地址对应符号名，程序中尚未被释放的内存总量，未被释放的分配次数。也可以输出内核态的内存泄漏。如跟踪内核态内存泄漏，只输入参数-l；如跟踪用户态内存泄漏，则在获取用户态进程的pid后，再输入要跟踪进程的pid。**

---

# mem\_watcher具体功能分析

## procstat

### 采集信息：


| **参数**     | **含义**                     |
| ------------ | ---------------------------- |
| **vsize**    | **进程使用的虚拟内存**       |
| **size**     | **进程使用的最大物理内存**   |
| **rssanon**  | **进程使用的匿名页面**       |
| **rssfile**  | **进程使用的文件映射页面**   |
| **rssshmem** | **进程使用的共享内存页面**   |
| **vswap**    | **进程使用的交换分区大小**   |
| **vdata**    | **进程使用的私有数据段大小** |
| **vpte**     | **进程页表大小**             |
| **vstk**     | **进程用户栈大小**           |

### 载点及挂载原因

**挂载点：finish\_task\_switch**

**挂载原因：**

**首先，获取进程级别内存使用信息首先需要获取到进程的task\_struct结构体，其中在mm\_struct成员中存在一个保存进程当前内存使用状态的数组结构，因此有关进程的大部分内存使用信息都可以通过这个数组获得。其次，需要注意函数的插入点，插入点的选取关系到数据准确性是否得到保证，而在进程的内存申请，释放，规整等代码路径上都存在页面状态改变，但是数量信息还没有更新的相关结构中的情况，如果插入点这两者中间，数据就会和实际情况存在差异，所有在确保可以获取到进程PCB的前提下，选择在进程调度代码路径上考虑。而finish\_task\_switch函数是新一个进程第一个执行的函数，做的事却是给上一个被调度出去的进程做收尾工作，所有这个函数的参数是上一个进程的PCB，从这块获得上一个进程的内存信息就可以确保在它没有再次被调度上CPU执行的这段时间内的内存数据稳定性。因此最后选择将程序挂载到finish\_task\_switch函数上。**

### 可以解决的问题

**首先，通过监测这些指标，可以及时发现内存使用异常或泄漏问题，针对性地进行性能优化和内存管理，确保系统运行的高效性和稳定性。其次，了解进程的内存占用情况有助于有效管理系统资源，避免资源浪费和冲突，提高整体资源利用率。此外，当系统出现内存相关的故障或异常时，通过分析这些指标可以快速定位问题所在，有针对性地进行故障排除和修复，缩短系统恢复时间。结合这些指标可以进行性能调优，优化内存分配和释放策略，提升系统的响应速度和整体性能表现。**

### 使用方法和结果展示

```
sudo ./mem_watcher -r
......
01:08:50 334      0        0        0        0   
01:08:50 2984     13194    10242    2952     0   
01:08:50 0        0        0        0        0   
01:08:50 334      0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 0        0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 0        0        0        0        0   
01:08:50 0        0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 0        0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 2984     13194    10242    2952     0   
01:08:50 0        0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 334      0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 0        0        0        0        0   
01:08:50 0        0        0        0        0   
01:08:50 5427     0        0        0        0   
01:08:50 0        0        0        0        0  
......
```

## sysstat

### 采集信息：


| **参数**           | **含义**                             |
| ------------------ | ------------------------------------ |
| **active**         | **LRU活跃内存大小**                  |
| **inactive**       | **LRU不活跃内存大小**                |
| **anon\_active**   | **活跃匿名内存大小**                 |
| **anon\_inactive** | **不活跃匿名内存大小**               |
| **file\_active**   | **活跃文件映射内存大小**             |
| **file\_inactive** | **不活跃文件映射内存大小**           |
| **unevictable**    | **不可回收内存大小**                 |
| **dirty**          | **脏页大小**                         |
| **writeback**      | **正在回写的内存大小**               |
| **anonpages**      | **RMAP页面**                         |
| **mapped**         | **所有映射到用户地址空间的内存大小** |
| **shmem**          | **共享内存**                         |
| **kreclaimable**   | **内核可回收内存**                   |
| **slab**           | **用于slab的内存大小**               |
| **sreclaimable**   | **可回收slab内存**                   |
| **sunreclaim**     | **不可回收slab内存**                 |
| **NFS\_unstable**  | **NFS中还没写到磁盘中的内存**        |
| **writebacktmp**   | **回写所使用的临时缓存大小**         |
| **anonhugepages**  | **透明巨页大小**                     |
| **shmemhugepages** | **shmem或tmpfs使用的透明巨页**       |

### 功能

**提取各种类型内存的活动和非活动页面数量，以及其他内存回收相关的统计数据，除了常规的事件信息外，程序还输出了与内存管理相关的详细信息，包括了不同类型内存的活动（active）和非活动（inactive）页面，未被驱逐（unevictable）页面，脏（dirty）页面，写回（writeback）页面，映射（mapped）页面，以及各种类型的内存回收相关统计数据。**

### 挂载点及挂载原因

**挂载点：get\_page\_from\_freelist**

**原因：**

**首先，内存状态数据的提取需要获取到内存节点pglist\_data数据结构，这个结构是对内存的总体抽象。pglist\_data数据结构末尾有个vm\_stat的数组，里面包含了当前内存节点所有的状态信息。所有只需要获取到pglist\_data结构就能拿到当前的内存状态信息。但是物理内存分配在选择内存节点是通过mempolicy结构获取，无法获得具体的节点结构。选择内存节点的函数处理流程如下：**

```
struct mempolicy *get_task_policy(struct task_struct *p)
{
        struct mempolicy *pol = p->mempolicy;//根据当前task_struct取得
        int node;

        if (pol)
                return pol; 

        node = numa_node_id();
        if (node != NUMA_NO_NODE) {//存在其他节点
                pol = &preferred_node_policy[node];
                /* preferred_node_policy is not initialised early in boot */
                if (pol->mode)
                        return pol; 
        }  

        return &default_policy;//不存在其他节点返回本地节点
}
```

**经过对内存申请的内部结构alloc\_context分析(这是内存申请过程中临时保存相关参数的结构)，当前内存节点是可以通过：alloc\_context——>zoneref——>zone——>pglist\_data的路径访问到。**

**其次，因为函数执行申请内存的过程对获取内存节点数据的影响不大，所以只要可以获得alloc\_context数据结构，在整个申请路径上挂载函数都是可以的。sysstat工具选择的挂载点是get\_page\_from\_freelist函数。这个函数是快速物理内存分配的入口函数。因为内核在进行物理内存分配时，都会进入快速路径分配，只有当失败时才会进入慢速路径，所以get\_page\_from\_freelist函数是必经函数。**

**但是，经过对proc文件系统的打印函数meminfo\_proc\_show函数的分析得知，影响内存性能的参数在vm\_stat中无法全部获得。一部分数据需要遍历当前内存节点包含的所有内存管理区zone结构中vm\_stat数组获得，一部分需要读取全局变量vm\_node\_stat获得。但是内核的全局变量不会作为函数参数参与数据处理，目前还没具体方法获得这部分数据。**

### 存在问题

**■ 部分性能数据存在于内核全局变量中，而这些数据不会作为函数参数存储在栈中，因此这些数据目前还没实现统计**

**■ 因为内核对内存管理不会是物理内存的全部容量，而且最大管理内存的数据结构是内存结点，所以以上统计数据是以当前内存结点实际管理的内存容量为基准。**

**■ 当前剩余内存总量的统计需要遍历所有内存管理区来统计，但是由于内存管理区的空闲页面信息存储在数组第一个位置，使用指针指向时，统计到的数据不准确，使用变量统计会出现数据类型错误的报告。**

### 可以解决的问题

**通过提取内存指标，可以及时发现潜在问题，如内存泄漏，从而采取相应措施。此外，了解各种内存类型的使用情况有助于合理分配资源，提高系统效率，并确保数据一致性。**

### 使用方法和结果展示

```
sudo ./mem_watcher -s
......
ACTIVE   INACTVE  ANON_ACT ANON_INA FILE_ACT FILE_INA UNEVICT  DIRTY    WRITEBK  ANONPAG  MAP      SHMEM   
327644   2747936  1988     2278752  325656   469184   0        216      0        563728   249116   7832  
327652   2747616  1996     2278432  325656   469184   0        240      0        563844   249164   7832  
327652   2747616  1996     2278432  325656   469184   0        240      0        563864   249164   7832  
327652   2747844  1996     2278656  325656   469188   0        252      0        563864   249164   7832  
327652   2747844  1996     2278656  325656   469188   0        252      0        563884   249164   7832
......
```

## paf

### 采集信息


| **参数**    | **含义**                                 |
| ----------- | ---------------------------------------- |
| **min**     | **内存管理区处于最低警戒水位的页面数量** |
| **low**     | **内存管理区处于低水位的页面数量**       |
| **high**    | **内存管理区处于高水位的页面数量**       |
| **present** | **内存管理区实际管理的页面数量**         |
| **flag**    | **申请页面时的权限（标志）**             |

### 功能

**主要是监控内核中的 **`get_page_from_freelist`函数。这个函数在内核中用于从内存空闲页列表中获取一个页面。** **程序主要是输出present(当前内存中可用的页面数量)，min(在这个阈值下，系统可能会触发内存压缩)，low(在这个阈值下，系统进行内存回收)，high(在这个阈值上，认为内存资源充足)，flag(用于内存分配的状态)。

### 注：

**内存申请失败一般集中在申请权限不够或者是权限冲突导致，申请权限不够是当内核申请优先级较低的页面时，虽然内存管理区有足够的页面满足这次申请数量，但是当前剩余空闲页面少于最低警戒水位，因此导致内核无法成功分配页面的情况。权限冲突，例如内核在开启CMA机制下导致的页面页面申请失败的情况，这种情况下管理区空闲页面需要减去CMA机制占用内存才是当前可分配内存。相关权限判断代码如下：**

**添加CMA权限代码路径mm/page\_alloc.c**

```
static inline unsigned int
gfp_to_alloc_flags(gfp_t gfp_mask)
{
    unsigned int alloc_flags = ALLOC_WMARK_MIN | ALLOC_CPUSET;
    ...
    alloc_flags |= (__force int) (gfp_mask & __GFP_HIGH);
    ...
    if (gfp_mask & __GFP_KSWAPD_RECLAIM)
            alloc_flags |= ALLOC_KSWAPD;
  
#ifdef CONFIG_CMA
    if (gfpflags_to_migratetype(gfp_mask) == MIGRATE_MOVABLE)
            alloc_flags |= ALLOC_CMA;
#endif
    return alloc_flags;
}
```

**CMA机制内存处理代码:**

```
bool __zone_watermark_ok(struct zone *z, unsigned int order, unsigned long mark,
                         int classzone_idx, unsigned int alloc_flags, long free_pages)
{
   ...
#ifdef CONFIG_CMA
        if (!(alloc_flags & ALLOC_CMA))
                free_pages -= zone_page_state(z, NR_FREE_CMA_PAGES);
#endif  
  
        if (free_pages <= min + z->lowmem_reserve[classzone_idx])
                return false;
    ...
#ifdef CONFIG_CMA
       if ((alloc_flags & ALLOC_CMA) &&
                !list_empty(&area->free_list[MIGRATE_CMA])) {
                        return true;
                }
#endif
}
```

**挂载点：get\_page\_from\_freelist**

**原因:**

**经过对内核源码的分析，页面申请失败分析工具的理想挂载点应该是慢速路径的入口函数（\_\_alloc\_pages\_slowpath）。但是这个函数不允许ebpf程序挂载，而且这个函数内部也不存在合理的挂载点，所有将函数挂载点选在快速路径的入口函数get\_page\_from\_freelist上。因为页面申请的控制结构体ac在这两个函数之间不存在信息更改，所以可以确保这两个函数传递的ac结构体是相同的，不会对提取出来的数据产生影响。为了确保数据确实是在页面申请失败的情况下才会打印数据，需要对alloc\_pages\_nodemask函数的返回值进行挂载，当alloc\_pages\_nodemask函数没有返回页面结构体page时，也就是页面申请失败的情况下单元提取的数据。**

### 存在问题

**■ 打印出来的内存申请标志与申请内存传递进去的标志不符，分析原因可能内核在进行alloc\_pages函数之前有对标志位进行处理。**

**■ 因为内存管理区的剩余内存空间处在vm\_stat数组第一位，经过分析，使用指针提取的数组第一个数据总是存在差异，需要调整。**

**■ 对打印的标志位需要进一步解析，方便快速确认当前申请页面类型。**

### 可以解决的问题

**可以帮助监控系统内存的使用情况，预测内存不足的可能性，以及在必要时触发相应的内存回收机制来保证系统的稳定性和性能。**

### 使用方法和结果展示

```
sudo ./mem_watcher -a
MIN      LOW       HIGH     PRESENT  FLAG  
262144   5100      6120     262144   1100dca 
262144   5100      6120     262144   2800  
262144   5100      6120     262144   cc0   
262144   5100      6120     262144   d00   
262144   5100      6120     262144   2dc2   
......
```

## pr

### 采集信息


| **参数**           | **含义**                                         |
| ------------------ | ------------------------------------------------ |
| **reclaim**        | **要回收的页面数量**                             |
| **reclaimed**      | **已经回收的页面数量**                           |
| **unqueue\_dirty** | **还没开始回写和还没在队列等待的脏页**           |
| **congested**      | **正在块设备上回写的页面，含写入交换空间的页面** |
| **writeback**      | **正在回写的页面**                               |

### 功能

**主要用于监控内核中的 **`shrink_page_list`函数。** **整个BPF程序的功能是监控 `shrink_page_list`函数的调用，当函数被调用时，记录特定的内核数据（包括 `nr_reclaimed`等值），并将这些数据存储在环形缓冲区中，以供用户空间程序使用。** **跟踪内核中页面的回收行为，记录回收的各个阶段，例如要回收的页面，以回收的页面，等待回收的脏页数，要写回的页数(包括交换空间中的页数)以及当前正在写回的页数。

### 挂载点与挂载原因

**挂载点**

**shrink\_page\_list**

**挂载原因**

**shrink\_page\_list函数是页面回收后期指向函数，主要操作是遍历链表中每一个页面，根据页面的属性确定将页面添加到回收队列、活跃链表还是不活跃链表.这块遍历的链表是在上一级函数 shrink\_inactive\_list中定义的临时链表，因为一次最多扫描32个页面，所有链表最多含有32个页面。在shrink\_page\_list这个函数中还有一个重要操作是统计不同状态的页面数量并保存在scan\_control结构体中。而工具数据提取的位置就是找到这个结构体并获取有关性能指标。因为这个提取的数据都是内核函数实时更改的，所有具有较高准确性。** **scan\_control结构体是每次进行内存回收时都会被回收进程重新定义，所有会看到数据是一个增长状态，之后有回归0，这和挂载点也有一定关系。**

### 可以解决的问题

**监测系统的页面回收和写回情况，对系统内存使用和性能优化非常重要。整体来说，这些参数可以帮助系统管理员或开发人员了解系统内存管理的情况，包括页面回收的效率、脏页处理情况以及写回操作的进度。**

### 使用方法和结果展示

```
sudo ./mem_watcher -p
RECLAIM  RECLAIMED UNQUEUE  CONGESTED WRITEBACK
16893    0         0        0        0   
16893    24        0        0        0   
16893    24        0        0        0   
16893    40        0        0        0   
16893    64        0        0        0   
16893    64        0        0        0   
16893    66        0        0        0   
......
```

## memleak

### 计算方式

1. **当调用内存分配相关的函数（如malloc、calloc等）时，程序记录分配的大小并跟踪分配返回的地址。这涉及更新两个BPF映射，一个记录PID与分配大小的对应关系，另一个记录分配地址与分配详情的对应关系。**
2. **当调用free或相关函数时，程序查找之前记录的分配地址，若找到，则更新或删除对应映射中的记录。**
3. **对于每次分配，程序尝试获取调用堆栈的ID，这通过bpf\_get\_stackid()实现。堆栈ID用于识别特定的调用序列，帮助理解分配发生的上下文。**
4. **使用堆栈ID将相同堆栈上的分配合并，记录总分配大小和次数。这涉及到在BPF映射中累加新的分配或减去释放的分配。程序使用****sync\_fetch\_and\_add和**sync\_fetch\_and\_sub等原子操作来更新共享数据。这确保即使在高并发的环境下，数据更新也是安全的。

### 采集信息


| **参数**        | **含义**                           |
| --------------- | ---------------------------------- |
| **stack\_id**   | **触发分配的的调用堆栈ID**         |
| **total\_size** | **表示程序中尚未被释放的内存总量** |
| **nr\_allocs**  | **所有未释放分配的总次数**         |
| **input\_addr** | **堆栈中的指令地址**               |
| **name**        | **符号名**                         |

### 功能

**代码主要用于跟踪内核内存分配和释放的情况，并记录相关的统计信息。**

### 可以解决的问题

**可以帮助用户准确的找出内存泄露的位置，更好的排查出所存在的问题。**

### 使用方法和结果展示

**用户态内存泄漏**

```
sudo ./mem_watcher -l -P 2429
......
stack_id=0x3c14 with outstanding allocations: total_size=4 nr_allocs=1
000055e032027205: alloc_v3 @ 0x11e9+0x1c /test_leak.c:11
000055e032027228: alloc_v2 @ 0x120f+0x19 /test_leak.c:17
000055e03202724b: alloc_v1 @ 0x1232+0x19 /test_leak.c:23
000055e032027287: memory_leak @ 0x1255+0x32 /test_leak.c:35
00007f1ca1d66609: start_thread @ 0x8530+0xd9
stack_id=0x3c14 with outstanding allocations: total_size=8 nr_allocs=2
000055e032027205: alloc_v3 @ 0x11e9+0x1c /test_leak.c:11
000055e032027228: alloc_v2 @ 0x120f+0x19 /test_leak.c:17
000055e03202724b: alloc_v1 @ 0x1232+0x19 /test_leak.c:23
000055e032027287: memory_leak @ 0x1255+0x32 /test_leak.c:35
00007f1ca1d66609: start_thread @ 0x8530+0xd9
......
```

**内核态内存泄漏**

```
sudo ./mem_watcher -l
......
[19:49:22] Top 10 stacks with outstanding allocations:
ffffffff95127b02: __alloc_pages @ 0xffffffff951278a0+0x262
ffffffff95127b02: __alloc_pages @ 0xffffffff951278a0+0x262
ffffffff95147bb0: alloc_pages @ 0xffffffff95147b20+0x90
ffffffff950b40e7: __page_cache_alloc @ 0xffffffff950b4060+0x87
ffffffff950b75f0: pagecache_get_page @ 0xffffffff950b74a0+0x150
ffffffff951e1f92: __getblk_gfp @ 0xffffffff951e1ea0+0xf2
ffffffff952d143c: jbd2_journal_get_descriptor_buffer @ 0xffffffff952d13e0+0x5c
ffffffff952c724b: journal_submit_commit_record.part.0 @ 0xffffffff952c7210+0x3b
ffffffff952c8839: jbd2_journal_commit_transaction @ 0xffffffff952c7540+0x12f9
ffffffff952ce166: kjournald2 @ 0xffffffff952ce0b0+0xb6
......
```

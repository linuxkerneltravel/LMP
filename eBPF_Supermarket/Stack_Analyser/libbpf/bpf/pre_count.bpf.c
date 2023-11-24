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
// author: luiyanbing@foxmail.com
//
// 内核态bpf的预读取分析模块代码

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#include "stack_analyzer.h"

#define MINBLOCK_US 1ULL
#define MAXBLOCK_US 99999999ULL

BPF_STACK_TRACE(stack_trace);
BPF_HASH(pid_tgid, u32, u32);
BPF_HASH(pid_comm, u32, comm);

BPF_HASH(psid_util, psid, tuple);

BPF_HASH(in_ra, u32, psid);
BPF_HASH(page_psid, struct page *, psid);

int apid = 0;
bool u = false, k = false;
__u64 min = 0, max = 0;
  
SEC("fentry/page_cache_ra_unbounded")                               //fentry在内核函数page_cache_ra_unbounded进入时触发的挂载点 

                                                                    //定义了一个名为BPF_PROG(page_cache_ra_unbounded)的探针，该探针在page_cache_ra_unbounded的入口处被触发
int BPF_PROG(page_cache_ra_unbounded)
{
    u64 td = bpf_get_current_pid_tgid();
    u32 pid = td >> 32;                                             //获取当前进程tgid，用户空间的pid即是tgid

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    u32 tgid = td;
    bpf_map_update_elem(&pid_tgid, &pid, &tgid, BPF_ANY);           //更新pid_tgid表中的pid对应的值
    comm *p = bpf_map_lookup_elem(&pid_comm, &pid);                 //p指向pid_comm表中pid对应的值
    if (!p)
    {
        comm name;
        bpf_get_current_comm(&name, COMM_LEN);                     //获取当前进程名
        bpf_map_update_elem(&pid_comm, &pid, &name, BPF_NOEXIST);//在pid_comm表中更新pid对应的值
    }
                                                                //栈计数的键，可以唯一标识一个用户内核栈
    psid apsid = {
        .pid = pid,
        .usid = u ? USER_STACK : -1,
        .ksid = k ? KERNEL_STACK : -1,
    };

// typedef struct
// {
//     __u64 truth;
//     __u64 expect;
// } tuple;

    tuple *d = bpf_map_lookup_elem(&psid_util, &apsid);         //d指向psid_util表中的apsid对应的类型为tuple的值
    if (!d)
    {
        tuple a = {.expect = 0, .truth = 0};                    //初始化为0
        bpf_map_update_elem(&psid_util, &apsid, &a, BPF_ANY);   //更新psid_util表中的apsid的值为a
    }
    bpf_map_update_elem(&in_ra, &pid, &apsid, BPF_ANY);         //更新in_ra表中的pid对应的值为apsid
    return 0;
}


SEC("fexit/alloc_pages")                                        //fexit在内核函数alloc_pages退出时触发，挂载点为alloc_pages
                                                                //struct page *alloc_pages(gfp_t gfp_mask, unsigned int order); 参数分别是分配标志以及页的阶数
int BPF_PROG(filemap_alloc_folio_ret, gfp_t gfp, unsigned int order, u64 ret)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;                 //pid为当前进程的pid

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    struct psid *apsid = bpf_map_lookup_elem(&in_ra, &pid);     //apsid指向了当前in_ra中pid的表项内容
    if (!apsid)
        return 0;

    tuple *a = bpf_map_lookup_elem(&psid_util, apsid);          //a是指向psid_util的apsid对应的内容
    if (!a)
        return 0;

    const u32 lim = 1ul << order;                               //1 为长整型，左移order位，即2^order 即申请页的大小
    a->expect += lim;                                           //a->expect+=页大小（未访问）
    u64 addr;
    bpf_core_read(&addr, sizeof(u64), &ret);                    //alloc_pages返回的值，即申请页的起始地址保存在addr中
    for (int i = 0; i < lim && i < 1024; i++, addr += 0x1000)
        bpf_map_update_elem(&page_psid, &addr, apsid, BPF_ANY);//更新page_psid表中的addr（从页的起始地址开始到页的结束地址）所对应的值为apsid

    return 0;
}

SEC("fexit/page_cache_ra_unbounded")
int BPF_PROG(page_cache_ra_unbounded_ret)                       //fexit在内核函数page_cache_ra_unbounded退出时触发的挂载点
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;                 //获取当前进程的pid

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;

    bpf_map_delete_elem(&in_ra, &pid);                           //删除了in_ra对应的pid的表项,即删除对应的栈计数信息
    return 0;
}


SEC("fentry/mark_page_accessed")                                //fentry在内核函数/mark_page_accessed进入时触发的挂载点

                                                                //void mark_page_accessed(struct page *page);用于标记页面（page）已经被访问

int BPF_PROG(mark_page_accessed, u64 page)
{
    u32 pid = bpf_get_current_pid_tgid() >> 32;                 //获取当前进程的pid

    if ((apid >= 0 && pid != apid) || !pid)
        return 0;
    psid *apsid;
    apsid = bpf_map_lookup_elem(&page_psid, &page);             //查看page_psid对应的 地址page 对应类型为psid的值，并保存在apsid
    if (!apsid)
        return 0;
    tuple *a = bpf_map_lookup_elem(&psid_util, apsid);          //a指向psid_util的apsid的内容
    if (!a)
        return 0;
    a->truth++;                                                 //已访问
    bpf_map_delete_elem(&page_psid, &page);                     //删除page_psid的page对应的内容
    return 0;
}

const char LICENSE[] SEC("license") = "GPL";
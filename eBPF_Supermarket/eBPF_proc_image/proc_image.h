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
// author: zhangziheng0525@163.com
//
// eBPF map for the process image

#ifndef __PROC_IMAGE_H
#define __PROC_IMAGE_H

#define TASK_COMM_LEN 16

// 以便于对0号进程进行画像（0号进程是每cpu进程）
struct proc_id{
    int pid;
    int cpu_id;
};

struct proc_oncpu{
    int pad;
    int oncpu_id;
    long long unsigned int oncpu_time;
};

struct proc_offcpu{
    int pad;
    int offcpu_id;
    long long unsigned int offcpu_time;
};

struct cpu_event{
    int flag;
    int pid;
    char comm[TASK_COMM_LEN];
    int oncpu_id;
    long long unsigned int oncpu_time;
    int offcpu_id;
    long long unsigned int offcpu_time;
};

#endif /* __PROC_IMAGE_H */
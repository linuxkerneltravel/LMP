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
// process sleep image test program

#include <stdio.h>
#include <unistd.h>
#include <time.h>   // 包含时间相关函数的头文件

int main() {
    int pid,ct;
    int sleepTime = 3; // 睡眠时间，单位为秒

    pid = getpid(); // 获取当前进程的PID
    printf("test_A进程的PID：%d\n", pid);

    printf("输入任意数字继续程序的运行：");
    //scanf("%d",&ct);                    // 使用时将其取消注释
    printf("程序开始执行...\n");

    // 输出当前时间
    time_t now = time(NULL); // 获取当前时间（自1970年1月1日以来的秒数）
    struct tm *localTime = localtime(&now); // 转换为本地时间结构体
    printf("sleep开始时间：%04d-%02d-%02d %02d:%02d:%02d\n",
           localTime->tm_year + 1900, localTime->tm_mon + 1, localTime->tm_mday,
           localTime->tm_hour, localTime->tm_min, localTime->tm_sec);

    // 使用sleep函数进行睡眠
    sleep(sleepTime);

    // 输出睡眠后的当前时间
    time_t afterSleep = time(NULL);
    struct tm *localTimeAfterSleep = localtime(&afterSleep);
    printf("sleep结束时间：%04d-%02d-%02d %02d:%02d:%02d\n",
           localTimeAfterSleep->tm_year + 1900, localTimeAfterSleep->tm_mon + 1, localTimeAfterSleep->tm_mday,
           localTimeAfterSleep->tm_hour, localTimeAfterSleep->tm_min, localTimeAfterSleep->tm_sec);

    printf("程序睡眠%ds，执行完毕！\n",sleepTime);
    

    return 0;
}

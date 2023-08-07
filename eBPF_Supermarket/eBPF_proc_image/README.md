# 基于eBPF的Linux系统性能监测工具-进程画像

## 一、介绍

本项目是一个Linux进程生命周期画像工具，通过该工具可以清晰展示出一个进程从创建到终止的完整生命周期，并可以额外展示出进程/线程持有锁的区间画像、进程/线程上下文切换原因的标注、线程之间依赖关系（线程）、进程关联调用栈信息标注等。在这些功能的前提下，加入了更多的可视化元素和交互方式，使得整个画像更加直观、易于理解。

运行环境：Ubuntu 22.04，内额版本5.19.0-46-generic

## 二、proc_image工具

proc_image便是Linux进程生命周期画像工具，该工具由多个子功能组成。

### 1. 进程上下CPU时间统计

目前该功能可由proc_image工具的-p参数去实现，需指定进程pid，便可以采集到该进程在生命周期中上下CPU的时间信息。该功能已经和top进行了时间上的比对，准确性满足要求。示例如下：

在top页面按下“d”，可以看到top默认为每3秒更新一次：

<div align='center'><img src="./docs/images/top_delay.png"></div>

运行eBPF程序跟踪top进程，执行指令 sudo ./proc_image -p 5523，运行结果：

<div align='center'><img src="./docs/images/proc_cpu.png"></div>

结合top进程每3秒更新一次，从运行结果中可以看出该eBPF程序已经成功捕获到top进程上下cpu的时间信息。

在此基础上，通过该工具的-p和-C参数，能捕获到每个CPU所对应0号进程的上下cpu时间信息，进而也可以体现出0号进程所对应的CPU繁忙程度。

## 三、proc_offcpu_time工具

该工具可通过-p参数指定进程的pid，便可以采集到该进程处于off_CPU的时间。该功能已经和加入sleep逻辑的用户态程序（./test/test_sleep.c）进行了时间上的比对，准确性满足要求。示例如下：

终端1：./test_sleep

```
test_sleep进程的PID：9063
输入任意数字继续程序的运行：
```

终端2：现在已知test_sleep进程的PID为9063，执行指令sudo ./proc_image -p 9063进行跟踪

终端1：输入任意数字继续程序的运行

最后终端1和终端2的运行结果如下：

```
// 终端1
test_sleep进程的PID：9063
输入任意数字继续程序的运行：1
程序开始执行...
sleep开始时间：2023-07-24 16:58:28
sleep结束时间：2023-07-24 16:58:31
程序睡眠3s，执行完毕！

//终端2
pid:9063  comm:test_sleep  offcpu_id:3  offcpu_time:5963882827916  oncpu_id:3  oncpu_time:5966883001411  sleeptime:3.000173
```

目前该工具的功能已经合入proc_image。

## 四、mutex_image 工具

mutex_image 工具目前只能完成下图情形1的进程互斥锁画像，后期会继续迭代。

<div align='center'><img src="./docs/images/mutex_development.png"></div>

该工具的详细文档见./docs/mutex。

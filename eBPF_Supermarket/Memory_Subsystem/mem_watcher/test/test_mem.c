#include <argp.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <stdbool.h>
#include <unistd.h>
#include <sys/types.h>
#include <pthread.h>
#include <signal.h>

#define ALLOC_SIZE_SMALL 4
#define ALLOC_SIZE_MEDIUM 64
#define ALLOC_SIZE_LARGE 1024
#define NUM_THREADS 10
#define ALLOC_SIZE (512 * 1024 * 1024)

static struct env {
    bool overall_leak_test;
    bool mem_leak;
    bool mem_unleak;
    bool mem_stress_test;
    bool simulate_leak;
} env = {
    .overall_leak_test = false,
    .mem_leak = false,
    .mem_unleak = false,
    .mem_stress_test = false,
    .simulate_leak = false
};

static volatile bool running = true;  // 控制程序是否继续运行

const char argp_program_doc[] = "mem_watcher test.\n";

static const struct argp_option opts[] = {
    { NULL, 0, NULL, 0, "Memory Management Options:", 1 },
    { "overall-test", 'o', NULL, 0, "Perform overall memory test", 2 },
    { "detect-leak", 'l', NULL, 0, "Detect memory leaks", 3 },
    { "no-leak", 'n', NULL, 0, "No memory leaks expected", 3 },
    { "stress-test", 's', NULL, 0, "Perform memory stress test", 4 },
    { "simulate-leak", 'm', NULL, 0, "Simulate memory leak with complex objects", 5 },
    { NULL, 'h', NULL, OPTION_HIDDEN, "show the full help", 0 },
    { NULL, 0, NULL, 0, NULL, 0 }
};

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
    (void)arg; 
    switch (key) {
        case 'o':
            env.overall_leak_test = true;
            break;
        case 'l':
            env.mem_leak = true;
            break;
        case 'n':
            env.mem_unleak = true;
            break;
        case 's':
            env.mem_stress_test = true;
            break;
        case 'm':
            env.simulate_leak = true;
            break;
        case 'h':
            argp_state_help(state, stderr, ARGP_HELP_STD_HELP);
            break;
        default:
            return ARGP_ERR_UNKNOWN;
    }    
    return 0;
}

typedef struct {
    int* data;
} ComplexObject;

ComplexObject* createComplexObject() {
    ComplexObject* obj = (ComplexObject*)malloc(sizeof(ComplexObject));
    if (obj != NULL) {
        obj->data = (int*)malloc(1000 * sizeof(int));
        if (obj->data != NULL) {
            for (int i = 0; i < 1000; ++i) {
                obj->data[i] = rand() % 100; // 填充数据
            }
            return obj;
        } else {
            free(obj);
            return NULL;
        }
    } else {
        return NULL;
    }
}

void destroyComplexObject(ComplexObject* obj) {
    if (obj != NULL) {
        if (obj->data != NULL) {
            free(obj->data);
        }
        free(obj);
    }
}

void simulateMemoryLeak() {
    // 动态分配一个复杂对象的数组
    ComplexObject* objects[1000];
    for (int i = 0; i < 1000; ++i) {
        objects[i] = createComplexObject();
    }
}

// 模拟一些处理，通过写入分配的内存
static void process_data(void *ptr, int size) {
    memset(ptr, 0, size);
}

// 分配内存并处理数据
static void * alloc_v3(int alloc_size) {
    void *ptr = malloc(alloc_size);
    if (ptr) {
        process_data(ptr, alloc_size / 3);
    }
    return ptr;
}

// 分配内存并处理数据
static void * alloc_v2(int alloc_size) {
    void *ptr = alloc_v3(alloc_size);
    if (ptr) {
        process_data(ptr, alloc_size / 4);
    }
    return ptr;
}

// 分配内存并处理数据
static void * alloc_v1(int alloc_size) {
    void *ptr = alloc_v2(alloc_size);
    if (ptr) {
        process_data(ptr, alloc_size / 5);
    }
    return ptr;
}

// 演示内存泄漏
static void leak_memory() {
    void *ptr = malloc(ALLOC_SIZE_LARGE);
    // 故意不释放 ptr 以制造内存泄漏
    process_data(ptr, ALLOC_SIZE_LARGE);
}

static void mem_leak_process() {
    // 引入一些间歇性的内存泄漏
    void *ptr = NULL;
    int i = 0;
    for (i = 0; ; i++) {
        if (i % 5 == 0) {
            leak_memory();
        }
        sleep(1);
    }
}

static void mem_unleak_process() {
    void *ptr = NULL;
    int i = 0;

    for (i = 0; ; i++) {
        int alloc_size = (i % 3 == 0) ? ALLOC_SIZE_SMALL : (i % 3 == 1) ? ALLOC_SIZE_MEDIUM : ALLOC_SIZE_LARGE;

        ptr = alloc_v1(alloc_size);
        if (!ptr) {
            perror("alloc_v1 失败");
            exit(EXIT_FAILURE);
        }

        void *ptr2 = malloc(alloc_size);
        if (!ptr2) {
            perror("malloc 失败");
            free(ptr);
            exit(EXIT_FAILURE);
        }

        process_data(ptr2, alloc_size);

        sleep(1);
        free(ptr);

        sleep(2);
        free(ptr2);
    }
}

// 内存压力测试线程函数
void *memory_stress(void *arg) {
    printf("Thread %ld starting memory allocation...\n", (long)arg);

    // 分配指定大小的内存
    char *memory_block = malloc(ALLOC_SIZE);
    if (!memory_block) {
        perror("Memory allocation failed");
        return NULL;
    }

    // 用 0xFF 填充内存，模拟占用
    memset(memory_block, 0xFF, ALLOC_SIZE);

    // 保持分配的内存一段时间
    while (running) {
        sleep(10);  // 继续分配并占用内存
    }

    // 释放内存
    free(memory_block);
    return NULL;
}

// 处理 SIGINT 信号（Ctrl+C）
void sigint_handler(int sig) {
    (void)sig;  // 忽略信号参数
    running = false;  // 设置标志以退出循环
    printf("Received SIGINT, stopping...\n");
}

int main(int argc, char **argv) {
    int err;
    static const struct argp argp = {
        .options = opts,
        .parser = parse_arg,
        .doc = argp_program_doc,
    };

    err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
    if (err)
        return err;

    if (env.overall_leak_test) {
        // 打印当前进程的进程号（PID）
        pid_t pid = getpid();
        printf("当前进程的进程号（PID）: %d\n", pid);
        if (env.mem_leak) {
            printf("正在进行内存泄漏检测...\n");
            mem_leak_process();
        }
        if (env.mem_unleak) {
            printf("正在进行无内存泄漏测试...\n");
            mem_unleak_process();
        }
    }

    if (env.simulate_leak) {
        // 模拟复杂对象内存泄漏
        for (int i = 0; i < 1000; ++i) {
            simulateMemoryLeak();
        }
    }

    if (env.mem_stress_test) {
        // 打印当前进程的进程号（PID）
        pid_t pid = getpid();
        printf("当前进程的进程号（PID）: %d\n", pid);
        printf("正在进行内存压力测试...\n");

        sleep(2);

        pthread_t threads[NUM_THREADS];
        
        // 创建多个线程，每个线程分配 ALLOC_SIZE 大小的内存
        for (long i = 0; i < NUM_THREADS; i++) {
            if (pthread_create(&threads[i], NULL, memory_stress, (void *)i) != 0) {
                perror("Failed to create thread");
                return 1;
            }
        }

        // 等待所有线程完成
        for (int i = 0; i < NUM_THREADS; i++) {
            pthread_join(threads[i], NULL);
        }

        printf("所有线程完成\n");
    }

    return 0;
}

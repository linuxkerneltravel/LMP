// SPDX-License-Identifier: (LGPL-2.1 OR BSD-2-Clause)
/* Copyright (c) 2020 Facebook */
#include <argp.h>
#include <signal.h>
#include <stdio.h>
#include <time.h>
#include <sys/resource.h>
#include <bpf/libbpf.h>
#include "mem_watcher.h"
#include "paf.skel.h"
#include <sys/select.h>
#include <unistd.h>

static struct env
{
	long choose_pid;
	long time_s;
	long rss;
} env;
/*
const char *argp_program_version = "bootstrap 0.0";
const char *argp_program_bug_address = "<bpf@vger.kernel.org>";

const char argp_program_doc[] =
"BPF bootstrap demo application.\n"
"\n"
"It traces process start and exits and shows associated \n"
"information (filename, process duration, PID and PPID, etc).\n"
"\n"
"USAGE: ./bootstrap [-d <min-duration-ms>] [-v]\n";
*/
static const struct argp_option opts[] = {
	{"choose_pid", 'p', "PID", 0, "选择进程号打印。"},
	{"time_s", 't', "MS", 0, "延时打印。单位：毫秒"},
	{"Rss", 'r', NULL, 0, "进程页面。"},
};

pid_t own_pid;

static error_t parse_arg(int key, char *arg, struct argp_state *state)
{
	switch (key)
	{
	case 'p':
		env.choose_pid = strtol(arg, NULL, 10);
		break;
	case 't':
		env.time_s = strtol(arg, NULL, 10);
		break;
	case 'r':
		env.rss = true;
		break;
	case ARGP_KEY_ARG:
		argp_usage(state);
		break;
	default:
		return ARGP_ERR_UNKNOWN;
	}
	return 0;
}

static const struct argp argp = {
	.options = opts,
	.parser = parse_arg,
	//        .doc = argp_program_doc,
};

static int libbpf_print_fn(enum libbpf_print_level level, const char *format, va_list args)
{
	return vfprintf(stderr, format, args);
}

static volatile bool exiting;

static void sig_handler(int sig)
{
	exiting = true;
}

static void msleep(long secs)
{
	struct timeval tval;

	tval.tv_sec = secs / 1000;
	tval.tv_usec = (secs * 1000) % 1000000;
	select(0, NULL, NULL, NULL, &tval);
}
/*
static char* flags(int flag)
{
	if(flag & GFP_ATOMIC)
		return "GFP_ATOMIC";
	if(flag & GFP_KERNEL)
		return "GFP_KERNEL";
	if(flag & GFP_KERNEL_ACCOUNT)
		return "GFP_KERNEL_ACCOUNT";
	if(flag & GFP_NOWAIT)
		return "GFP_NOWAIT";
	if(flag & GFP_NOIO )
		return "GFP_NOIO ";
	if(flag & GFP_NOFS)
		return "GFP_NOFS";
	if(flag & GFP_USER)
		return "GFP_USER";
	if(flag & GFP_DMA)
		return "GFP_DMA";
	if(flag & GFP_DMA32)
		return "GFP_DMA32";
	if(flag & GFP_HIGHUSER)
		return "GFP_HIGHUSER";
	if(flag & GFP_HIGHUSER_MOVABLE)
		return "GFP_HIGHUSER_MOVABLE";
	if(flag & GFP_TRANSHUGE_LIGHT)
		return "GFP_TRANSHUGE_LIGHT";
	return;
}
*/
static int handle_event(void *ctx, void *data, size_t data_sz)
{
	const struct event *e = data;
	struct tm *tm;
	char ts[32];
	time_t t;

	time(&t);
	tm = localtime(&t);
	strftime(ts, sizeof(ts), "%H:%M:%S", tm);

	printf("%-8lu %-8lu  %-8lu %-8lu %-8x\n",
		   e->min, e->low, e->high, e->present, e->flag);
	/* 睡眠会导致程序无法终止，所以需要注释掉这个代码块   */
	// if(env.time_s != 0) {
	// 	msleep(env.time_s);
	// }
	// else {
	// 	msleep(1000);
	// }
	return 0;
}

int main(int argc, char **argv)
{
	struct ring_buffer *rb = NULL;
	struct paf_bpf *skel;
	int err;

	err = argp_parse(&argp, argc, argv, 0, NULL, NULL);
	if (err)
		return err;
	own_pid = getpid();

	libbpf_set_strict_mode(LIBBPF_STRICT_ALL);
	/* Set up libbpf errors and debug info callback */
	libbpf_set_print(libbpf_print_fn);

	/* Cleaner handling of Ctrl-C */
	signal(SIGINT, sig_handler);
	signal(SIGTERM, sig_handler);

	/* Load and verify BPF application */
	skel = paf_bpf__open();
	if (!skel)
	{
		fprintf(stderr, "Failed to open and load BPF skeleton\n");
		return 1;
	}

	skel->bss->user_pid = own_pid;

	/* Load & verify BPF programs */
	err = paf_bpf__load(skel);
	if (err)
	{
		fprintf(stderr, "Failed to load and verify BPF skeleton\n");
		goto cleanup;
	}

	/* Attach tracepoints */
	err = paf_bpf__attach(skel);
	if (err)
	{
		fprintf(stderr, "Failed to attach BPF skeleton\n");
		goto cleanup;
	}

	/* Set up ring buffer polling */
	rb = ring_buffer__new(bpf_map__fd(skel->maps.rb), handle_event, NULL, NULL);
	if (!rb)
	{
		err = -1;
		fprintf(stderr, "Failed to create ring buffer\n");
		goto cleanup;
	}

	/* Process events */
	if (env.rss == true)
	{
		printf("%-8s %-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "VMSIZE", "VMDATA", "VMSTK", "VMPTE", "VMSWAP");
	}
	else
	{
		printf("%-8s %-8s %-8s %-8s %-8s %-8s\n", "TIME", "PID", "SIZE", "RSSANON", "RSSFILE", "RSSSHMEM");
	}

	while (!exiting)
	{
		err = ring_buffer__poll(rb, 100 /* timeout, ms */);
		/* Ctrl-C will cause -EINTR */
		if (err == -EINTR)
		{
			err = 0;
			break;
		}
		if (err < 0)
		{
			printf("Error polling perf buffer: %d\n", err);
			break;
		}
	}

cleanup:
	/* Clean up */
	ring_buffer__free(rb);
	paf_bpf__destroy(skel);
	return err < 0 ? -err : 0;
}

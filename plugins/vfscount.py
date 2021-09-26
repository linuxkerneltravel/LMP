#!/usr/bin/python
# @lint-avoid-python-3-compatibility-imports
#
# vfscount  Count VFS calls ("vfs_*").
#           For Linux, uses BCC, eBPF. See .c file.
#
# Written as a basic example of counting functions.
#
# Copyright (c) 2015 Brendan Gregg.
# Licensed under the Apache License, Version 2.0 (the "License")
#
# 14-Aug-2015   Brendan Gregg   Created this.

from __future__ import print_function
from bcc import BPF
from time import sleep
from sys import argv

# for influxdb
from init_db import influx_client
from db_modules import write2db
from const import DatabaseType
from datetime import datetime

def usage():
    print("USAGE: %s [time]" % argv[0])
    exit()

interval = 1
if len(argv) > 1:
    try:
        interval = int(argv[1])
        if interval == 0:
            raise
    except:  # also catches -h, --help
        usage()
# load BPF program
b = BPF(text="""
#include <uapi/linux/ptrace.h>

struct key_t {
    u64 ip;
    u64 timestamp;
};

BPF_HASH(counts, struct key_t, u64, 256);

int do_count(struct pt_regs *ctx) {
    struct key_t key = {};
    key.ip = PT_REGS_IP(ctx);
    key.timestamp=bpf_ktime_get_ns();
    counts.increment(key);
    return 0;
}
""")
b.attach_kprobe(event_re="^vfs_.*", fn_name="do_count")


class lmp_data(object):
    def __init__(self, a, b, c, d):
        self.time = a
        self.glob = b
        self.addr = c
        self.func = d

data_struct = {"measurement": 'vfscount',
               "tags": ['glob'],
               "fields": ['time', 'addr', 'func']}

# header
#print("Tracing... Ctrl-C to end.")

# output
# try:
#     sleep(interval)
# except KeyboardInterrupt:
#     pass

# print("\n%-16s %-26s %8s" % ("ADDR", "FUNC", "COUNT"))
# counts = b.get_table("counts")
# for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
#     print(" %-81d %-16x %-26s %8d" % (k.timestamp,k.ip, b.ksym(k.ip), v.value))

exiting=0 if interval else 1
counts = b.get_table("counts")
#print(type(data))
while (1):
    try:
        sleep(int(interval))
    except KeyboardInterrupt:
        exiting=1
    for k, v in sorted(counts.items(), key=lambda counts: counts[1].value):
        #print(" %-81d %-16x %-26s %8d" % (k.timestamp,k.ip, b.ksym(k.ip), v.value))
        # write to influxdb
        test_data = lmp_data(datetime.now().isoformat(),'glob',hex(k.ip), b.ksym(k.ip))
        # print(test_data)
        write2db(data_struct, test_data, influx_client, DatabaseType.INFLUXDB.value)


    counts.clear()

    if exiting:
        exit()

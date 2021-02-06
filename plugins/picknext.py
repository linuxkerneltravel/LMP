#!/usr/bin/python3

from bcc import BPF
from time import sleep, strftime

# for influxdb
from influxdb import InfluxDBClient
import lmp_influxdb as db
from db_modules import write2db

from datetime import datetime
from config import read_config

cfg = read_config()
DBNAME = cfg.getProperty("influxdb.dbname")
USER = cfg.getProperty("influxdb.user")
PASSWORD = cfg.getProperty("influxdb.password")


client = db.connect(DBNAME,user=USER,passwd=PASSWORD)

bpf_text = """
#include <uapi/linux/ptrace.h>

struct key_t {
    u32 cpu;
    u32 pid;
    u32 tgid;
};

BPF_HASH(start, struct key_t);
BPF_HASH(dist, struct key_t);

int pick_start(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    start.update(&key, &ts);
    return 0;
}

int pick_end(struct pt_regs *ctx)
{
    u64 ts = bpf_ktime_get_ns();
    u64 pid_tgid = bpf_get_current_pid_tgid();
    struct key_t key;
    u64 *value;
    u64 delta;

    key.cpu = bpf_get_smp_processor_id();
    key.pid = pid_tgid;
    key.tgid = pid_tgid >> 32;

    value = start.lookup(&key);

    if (value == 0) {
        return 0;
    }

    delta = ts - *value;
    start.delete(&key);
    dist.increment(key, delta);

    return 0;
}
"""

# data structure from template
class lmp_data(object):
    def __init__(self,a,b,c,d,e):
        self.time = a
        self.glob = b
        self.cpu = c
        self.pid = d
        self.duration = e


data_struct = {"measurement":'picknext',
               "time":[],
               "tags":['glob','cpu','pid',],
               "fields":['duration']}


b = BPF(text=bpf_text)
b.attach_kprobe(event="pick_next_task_fair", fn_name="pick_start")
b.attach_kretprobe(event="pick_next_task_fair", fn_name="pick_end")

dist = b.get_table("dist")

#print("%-6s%-6s%-6s%-6s" % ("CPU", "PID", "TGID", "TIME(ns)"))

while (1):
    try:
        sleep(1)
        for k, v in dist.items():
            #print("%-6d%-6d%-6d%-6d" % (k.cpu, k.pid, k.tgid, v.value))
            #test_data = lmp_data('glob', k.cpu, k.pid, v.value)
            test_data = lmp_data(datetime.now().isoformat(),'glob', k.cpu, k.pid, v.value)
            write2db(data_struct, test_data, client)
        dist.clear()
    except KeyboardInterrupt:
        exit()


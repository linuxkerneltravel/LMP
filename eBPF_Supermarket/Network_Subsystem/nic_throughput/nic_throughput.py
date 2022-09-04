#!/usr/bin/python

from __future__ import print_function
from bcc import BPF
from ctypes import *
import argparse
import os
from time import sleep,time,localtime,asctime

# pre defines -------------------------------
ROOT_PATH = "/sys/class/net"
IFNAMSIZ = 16
COL_WIDTH = 10
MAX_QUEUE_NUM = 1024

# structure for network interface name array
class Devname(Structure):
    _fields_=[
        ('name', c_char*IFNAMSIZ)
    ]

################## printer for results ###################
def to_str(num):
    s = ""
    if num > 1000000:
        return str(round(num/(1024*1024.0), 2)) + 'M'
    elif num > 1000:
        return str(round(num/1024.0, 2)) + 'K'
    else:
        if isinstance(num, float):
            return str(round(num, 2))
        else:
            return str(num)

def print_table(table, qnum):
    global print_interval

    # ---- print headers ----------------
    headers = [
		"QueueID", 
		"avg_size",
        "BPS",
        "PPS"
	]

    print(" ", end="")
    for hd in headers:
        print( "%-11s" % hd, end="")
    print()

    # ------- calculates --------------
    qids=[]
    tBPS = 0
    tPPS = 0
    tAVG = 0
    tpkt = 0
    tlen = 0
    for k, v in table.items():
        qids += [k.value]
        tlen += v.total_pkt_len
        tpkt += v.num_pkt
    tBPS = tlen / print_interval
    tPPS = tpkt / print_interval
    if tpkt != 0:
        tAVG = tlen / tpkt

    # -------- print table --------------
    for k in range(qnum):
        if k in qids:
            item = table[c_ushort(k)]
            data = [
                k,
                item.total_pkt_len,
                item.num_pkt
            ]
        else:
            data = [k,0,0]
        
        # print a line per queue
        avg = 0
        if data[2] != 0:
            avg = data[1] / data[2]
        print(" %-11d%-11s" % (
            data[0],
            to_str(avg)
        ), end="")
        BPS = data[1] / print_interval
        PPS = data[2] / print_interval
        print("%-11s%-11s" % (
            to_str(BPS),
            to_str(PPS)
        ))
    
    # ------- print total --------------
    print(" Total      %-11s" % (
        to_str(tAVG)
    ), end="")


    print("%-11s%-11s" % (
        to_str(tBPS),
        to_str(tPPS)
    ))

############## specify network interface #################
parser = argparse.ArgumentParser(description="")
parser.add_argument("-n", "--name", type=str, default="")
parser.add_argument("-i", "--interval", type=float, default=1)
parser.add_argument("-c", "--count", type=int, default=99999999, help="count of outputs")
args = parser.parse_args()

if args.name == "":
	print ("Please specify a network interface.")
	exit()
else:
	dev_name = args.name

if len(dev_name) > IFNAMSIZ-1:
    print ("NIC name too long")
    exit()

print_interval = args.interval + 0.0
if print_interval <= 0:
    print ("print interval must stricly positive")
    exit()

################ get number of queues #####################
tx_num = 0
rx_num = 0
path = ROOT_PATH + "/" + dev_name + "/queues"
if not os.path.exists(path):
	print ("Net interface", dev_name, "does not exits.")
	exit()

list = os.listdir(path)
for s in list:
    if s[0] == 'r':
        rx_num += 1
    if s[0] == 't':
        tx_num += 1

if tx_num > MAX_QUEUE_NUM or rx_num > MAX_QUEUE_NUM:
    print ("number of queues over 1024 is not supported.")
    exit()

################## start tracing ##################
b = BPF(src_file = "nic_throughput.c")
devname_map = b['name_map']
_name = Devname()
_name.name = dev_name.encode()
devname_map[0] = _name

line = 0

while 1:
    try:
        sleep(print_interval)
    except KeyboardInterrupt:
        exit()

    # --------- print tx queues ---------------
    print(asctime(localtime(time())))
    print("TX")
    table = b['tx_q']
    print_table(table, tx_num)
    b['tx_q'].clear()

    # --------- print rx queues ---------------
    print("")
    print("RX")
    table = b['rx_q']
    print_table(table, rx_num)
    b['rx_q'].clear()
    print("-"*60)

    line += 1
    if line >= args.count:
        break
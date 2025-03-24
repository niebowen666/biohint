from __future__ import print_function
from bcc import BPF
from time import sleep, strftime
from threading import Event
import argparse
import json
import sys
import os
import signal

# arguments
epilog = """examples:
    ./biohint                    # summarize block I/O hint as a histogram
    ./biohint 1 10               # print 1 second summaries, 10 times
    ./biohint -T 1               # 1s summaries,and timestamps
    ./biohint -D                 # show each disk device separately
    ./biohint -d sdc             # Trace sdc only
"""
hint = """
    0: NOT_SET
    1: NONE
    2: SHORT
    3: MEDIUM
    4: LONG
    5: EXTREME
"""
print("the program is being configured!")
parser = argparse.ArgumentParser(
    description="Summarize block device I/O latency as a histogram",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=epilog)

parser = argparse.ArgumentParser(
    description="Summarize block device I/O hint as a histogram(only useful to FDP SSD write)",
    formatter_class=argparse.RawDescriptionHelpFormatter,
    epilog=epilog)
parser.add_argument("-T", "--timestamp", action="store_true",
    help="include timestamp on output")
parser.add_argument("-D", "--disks", action="store_true",
    help="print a histogram per disk device")
parser.add_argument("interval", nargs="?", default=99999999,
    help="output interval, in seconds")
parser.add_argument("count", nargs="?", default=99999999,
    help="number of outputs")
parser.add_argument("--ebpf", action="store_true",
    help=argparse.SUPPRESS)
parser.add_argument("-d", "--disk", type=str,
    help="Trace this disk only")

args = parser.parse_args()
countdown = int(args.count)
debug = 0

bpf_text = """
#include <linux/blk_types.h>
#include <linux/blkdev.h>
#include <linux/blk-mq.h>
#include <linux/time64.h>


typedef struct disk_key {
    u64 dev;
    u64 slot;
} disk_key_t;

STORAGE

RAW_TRACEPOINT_PROBE(block_bio_queue)
{
        // TP_PROTO(struct bio *)
        
        struct bio *b = (void *)ctx->args[0];
        unsigned int flags = b->bi_opf;
        unsigned int flag = flags & REQ_OP_MASK;
        dev_t dev = b->bi_bdev->bd_dev;
        HINT_GET

        DISK_FILTER
        
        if(flag | REQ_OP_WRITE){
            STORE
        }
        return 0;
}
"""

storage_str = ""
store_str = ""
disk_filter_str = ""

if args.disks:
    storage_str += "BPF_HISTOGRAM(dist, disk_key_t);"
    store_str += """
    disk_key_t dkey = {};
    dkey.dev = dev;
    dkey.slot = hint;
    dist.atomic_increment(dkey);
    """
else:
    storage_str += "BPF_HISTOGRAM(dist);"
    store_str += "dist.atomic_increment(hint);"

if args.disk is not None:
    disk_path = os.path.join('/dev', args.disk)
    if not os.path.exists(disk_path):
        print("no such disk '%s'" % args.disk)
        exit(1)

    stat_info = os.stat(disk_path)
    dev = os.major(stat_info.st_rdev) << 20 | os.minor(stat_info.st_rdev)

    disk_filter_str = """
    if(dev != %s) {
        return 0;
    }
    """ % (dev)
    
bpf_text = bpf_text.replace("STORAGE", storage_str)
bpf_text = bpf_text.replace("STORE", store_str)
bpf_text = bpf_text.replace("DISK_FILTER", disk_filter_str)
if BPF.kernel_struct_has_field(b'bio', b'bi_write_hint') == 1:
    bpf_text = bpf_text.replace("HINT_GET", "u32 hint = b->bi_write_hint;")
else:
    bpf_text = bpf_text.replace("HINT_GET", "return 0;")
#print(bpf_text)

b = BPF(text=bpf_text)
diskstats = "/proc/diskstats"
disklookup = {}
with open(diskstats) as stats:
    for line in stats:
        a = line.split()
        disklookup[a[0] + "," + a[1]] = a[2]

def disk_print(d):
    major = d >> 20
    minor = d & ((1 << 20) - 1)

    disk = str(major) + "," + str(minor)
    if disk in disklookup:
        diskname = disklookup[disk]
    else:
        diskname = "?"

    return diskname

exiting = 0 if args.interval else 1
dist = b.get_table("dist")
print(hint)
print("configure complete! the program is running!")
while True:
    try:
        sleep(int(args.interval))
    except KeyboardInterrupt:
        exiting = 1

    if args.timestamp:
        print("%-8s\n" % strftime("%H:%M:%S"), end="")

    #if args.disks:
    dist.print_linear_hist("hint", "disk", disk_print)

    dist.clear()
    countdown -= 1
    if exiting or countdown == 0:
        exit()

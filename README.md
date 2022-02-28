# eBPF experiments

> Playing with [eBPF](https://ebpf.io/) technology.

## General Information

I've created this repository to practice and learn eBPF technology.

## Setup

In order to run the examples, you need:

- a kernel which supports eBPF (starting from version 3.15, but to use bcc features, a Linux kernel version 4.1 or newer is required. For more info follow [this](https://github.com/iovisor/bcc/blob/master/docs/kernel-versions.md#main-features) link)
- [python3](https://www.python.org/downloads/)
- [bcc](https://github.com/iovisor/bcc/)

## Usage

- **hide_pid**

This simple eBPF program hooks to the `getdents64` syscall (using [attach_tracepoint](https://github.com/iovisor/bcc/blob/master/docs/reference_guide.md#3-attach_tracepoint)) and it modifies the corresponding `linux_dirent64` kernel structure in order to "hide" the input PID.

For example, when a system utility (like `ps` or `top`) looks for process information under `/proc/PID` directory, it won't find our input PID.

By default, the eBPF program is attached to all processes. You can attach it to a specific PID list by using the `--pids` option. By using this option, the PID will be "hidden" only for the specified PIDs.

This program can be easily modified to "hide" a specific file(s) instead of the input PID.

```bash
usage: hide_pid.py [-h] [--pids PIDS [PIDS ...]] pid

Hide the specified PID by overwriting "linux_dirent64" struct when "getdents64" is called by
userspace process.

positional arguments:
  pid                   PID to hide

optional arguments:
  -h, --help            show this help message and exit
  --pids PIDS [PIDS ...]
                        Hide only to specified PIDs
```

## Contact

Created by [@lfama](https://github.com/lfama)

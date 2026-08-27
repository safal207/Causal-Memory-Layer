#!/usr/bin/env python3
"""
vCML File Monitor (v0.8 Reference Implementation)

Monitors filesystem boundary crossings (open/read syscalls) via eBPF
and generates vCML-compliant causal records.

Boundary: open / read entry / read exit (secret access detection)
Tracepoints: syscalls:sys_enter_openat, syscalls:sys_enter_read,
             syscalls:sys_exit_read

The read-entry event proves that a read syscall was attempted. The read-exit
event adds the kernel return value so consumers can distinguish successful
completion (ret >= 0, including EOF at ret == 0) from failure (ret < 0).

v0.7 introduced one stable boundary correlation token from sys_enter_read to
sys_exit_read. The token is derived from PID, TID, and a kernel monotonic
``bpf_ktime_get_ns()`` timestamp captured at entry. It is a local correlation
identity, not a cryptographic or globally unique identifier.

v0.8 resolves the file descriptor to the kernel file object at sys_enter_read
and captures the backing ``(superblock device, inode)`` pair. That object
identity is copied into the kernel read-start state and therefore remains bound
to the same read even if the numeric fd is later reused before userspace sees
the exit event. Path fields remain descriptive evidence from the userspace
last-open cache; ``object_id`` is the stronger read-boundary object binding.

Usage:
    sudo ./file_monitor.py [--secret-prefix /secrets/] [--ext .key .pem]

Requirements:
    - Root privileges
    - python3-bpfcc
    - Linux kernel with eBPF support
"""

import sys
import os
import json
import time
import uuid
import argparse

try:
    from bcc import BPF
except ImportError:
    print("Error: python3-bpfcc not found. Install with: apt install python3-bpfcc",
          file=sys.stderr)
    sys.exit(1)


BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

#define FNAME_LEN 256

struct open_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    char filename[FNAME_LEN];
    int  flags;
};

struct read_start_t {
    int fd;
    u64 count;
    u64 started_ns;
    u32 dev;
    u64 inode;
    u8  object_resolved;
};

struct read_event_t {
    u32  pid;
    u32  tid;
    u32  ppid;
    u32  uid;
    char comm[16];
    int  fd;
    u64  count;
    u64  started_ns;
    u32  dev;
    u64  inode;
    u8   object_resolved;
};

struct read_exit_event_t {
    u32  pid;
    u32  tid;
    u32  ppid;
    u32  uid;
    char comm[16];
    int  fd;
    u64  count;
    u64  started_ns;
    u32  dev;
    u64  inode;
    u8   object_resolved;
    s64  ret;
};

BPF_HASH(read_starts, u32, struct read_start_t);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(read_events);
BPF_PERF_OUTPUT(read_exit_events);

static __always_inline int resolve_fd_object(int fd, u32 *dev, u64 *inode) {
    if (fd < 0) {
        return 0;
    }

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    struct files_struct *files = NULL;
    struct fdtable *fdt = NULL;
    struct file **fd_array = NULL;
    struct file *file = NULL;
    struct inode *node = NULL;
    struct super_block *sb = NULL;
    unsigned int max_fds = 0;
    dev_t device = 0;
    unsigned long inode_number = 0;

    bpf_probe_read_kernel(&files, sizeof(files), &task->files);
    if (!files) {
        return 0;
    }

    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) {
        return 0;
    }

    bpf_probe_read_kernel(&max_fds, sizeof(max_fds), &fdt->max_fds);
    if ((u32)fd >= max_fds) {
        return 0;
    }

    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    if (!fd_array) {
        return 0;
    }

    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file) {
        return 0;
    }

    bpf_probe_read_kernel(&node, sizeof(node), &file->f_inode);
    if (!node) {
        return 0;
    }

    bpf_probe_read_kernel(&inode_number, sizeof(inode_number), &node->i_ino);
    bpf_probe_read_kernel(&sb, sizeof(sb), &node->i_sb);
    if (!sb) {
        return 0;
    }
    bpf_probe_read_kernel(&device, sizeof(device), &sb->s_dev);

    *dev = (u32)device;
    *inode = (u64)inode_number;
    return 1;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct open_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    data.flags = args->flags;

    open_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    struct read_event_t data = {};
    struct read_start_t start = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    u64 started_ns = bpf_ktime_get_ns();

    data.pid = pid_tgid >> 32;
    data.tid = tid;
    data.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd = args->fd;
    data.count = args->count;
    data.started_ns = started_ns;
    data.object_resolved = resolve_fd_object(args->fd, &data.dev, &data.inode);

    start.fd = args->fd;
    start.count = args->count;
    start.started_ns = started_ns;
    start.dev = data.dev;
    start.inode = data.inode;
    start.object_resolved = data.object_resolved;
    read_starts.update(&tid, &start);

    read_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    struct read_exit_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 tid = (u32)pid_tgid;
    struct read_start_t *start = read_starts.lookup(&tid);

    if (!start) {
        return 0;
    }

    data.pid = pid_tgid >> 32;
    data.tid = tid;
    data.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd = start->fd;
    data.count = start->count;
    data.started_ns = start->started_ns;
    data.dev = start->dev;
    data.inode = start->inode;
    data.object_resolved = start->object_resolved;
    data.ret = args->ret;

    read_exit_events.perf_submit(args, &data, sizeof(data));
    read_starts.delete(&tid);
    return 0;
}
"""


_MAX_PID_CACHE = 10_000
_MAX_READ_ATTEMPTS = 10_000


def _evict_pid(pid_causes: dict, pid_open_path: dict) -> None:
    """FIFO eviction: remove the oldest PID from both dicts to keep them in sync."""
    if len(pid_causes) >= _MAX_PID_CACHE:
        oldest = next(iter(pid_causes))
        del pid_causes[oldest]
        pid_open_path.pop(oldest, None)


def _remember_read_attempt(tid_read_attempts: dict[int, str], tid: int, record_id: str) -> None:
    """Keep per-thread read-attempt linkage bounded if exit events are lost."""
    if len(tid_read_attempts) >= _MAX_READ_ATTEMPTS and tid not in tid_read_attempts:
        oldest = next(iter(tid_read_attempts))
        del tid_read_attempts[oldest]
    tid_read_attempts[tid] = record_id


def _format_read_id(pid: int, tid: int, started_ns: int) -> str:
    """Format the kernel-originated local correlation identity for one read."""
    return f"linux-read:{pid}:{tid}:{started_ns}"


def _format_object_id(dev: int, inode: int) -> str:
    """Format the local kernel object identity captured at read entry."""
    return f"linux-inode:{dev}:{inode}"


def _append_kernel_object_identity(obj: dict, event) -> None:
    """Attach read-boundary kernel object identity when fd resolution succeeded."""
    if not int(event.object_resolved):
        return
    dev = int(event.dev)
    inode = int(event.inode)
    obj["object_id"] = _format_object_id(dev, inode)
    obj["device"] = dev
    obj["inode"] = inode
    obj["object_identity_source"] = "kernel_fd_at_sys_enter_read"


def classify_path(path: str, secret_prefixes: list, secret_exts: list) -> str:
    """Return 'SECRET' if path matches secret heuristics, else 'NORMAL'."""
    if any(path.startswith(p) for p in secret_prefixes):
        return "SECRET"
    if any(path.endswith(e) for e in secret_exts):
        return "SECRET"
    return "NORMAL"


def main():
    parser = argparse.ArgumentParser(description="vCML File Monitor (v0.8)")
    parser.add_argument(
        "--secret-prefix", nargs="*", default=["/secrets/", "/etc/ssl/", "/var/secrets/"],
        help="Path prefixes to classify as SECRET"
    )
    parser.add_argument(
        "--ext", nargs="*", default=[".key", ".pem", ".p12", ".pfx", ".crt"],
        help="File extensions to classify as SECRET"
    )
    args = parser.parse_args()

    secret_prefixes = args.secret_prefix
    secret_exts = args.ext

    print("Initializing vCML File Monitor...", file=sys.stderr)
    try:
        b = BPF(text=BPF_TEXT)
    except Exception as e:
        print(f"Error loading BPF: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Monitoring open/read-entry/read-exit events | configured_secret_prefixes={len(secret_prefixes)} "
        f"configured_secret_exts={len(secret_exts)} | Ctrl-C to stop.",
        file=sys.stderr
    )

    # Causal state: pid -> (last_causal_id, last_open_path)
    pid_causes: dict[int, str] = {}
    pid_open_path: dict[int, dict] = {}  # pid -> descriptive {path, classification}
    tid_read_attempts: dict[int, str] = {}  # tid -> read-entry record id

    def on_open(cpu, data, size):
        event = b["open_events"].event(data)
        record_id = str(uuid.uuid4())

        try:
            filename = event.filename.decode("utf-8").split("\x00", 1)[0]
        except Exception:
            filename = event.filename.decode("latin1").split("\x00", 1)[0]

        comm = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]
        classification = classify_path(filename, secret_prefixes, secret_exts)
        parent_cause = pid_causes.get(event.ppid) or pid_causes.get(event.pid)
        permitted_by = "parent_process_context" if parent_cause else "unobserved_parent"

        record = {
            "id": record_id,
            "timestamp": time.time_ns(),
            "actor": {"pid": event.pid, "ppid": event.ppid,
                      "uid": event.uid, "comm": comm},
            "action": "open",
            "object": {"path": filename, "classification": classification,
                       "flags": event.flags},
            "permitted_by": permitted_by,
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        _evict_pid(pid_causes, pid_open_path)
        pid_causes[event.pid] = record_id
        pid_open_path[event.pid] = {"path": filename, "classification": classification,
                                    "cause_id": record_id}

    def on_read(cpu, data, size):
        event = b["read_events"].event(data)
        comm = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]
        record_id = str(uuid.uuid4())
        read_id = _format_read_id(int(event.pid), int(event.tid), int(event.started_ns))

        open_ctx = pid_open_path.get(event.pid, {})
        parent_cause = pid_causes.get(event.pid)
        permitted_by = parent_cause if parent_cause else "unobserved_parent"

        obj = {
            "fd": event.fd,
            "count": event.count,
            "boundary_started_ns": int(event.started_ns),
        }
        _append_kernel_object_identity(obj, event)
        if open_ctx:
            obj["path"] = open_ctx.get("path", "")
            obj["classification"] = open_ctx.get("classification", "NORMAL")
            obj["path_evidence"] = "last_open_path_by_pid"

        record = {
            "id": record_id,
            "read_id": read_id,
            "timestamp": time.time_ns(),
            "actor": {"pid": event.pid, "tid": event.tid, "ppid": event.ppid,
                      "uid": event.uid, "comm": comm},
            "action": "read",
            "object": obj,
            "permitted_by": permitted_by,
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        _remember_read_attempt(tid_read_attempts, event.tid, record_id)
        _evict_pid(pid_causes, pid_open_path)
        pid_causes[event.pid] = record_id

    def on_read_exit(cpu, data, size):
        event = b["read_exit_events"].event(data)
        comm = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]
        record_id = str(uuid.uuid4())
        read_id = _format_read_id(int(event.pid), int(event.tid), int(event.started_ns))
        return_value = int(event.ret)
        parent_cause = tid_read_attempts.pop(event.tid, None) or pid_causes.get(event.pid)
        status = "success" if return_value >= 0 else "failure"

        obj = {
            "fd": event.fd,
            "requested_count": event.count,
            "return_value": return_value,
            "bytes_returned": return_value if return_value > 0 else 0,
            "status": status,
            "boundary_started_ns": int(event.started_ns),
        }
        _append_kernel_object_identity(obj, event)

        open_ctx = pid_open_path.get(event.pid, {})
        if open_ctx:
            obj["path"] = open_ctx.get("path", "")
            obj["classification"] = open_ctx.get("classification", "NORMAL")
            obj["path_evidence"] = "last_open_path_by_pid"

        record = {
            "id": record_id,
            "read_id": read_id,
            "timestamp": time.time_ns(),
            "actor": {"pid": event.pid, "tid": event.tid, "ppid": event.ppid,
                      "uid": event.uid, "comm": comm},
            "action": "read_exit",
            "object": obj,
            "permitted_by": "read_attempt" if parent_cause else "unobserved_read_attempt",
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        _evict_pid(pid_causes, pid_open_path)
        pid_causes[event.pid] = record_id

    b["open_events"].open_perf_buffer(on_open)
    b["read_events"].open_perf_buffer(on_read)
    b["read_exit_events"].open_perf_buffer(on_read_exit)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()

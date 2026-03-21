#!/usr/bin/env python3
"""
vCML File Monitor (v0.5 Reference Implementation)

Monitors filesystem boundary crossings (open/read syscalls) via eBPF
and generates vCML-compliant causal records.

Boundary: open / read (secret access detection)
Tracepoints: syscalls:sys_enter_openat, syscalls:sys_enter_read

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

#define FNAME_LEN 256

struct open_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    char filename[FNAME_LEN];
    int  flags;
};

struct read_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    int  fd;
    u64  count;
};

BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(read_events);

// Track open fd -> filename for read correlation
BPF_HASH(fd_map, u64, struct open_event_t);

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
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd    = args->fd;
    data.count = args->count;

    read_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


def classify_path(path: str, secret_prefixes: list, secret_exts: list) -> str:
    """Return 'SECRET' if path matches secret heuristics, else 'NORMAL'."""
    if any(path.startswith(p) for p in secret_prefixes):
        return "SECRET"
    if any(path.endswith(e) for e in secret_exts):
        return "SECRET"
    return "NORMAL"


def main():
    parser = argparse.ArgumentParser(description="vCML File Monitor (v0.5)")
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
    secret_exts     = args.ext

    print("Initializing vCML File Monitor...", file=sys.stderr)
    try:
        b = BPF(text=BPF_TEXT)
    except Exception as e:
        print(f"Error loading BPF: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        f"Monitoring open/read events | secret_prefixes={secret_prefixes} "
        f"exts={secret_exts} | Ctrl-C to stop.",
        file=sys.stderr
    )

    # Causal state: pid → (last_causal_id, last_open_path)
    pid_causes: dict[int, str] = {}
    pid_open_path: dict[int, dict] = {}  # pid → {path, classification}

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
            "id":        record_id,
            "timestamp": time.time_ns(),
            "actor":     {"pid": event.pid, "ppid": event.ppid,
                          "uid": event.uid, "comm": comm},
            "action":    "open",
            "object":    {"path": filename, "classification": classification,
                          "flags": event.flags},
            "permitted_by": permitted_by,
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        pid_causes[event.pid] = record_id
        pid_open_path[event.pid] = {"path": filename, "classification": classification,
                                    "cause_id": record_id}

    def on_read(cpu, data, size):
        event = b["read_events"].event(data)
        comm  = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]
        record_id = str(uuid.uuid4())

        open_ctx    = pid_open_path.get(event.pid, {})
        parent_cause = pid_causes.get(event.pid)
        permitted_by = parent_cause if parent_cause else "unobserved_parent"

        obj = {
            "fd":    event.fd,
            "count": event.count,
        }
        if open_ctx:
            obj["path"]           = open_ctx.get("path", "")
            obj["classification"] = open_ctx.get("classification", "NORMAL")

        record = {
            "id":        record_id,
            "timestamp": time.time_ns(),
            "actor":     {"pid": event.pid, "ppid": event.ppid,
                          "uid": event.uid, "comm": comm},
            "action":    "read",
            "object":    obj,
            "permitted_by": permitted_by,
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        pid_causes[event.pid] = record_id

    b["open_events"].open_perf_buffer(on_open)
    b["read_events"].open_perf_buffer(on_read)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()

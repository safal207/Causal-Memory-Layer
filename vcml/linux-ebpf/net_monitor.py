#!/usr/bin/env python3
"""
vCML Network Monitor (v0.5 Reference Implementation)

Monitors network egress boundary crossings (connect/sendto syscalls) via eBPF
and generates vCML-compliant causal records.

Boundary: connect / send (network egress — NET_OUT)
Tracepoints: syscalls:sys_enter_connect, syscalls:sys_enter_sendto

Usage:
    sudo ./net_monitor.py [--external-only]

Requirements:
    - Root privileges
    - python3-bpfcc
    - Linux kernel with eBPF support
"""

import sys
import json
import time
import uuid
import socket
import struct
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
#include <net/sock.h>
#include <uapi/linux/in.h>

struct connect_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    u32  daddr;   // IPv4 dest
    u16  dport;
    int  fd;
    u16  family;
};

struct send_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    char comm[16];
    int  fd;
    u64  len;
    int  flags;
};

BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(send_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct connect_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd = args->fd;

    // Read sockaddr safely
    struct sockaddr sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);
    data.family = sa.sa_family;

    if (sa.sa_family == AF_INET) {
        struct sockaddr_in sin = {};
        bpf_probe_read_user(&sin, sizeof(sin), args->uservaddr);
        data.daddr = sin.sin_addr.s_addr;
        data.dport = __builtin_bswap16(sin.sin_port);
    }

    connect_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_sendto) {
    struct send_event_t data = {};
    u64 pid_tgid = bpf_get_current_pid_tgid();
    data.pid = pid_tgid >> 32;
    data.uid = (u32)bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd    = args->fd;
    data.len   = args->len;
    data.flags = args->flags;

    send_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


_PRIVATE_RANGES = [
    ("10.0.0.0",     8),
    ("172.16.0.0",  12),
    ("192.168.0.0", 16),
    ("127.0.0.0",    8),
]


def _ip_int(addr: str) -> int:
    return struct.unpack("!I", socket.inet_aton(addr))[0]


_MAX_PID_CACHE = 10_000


def _evict_if_full(d: dict) -> None:
    """FIFO eviction: remove the oldest entry when the dict is full."""
    if len(d) >= _MAX_PID_CACHE:
        del d[next(iter(d))]


def _is_private(ip_int: int) -> bool:
    for base, prefix in _PRIVATE_RANGES:
        mask = (0xFFFFFFFF << (32 - prefix)) & 0xFFFFFFFF
        if (ip_int & mask) == (_ip_int(base) & mask):
            return True
    return False


def main():
    parser = argparse.ArgumentParser(description="vCML Network Monitor (v0.5)")
    parser.add_argument("--external-only", action="store_true",
                        help="Only emit records for non-private IP destinations")
    args = parser.parse_args()

    print("Initializing vCML Network Monitor...", file=sys.stderr)
    try:
        b = BPF(text=BPF_TEXT)
    except Exception as e:
        print(f"Error loading BPF: {e}", file=sys.stderr)
        sys.exit(1)

    print("Monitoring connect/sendto events | Ctrl-C to stop.", file=sys.stderr)

    pid_causes: dict[int, str] = {}

    def on_connect(cpu, data, size):
        event = b["connect_events"].event(data)
        comm  = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]

        ip_addr = ""
        if event.family == socket.AF_INET:
            try:
                ip_addr = socket.inet_ntoa(struct.pack("<I", event.daddr))
            except Exception:
                ip_addr = str(event.daddr)

            if args.external_only and _is_private(_ip_int(ip_addr)):
                return

        record_id    = str(uuid.uuid4())
        parent_cause = pid_causes.get(event.ppid) or pid_causes.get(event.pid)
        permitted_by = "parent_process_context" if parent_cause else "unobserved_parent"

        record = {
            "id":        record_id,
            "timestamp": time.time_ns(),
            "actor":     {"pid": event.pid, "ppid": event.ppid,
                          "uid": event.uid, "comm": comm},
            "action":    "connect",
            "object":    {"addr": ip_addr, "port": event.dport,
                          "family": event.family, "fd": event.fd},
            "permitted_by": permitted_by,
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        _evict_if_full(pid_causes)
        pid_causes[event.pid] = record_id

    def on_send(cpu, data, size):
        event = b["send_events"].event(data)
        comm  = event.comm.decode("utf-8", "replace").split("\x00", 1)[0]
        record_id    = str(uuid.uuid4())
        parent_cause = pid_causes.get(event.pid)
        permitted_by = parent_cause if parent_cause else "unobserved_parent"

        record = {
            "id":        record_id,
            "timestamp": time.time_ns(),
            "actor":     {"pid": event.pid, "ppid": event.ppid,
                          "uid": event.uid, "comm": comm},
            "action":    "send",
            "object":    {"fd": event.fd, "bytes": event.len, "flags": event.flags},
            "permitted_by": permitted_by,
            "parent_cause": parent_cause,
        }

        print(json.dumps(record), flush=True)
        _evict_if_full(pid_causes)
        pid_causes[event.pid] = record_id

    b["connect_events"].open_perf_buffer(on_connect)
    b["send_events"].open_perf_buffer(on_send)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break


if __name__ == "__main__":
    main()

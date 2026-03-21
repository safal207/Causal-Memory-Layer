#!/usr/bin/env python3
"""
vCML Combined Monitor (v0.5 Reference Implementation)

Monitors all three boundary types in a single process:
  1. exec   — process execution
  2. open/read — filesystem (secret detection)
  3. connect/send — network egress (NET_OUT)

Generates a unified JSONL causal log capturing the full chain:
  exec → secret access → network egress

Usage:
    sudo ./combined_monitor.py [options]
    sudo ./combined_monitor.py --output causal.jsonl
    sudo ./combined_monitor.py --secret-prefix /secrets/ --ext .key .pem

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
import socket
import struct
import argparse
import threading

try:
    from bcc import BPF
except ImportError:
    print("Error: python3-bpfcc not found. Install with: apt install python3-bpfcc",
          file=sys.stderr)
    sys.exit(1)


# ---------------------------------------------------------------------------
# BPF program — all boundaries
# ---------------------------------------------------------------------------

BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/in.h>

#define FNAME_LEN 256

// ---- Exec ----
struct exec_event_t {
    u32  pid; u32 ppid; u32 uid;
    char comm[16];
    char filename[FNAME_LEN];
};

// ---- Open ----
struct open_event_t {
    u32  pid; u32 ppid; u32 uid;
    char comm[16];
    char filename[FNAME_LEN];
    int  flags;
};

// ---- Connect ----
struct connect_event_t {
    u32  pid; u32 ppid; u32 uid;
    char comm[16];
    u32  daddr;
    u16  dport;
    u16  family;
    int  fd;
};

// ---- Send ----
struct send_event_t {
    u32  pid; u32 ppid; u32 uid;
    char comm[16];
    int  fd;
    u64  len;
};

BPF_PERF_OUTPUT(exec_events);
BPF_PERF_OUTPUT(open_events);
BPF_PERF_OUTPUT(connect_events);
BPF_PERF_OUTPUT(send_events);

static inline u32 get_ppid() {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    return task->real_parent->pid;
}

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct exec_event_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid  = id >> 32;
    data.uid  = (u32)bpf_get_current_uid_gid();
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_str(&data.filename, sizeof(data.filename), args->filename);
    exec_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct open_event_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid  = id >> 32;
    data.uid  = (u32)bpf_get_current_uid_gid();
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    bpf_probe_read_user_str(&data.filename, sizeof(data.filename), args->filename);
    data.flags = args->flags;
    open_events.perf_submit(args, &data, sizeof(data));
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct connect_event_t data = {};
    u64 id = bpf_get_current_pid_tgid();
    data.pid  = id >> 32;
    data.uid  = (u32)bpf_get_current_uid_gid();
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd = args->fd;
    struct sockaddr sa = {};
    bpf_probe_read_user(&sa, sizeof(sa), args->uservaddr);
    data.family = sa.sa_family;
    if (sa.sa_family == 2) { // AF_INET
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
    u64 id = bpf_get_current_pid_tgid();
    data.pid  = id >> 32;
    data.uid  = (u32)bpf_get_current_uid_gid();
    data.ppid = get_ppid();
    bpf_get_current_comm(&data.comm, sizeof(data.comm));
    data.fd  = args->fd;
    data.len = args->len;
    send_events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def _decode_str(b_arr: bytes) -> str:
    try:
        return b_arr.decode("utf-8").split("\x00", 1)[0]
    except Exception:
        return b_arr.decode("latin1").split("\x00", 1)[0]


def _classify(path: str, prefixes: list, exts: list) -> str:
    if any(path.startswith(p) for p in prefixes):
        return "SECRET"
    if any(path.endswith(e) for e in exts):
        return "SECRET"
    return "NORMAL"


def _ip_str(daddr_le: int) -> str:
    try:
        return socket.inet_ntoa(struct.pack("<I", daddr_le))
    except Exception:
        return str(daddr_le)


# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

def main():
    parser = argparse.ArgumentParser(description="vCML Combined Monitor (v0.5)")
    parser.add_argument("--output", "-o", default="-",
                        help="Output file for JSONL (default: stdout)")
    parser.add_argument(
        "--secret-prefix", nargs="*",
        default=["/secrets/", "/etc/ssl/private/", "/var/secrets/"],
    )
    parser.add_argument(
        "--ext", nargs="*",
        default=[".key", ".pem", ".p12", ".pfx", ".crt"],
    )
    parser.add_argument("--external-only", action="store_true",
                        help="Only emit NET_OUT records for non-loopback destinations")
    args = parser.parse_args()

    out = open(args.output, "w") if args.output != "-" else sys.stdout

    print("Initializing vCML Combined Monitor (v0.5)...", file=sys.stderr)
    try:
        b = BPF(text=BPF_TEXT)
    except Exception as e:
        print(f"Error loading BPF: {e}", file=sys.stderr)
        sys.exit(1)

    print(
        "Monitoring exec|open|connect|send | Ctrl-C to stop.",
        file=sys.stderr
    )

    _lock = threading.Lock()
    pid_causes: dict[int, str] = {}   # pid → last causal record id

    def emit(record: dict):
        with _lock:
            out.write(json.dumps(record) + "\n")
            out.flush()

    def parent_of(pid: int, ppid: int) -> tuple[str | None, str]:
        cause = pid_causes.get(ppid) or pid_causes.get(pid)
        perm  = "parent_process_context" if cause else "unobserved_parent"
        return cause, perm

    # -- exec --
    def on_exec(cpu, data, size):
        ev = b["exec_events"].event(data)
        rid    = str(uuid.uuid4())
        pc, pb = parent_of(ev.pid, ev.ppid)
        emit({
            "id": rid, "timestamp": time.time_ns(),
            "actor": {"pid": ev.pid, "ppid": ev.ppid, "uid": ev.uid,
                      "comm": _decode_str(ev.comm)},
            "action": "exec",
            "object": _decode_str(ev.filename),
            "permitted_by": pb,
            "parent_cause": pc,
        })
        with _lock:
            pid_causes[ev.pid] = rid

    # -- open --
    def on_open(cpu, data, size):
        ev = b["open_events"].event(data)
        rid    = str(uuid.uuid4())
        path   = _decode_str(ev.filename)
        cls    = _classify(path, args.secret_prefix, args.ext)
        pc, pb = parent_of(ev.pid, ev.ppid)
        emit({
            "id": rid, "timestamp": time.time_ns(),
            "actor": {"pid": ev.pid, "ppid": ev.ppid, "uid": ev.uid,
                      "comm": _decode_str(ev.comm)},
            "action": "open",
            "object": {"path": path, "classification": cls, "flags": ev.flags},
            "permitted_by": pb,
            "parent_cause": pc,
        })
        with _lock:
            pid_causes[ev.pid] = rid

    # -- connect --
    def on_connect(cpu, data, size):
        ev     = b["connect_events"].event(data)
        ip_str = _ip_str(ev.daddr)
        if args.external_only and (ip_str.startswith("127.") or ip_str.startswith("0.")):
            return
        rid    = str(uuid.uuid4())
        pc, pb = parent_of(ev.pid, ev.ppid)
        emit({
            "id": rid, "timestamp": time.time_ns(),
            "actor": {"pid": ev.pid, "ppid": ev.ppid, "uid": ev.uid,
                      "comm": _decode_str(ev.comm)},
            "action": "connect",
            "object": {"addr": ip_str, "port": ev.dport,
                       "family": ev.family, "fd": ev.fd},
            "permitted_by": pb,
            "parent_cause": pc,
        })
        with _lock:
            pid_causes[ev.pid] = rid

    # -- send --
    def on_send(cpu, data, size):
        ev  = b["send_events"].event(data)
        rid = str(uuid.uuid4())
        with _lock:
            pc = pid_causes.get(ev.pid)
        pb  = pc if pc else "unobserved_parent"
        emit({
            "id": rid, "timestamp": time.time_ns(),
            "actor": {"pid": ev.pid, "ppid": ev.ppid, "uid": ev.uid,
                      "comm": _decode_str(ev.comm)},
            "action": "send",
            "object": {"fd": ev.fd, "bytes": ev.len},
            "permitted_by": pb,
            "parent_cause": pc,
        })
        with _lock:
            pid_causes[ev.pid] = rid

    b["exec_events"].open_perf_buffer(on_exec)
    b["open_events"].open_perf_buffer(on_open)
    b["connect_events"].open_perf_buffer(on_connect)
    b["send_events"].open_perf_buffer(on_send)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            break

    if args.output != "-":
        out.close()


if __name__ == "__main__":
    main()

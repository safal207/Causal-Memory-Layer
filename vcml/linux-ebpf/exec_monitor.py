#!/usr/bin/env python3
# vCML Exec Monitor (Reference Implementation)
#
# This tool uses eBPF to trace process execution events and generates
# vCML-compliant causal records.
#
# It demonstrates the "Functionally Correct, Causally Questionable" invariant.

from bcc import BPF
import json
import time
import uuid
import os
import sys

# Define BPF program
bpf_text = """
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

struct data_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];
    char filename[256];
};

BPF_PERF_OUTPUT(events);

TRACEPOINT_PROBE(sched, sched_process_exec) {
    struct data_t data = {};
    struct task_struct *task;

    u64 id = bpf_get_current_pid_tgid();
    data.pid = id >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    data.uid = (u32)uid_gid;

    task = (struct task_struct *)bpf_get_current_task();
    data.ppid = task->real_parent->pid;

    bpf_get_current_comm(&data.comm, sizeof(data.comm));

    // args->filename is available in sched_process_exec tracepoint
    bpf_probe_read_str(&data.filename, sizeof(data.filename), args->filename);

    events.perf_submit(args, &data, sizeof(data));
    return 0;
}
"""

def main():
    print("Initializing vCML Exec Monitor...", file=sys.stderr)
    try:
        b = BPF(text=bpf_text)
    except Exception as e:
        print(f"Error loading BPF: {e}", file=sys.stderr)
        print("Note: This tool requires root privileges and kernel headers.", file=sys.stderr)
        sys.exit(1)

    print("Monitoring for exec events... Ctrl-C to stop.", file=sys.stderr)

    # Causal State
    # Mapping: PID -> Causal ID (of the last valid exec/cause)
    pid_causes = {}

    def print_event(cpu, data, size):
        event = b["events"].event(data)

        # Generate ID for this record
        record_id = str(uuid.uuid4())

        # Determine Parent Cause
        # We look up the PPID. If we have seen the PPID exec before, we link it.
        # Otherwise, it's a gap (null).
        parent_cause = pid_causes.get(event.ppid)
        permitted_by = "parent_process_context" if parent_cause else "unobserved_parent"

        # Timestamp (ns)
        timestamp = time.time_ns()

        # Decode filename
        try:
            filename = event.filename.decode('utf-8')
        except:
            filename = event.filename.decode('latin1')
        filename = filename.split('\x00', 1)[0]

        comm = event.comm.decode('utf-8', 'replace').split('\x00', 1)[0]

        record = {
            "id": record_id,
            "timestamp": timestamp,
            "actor": {
                "pid": event.pid,
                "ppid": event.ppid,
                "uid": event.uid,
                "comm": comm
            },
            "action": "exec",
            "object": filename,
            "permitted_by": permitted_by,
            "parent_cause": parent_cause
        }

        # Output JSONL
        print(json.dumps(record), flush=True)

        # Update state: This process (PID) is now causally linked to this record
        # In a real system, we might track process exit to clean up,
        # but for this reference implementation, we just map.
        pid_causes[event.pid] = record_id

    b["events"].open_perf_buffer(print_event)

    while True:
        try:
            b.perf_buffer_poll()
        except KeyboardInterrupt:
            exit()

if __name__ == "__main__":
    main()

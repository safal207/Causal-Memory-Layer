#!/usr/bin/env python3
"""Live kernel proof that fd reuse does not collapse file-object identity.

Exit codes:
  0  PASS
  1  FAIL after BPF loaded and the experiment executed
  77 UNSUPPORTED_ENVIRONMENT (BCC/kernel capability/tracepoint unavailable)

The workload intentionally opens and reads file A, closes it, then opens and
reads file B in the same child process. Linux normally reuses the same lowest
available numeric fd. The eBPF program captures the backing (device, inode) at
sys_enter_read and carries it through sys_exit_read. A PASS therefore proves
that one reused numeric fd remained bound to two different kernel objects at
the two read boundaries.
"""

from __future__ import annotations

import argparse
import ctypes
import json
import os
from pathlib import Path
import platform
import signal
import tempfile
import time
from typing import Any

from cml.integrations.ebpf_fd_reuse_runtime import (
    FAIL,
    PASS,
    UNSUPPORTED_ENVIRONMENT,
    evaluate_fd_reuse_runtime_proof,
)

EXIT_UNSUPPORTED = 77


BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

struct read_start_t {
    int fd;
    u64 started_ns;
    u32 dev;
    u64 inode;
    u8 object_resolved;
};

struct read_exit_event_t {
    u32 pid;
    u32 tid;
    int fd;
    u64 started_ns;
    u32 dev;
    u64 inode;
    u8 object_resolved;
    s64 ret;
};

BPF_HASH(target_pids, u32, u8);
BPF_HASH(read_starts, u32, struct read_start_t);
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
    if (!files) return 0;
    bpf_probe_read_kernel(&fdt, sizeof(fdt), &files->fdt);
    if (!fdt) return 0;
    bpf_probe_read_kernel(&max_fds, sizeof(max_fds), &fdt->max_fds);
    if ((u32)fd >= max_fds) return 0;
    bpf_probe_read_kernel(&fd_array, sizeof(fd_array), &fdt->fd);
    if (!fd_array) return 0;
    bpf_probe_read_kernel(&file, sizeof(file), &fd_array[fd]);
    if (!file) return 0;
    bpf_probe_read_kernel(&node, sizeof(node), &file->f_inode);
    if (!node) return 0;
    bpf_probe_read_kernel(&inode_number, sizeof(inode_number), &node->i_ino);
    bpf_probe_read_kernel(&sb, sizeof(sb), &node->i_sb);
    if (!sb) return 0;
    bpf_probe_read_kernel(&device, sizeof(device), &sb->s_dev);

    *dev = (u32)device;
    *inode = (u64)inode_number;
    return 1;
}

TRACEPOINT_PROBE(syscalls, sys_enter_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u8 *enabled = target_pids.lookup(&pid);
    if (!enabled) return 0;

    struct read_start_t start = {};
    start.fd = args->fd;
    start.started_ns = bpf_ktime_get_ns();
    start.object_resolved = resolve_fd_object(args->fd, &start.dev, &start.inode);
    read_starts.update(&tid, &start);
    return 0;
}

TRACEPOINT_PROBE(syscalls, sys_exit_read) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 tid = (u32)pid_tgid;
    u8 *enabled = target_pids.lookup(&pid);
    if (!enabled) return 0;

    struct read_start_t *start = read_starts.lookup(&tid);
    if (!start) return 0;

    struct read_exit_event_t data = {};
    data.pid = pid;
    data.tid = tid;
    data.fd = start->fd;
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


def _atomic_json(path: Path, payload: dict[str, Any]) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + ".tmp")
    tmp.write_text(json.dumps(payload, indent=2, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(tmp, path)


def _environment() -> dict[str, Any]:
    return {
        "kernel": platform.release(),
        "platform": platform.platform(),
        "python": platform.python_version(),
        "euid": os.geteuid(),
    }


def _unsupported(output: Path, reason: str) -> int:
    payload = {
        "schema_version": "cml-ebpf-fd-reuse-runtime-proof-v1",
        "status": UNSUPPORTED_ENVIRONMENT,
        "reason": reason,
        "environment": _environment(),
    }
    _atomic_json(output, payload)
    print(json.dumps(payload, sort_keys=True))
    return EXIT_UNSUPPORTED


def _child_workload(path_a: str, path_b: str, result_fd: int) -> None:
    os.kill(os.getpid(), signal.SIGSTOP)
    result: dict[str, Any] = {}
    try:
        fd_a = os.open(path_a, os.O_RDONLY)
        byte_a = os.read(fd_a, 1)
        os.close(fd_a)

        fd_b = os.open(path_b, os.O_RDONLY)
        byte_b = os.read(fd_b, 1)
        os.close(fd_b)

        result = {
            "fd_a": fd_a,
            "fd_b": fd_b,
            "byte_a": byte_a.decode("ascii", "strict"),
            "byte_b": byte_b.decode("ascii", "strict"),
        }
    except BaseException as exc:  # child must report even nonstandard failures
        result = {"error": f"{type(exc).__name__}: {exc}"}
    os.write(result_fd, (json.dumps(result, sort_keys=True) + "\n").encode("utf-8"))
    os.close(result_fd)
    os._exit(0 if "error" not in result else 2)


def _load_bcc():
    try:
        from bcc import BPF  # type: ignore[import-not-found]
    except Exception as exc:
        raise RuntimeError(f"BCC import failed: {type(exc).__name__}: {exc}") from exc
    return BPF


def run(output: Path, poll_timeout_seconds: float) -> int:
    tracepoint = Path("/sys/kernel/tracing/events/syscalls/sys_enter_read/id")
    legacy_tracepoint = Path("/sys/kernel/debug/tracing/events/syscalls/sys_enter_read/id")
    if not tracepoint.exists() and not legacy_tracepoint.exists():
        return _unsupported(output, "sys_enter_read tracepoint is unavailable")

    with tempfile.TemporaryDirectory(prefix="cml-ebpf-fd-reuse-") as temp_dir:
        root = Path(temp_dir)
        path_a = root / "a.txt"
        path_b = root / "b.txt"
        path_a.write_bytes(b"A")
        path_b.write_bytes(b"B")
        stat_a = path_a.stat()
        stat_b = path_b.stat()

        result_r, result_w = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            os.close(result_r)
            _child_workload(str(path_a), str(path_b), result_w)
            raise AssertionError("unreachable")

        os.close(result_w)
        _, stopped_status = os.waitpid(child_pid, os.WUNTRACED)
        if not os.WIFSTOPPED(stopped_status):
            os.close(result_r)
            return _unsupported(output, "workload child did not enter synchronization stop")

        try:
            BPF = _load_bcc()
            bpf = BPF(text=BPF_TEXT)
        except Exception as exc:
            os.kill(child_pid, signal.SIGKILL)
            os.waitpid(child_pid, 0)
            os.close(result_r)
            return _unsupported(output, f"BPF load failed: {type(exc).__name__}: {exc}")

        events: list[dict[str, int]] = []

        def on_read_exit(cpu, data, size):  # noqa: ANN001
            event = bpf["read_exit_events"].event(data)
            events.append(
                {
                    "pid": int(event.pid),
                    "tid": int(event.tid),
                    "fd": int(event.fd),
                    "started_ns": int(event.started_ns),
                    "device": int(event.dev),
                    "inode": int(event.inode),
                    "object_resolved": int(event.object_resolved),
                    "return_value": int(event.ret),
                }
            )

        bpf["read_exit_events"].open_perf_buffer(on_read_exit, page_cnt=8)
        bpf["target_pids"][ctypes.c_uint(child_pid)] = ctypes.c_ubyte(1)
        os.kill(child_pid, signal.SIGCONT)

        deadline = time.monotonic() + poll_timeout_seconds
        child_done = False
        child_status = None
        while time.monotonic() < deadline:
            bpf.perf_buffer_poll(timeout=50)
            if not child_done:
                waited_pid, status = os.waitpid(child_pid, os.WNOHANG)
                if waited_pid == child_pid:
                    child_done = True
                    child_status = status
            if child_done and len(events) >= 2:
                break

        # Drain any event already queued after the child exited.
        for _ in range(5):
            bpf.perf_buffer_poll(timeout=20)

        if not child_done:
            os.kill(child_pid, signal.SIGKILL)
            _, child_status = os.waitpid(child_pid, 0)

        raw_result = os.read(result_r, 65536)
        os.close(result_r)
        try:
            workload = json.loads(raw_result.decode("utf-8")) if raw_result else {}
        except Exception as exc:
            workload = {"error": f"invalid child result: {type(exc).__name__}: {exc}"}

        if not isinstance(workload, dict) or "error" in workload:
            payload = {
                "schema_version": "cml-ebpf-fd-reuse-runtime-proof-v1",
                "status": FAIL,
                "reason": "workload failed",
                "workload": workload,
                "events": events,
                "environment": _environment(),
            }
            _atomic_json(output, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1

        verdict = evaluate_fd_reuse_runtime_proof(
            expected_a={"device": int(stat_a.st_dev), "inode": int(stat_a.st_ino)},
            expected_b={"device": int(stat_b.st_dev), "inode": int(stat_b.st_ino)},
            workload=workload,
            events=events,
        )
        verdict["environment"] = _environment()
        verdict["child_exit_status"] = child_status
        verdict["paths"] = {"a": str(path_a), "b": str(path_b)}
        _atomic_json(output, verdict)
        print(json.dumps(verdict, sort_keys=True))
        return 0 if verdict["status"] == PASS else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/ebpf-runtime/fd-reuse-proof.json"),
    )
    parser.add_argument("--poll-timeout-seconds", type=float, default=5.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raise SystemExit(run(args.output, args.poll_timeout_seconds))


if __name__ == "__main__":
    main()

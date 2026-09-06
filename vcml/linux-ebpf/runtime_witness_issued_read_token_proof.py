#!/usr/bin/env python3
"""Live proof of witness-issued one-shot read identity binding.

Exit codes:
  0  PASS
  1  FAIL after the experiment executed
  77 UNSUPPORTED_ENVIRONMENT (BCC/kernel capability/tracepoint unavailable)

The witness controller issues one 128-bit correlation token and places it in a
kernel BPF map for the stopped target thread. The application child receives the
same token out-of-band, then performs two reads on one fd:

1. the first read consumes the token at ``sys_enter_read`` and the application
   authors a separate CML ``read`` record carrying that token;
2. the second read receives no new token and acts as a negative control proving
   the first token was not reusable thread state.

The kernel completion witness is reconciled against the application-authored
CML record through the existing exact read-id and read-object coverage checks.
The ledger never derives its token from the BPF completion event.
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
import uuid
from typing import Any

from cml.integrations.witness_issued_read_token_runtime import (
    FAIL,
    PASS,
    SCHEMA_VERSION,
    evaluate_witness_issued_read_token_runtime_proof,
    kernel_object_id,
)
from cml.record import Action, Actor, CausalRecord

EXIT_UNSUPPORTED = 77
LINUX_MINOR_BITS = 20
LINUX_MINOR_MASK = (1 << LINUX_MINOR_BITS) - 1


BPF_TEXT = r"""
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <linux/fs.h>
#include <linux/fdtable.h>

struct read_token_t {
    u64 hi;
    u64 lo;
};

struct read_start_t {
    int fd;
    u64 started_ns;
    u32 dev;
    u64 inode;
    u8 object_resolved;
    u8 token_present;
    u64 token_hi;
    u64 token_lo;
};

struct read_exit_event_t {
    u32 pid;
    u32 tid;
    int fd;
    u64 started_ns;
    u32 dev;
    u64 inode;
    u8 object_resolved;
    u8 token_present;
    u64 token_hi;
    u64 token_lo;
    s64 ret;
};

BPF_HASH(target_pids, u32, u8);
BPF_HASH(active_read_tokens, u32, struct read_token_t);
BPF_HASH(read_starts, u32, struct read_start_t);
BPF_PERF_OUTPUT(read_exit_events);

static __always_inline int resolve_fd_object(int fd, u32 *dev, u64 *inode) {
    if (fd < 0) return 0;

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

    struct read_token_t *token = active_read_tokens.lookup(&tid);
    if (token) {
        start.token_present = 1;
        start.token_hi = token->hi;
        start.token_lo = token->lo;

        // One-shot consumption occurs at the actual read-use boundary. The
        // token is copied into read_starts first so sys_exit_read can still
        // attest the same use even though active state is already gone.
        active_read_tokens.delete(&tid);
    }

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
    data.token_present = start->token_present;
    data.token_hi = start->token_hi;
    data.token_lo = start->token_lo;
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
        "schema_version": SCHEMA_VERSION,
        "status": "UNSUPPORTED_ENVIRONMENT",
        "reason": reason,
        "environment": _environment(),
    }
    _atomic_json(output, payload)
    print(json.dumps(payload, sort_keys=True))
    return EXIT_UNSUPPORTED


def _format_read_id(token_hi: int, token_lo: int) -> str:
    return f"witness-read:{token_hi:016x}{token_lo:016x}"


def _kernel_raw_device_from_userspace(st_dev: int) -> int:
    major = os.major(st_dev)
    minor = os.minor(st_dev)
    if minor > LINUX_MINOR_MASK:
        raise ValueError("userspace device minor exceeds Linux kernel dev_t proof range")
    return (major << LINUX_MINOR_BITS) | minor


def _child_workload(
    path: str,
    read_id: str,
    object_id: str,
    result_fd: int,
) -> None:
    """Author the ledger observation independently from BPF completion output."""

    os.kill(os.getpid(), signal.SIGSTOP)
    result: dict[str, Any]
    try:
        fd = os.open(path, os.O_RDONLY)
        first = os.read(fd, 1)

        record = CausalRecord.new(
            actor=Actor(
                pid=os.getpid(),
                uid=os.getuid(),
                ppid=os.getppid(),
                comm="cml-token-proof",
            ),
            action=Action.READ,
            object_={
                "fd": fd,
                "path": path,
                "object_id": object_id,
                "object_identity_source": "userspace_stat_reencoded_to_kernel_dev",
                "observation_source": "application_ledger",
            },
            permitted_by=f"witness_token:{read_id}",
            read_id=read_id,
        )

        # Deliberate negative control: same thread and same fd perform another
        # read without receiving a second witness token.
        second = os.read(fd, 1)
        os.close(fd)

        result = {
            "fd": fd,
            "first_byte": first.decode("ascii", "strict"),
            "second_byte": second.decode("ascii", "strict"),
            "ledger_record": record.to_dict(),
        }
    except BaseException as exc:
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


def _map_contains(table, key_value: int) -> bool:  # noqa: ANN001
    key = table.Key(key_value)
    try:
        table[key]
    except KeyError:
        return False
    return True


def run(output: Path, poll_timeout_seconds: float) -> int:
    tracepoint = Path("/sys/kernel/tracing/events/syscalls/sys_enter_read/id")
    legacy_tracepoint = Path("/sys/kernel/debug/tracing/events/syscalls/sys_enter_read/id")
    if not tracepoint.exists() and not legacy_tracepoint.exists():
        return _unsupported(output, "sys_enter_read tracepoint is unavailable")

    token_int = uuid.uuid4().int
    token_hi = (token_int >> 64) & ((1 << 64) - 1)
    token_lo = token_int & ((1 << 64) - 1)
    issued_read_id = _format_read_id(token_hi, token_lo)
    scope_id = f"runtime-witness-token:{issued_read_id}"

    with tempfile.TemporaryDirectory(prefix="cml-witness-token-") as temp_dir:
        root = Path(temp_dir)
        path = root / "payload.txt"
        path.write_bytes(b"AB")
        stat_result = path.stat()
        expected_raw_device = _kernel_raw_device_from_userspace(int(stat_result.st_dev))
        expected_object_id = kernel_object_id(
            expected_raw_device,
            int(stat_result.st_ino),
        )

        result_r, result_w = os.pipe()
        child_pid = os.fork()
        if child_pid == 0:
            os.close(result_r)
            _child_workload(str(path), issued_read_id, expected_object_id, result_w)
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

        events: list[dict[str, Any]] = []

        def on_read_exit(cpu, data, size):  # noqa: ANN001
            event = bpf["read_exit_events"].event(data)
            token_present = bool(int(event.token_present))
            read_id = None
            if token_present:
                read_id = _format_read_id(int(event.token_hi), int(event.token_lo))
            events.append(
                {
                    "pid": int(event.pid),
                    "tid": int(event.tid),
                    "fd": int(event.fd),
                    "started_ns": int(event.started_ns),
                    "device": int(event.dev),
                    "inode": int(event.inode),
                    "object_resolved": int(event.object_resolved),
                    "token_present": int(token_present),
                    "read_id": read_id,
                    "return_value": int(event.ret),
                }
            )

        bpf["read_exit_events"].open_perf_buffer(on_read_exit, page_cnt=8)

        target_table = bpf["target_pids"]
        target_table[target_table.Key(child_pid)] = target_table.Leaf(1)

        token_table = bpf["active_read_tokens"]
        token_leaf = token_table.Leaf()
        token_leaf.hi = token_hi
        token_leaf.lo = token_lo
        token_table[token_table.Key(child_pid)] = token_leaf

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

        for _ in range(5):
            bpf.perf_buffer_poll(timeout=20)

        if not child_done:
            os.kill(child_pid, signal.SIGKILL)
            _, child_status = os.waitpid(child_pid, 0)

        token_consumed = not _map_contains(token_table, child_pid)

        raw_result = os.read(result_r, 65536)
        os.close(result_r)
        try:
            workload = json.loads(raw_result.decode("utf-8")) if raw_result else {}
        except Exception as exc:
            workload = {"error": f"invalid child result: {type(exc).__name__}: {exc}"}

        if not isinstance(workload, dict) or "error" in workload:
            payload = {
                "schema_version": SCHEMA_VERSION,
                "status": FAIL,
                "reason": "application ledger workload failed",
                "issued_read_id": issued_read_id,
                "token_consumed": token_consumed,
                "workload": workload,
                "events": events,
                "environment": _environment(),
            }
            _atomic_json(output, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1

        events.sort(key=lambda item: item["started_ns"])
        if len(events) != 2:
            payload = {
                "schema_version": SCHEMA_VERSION,
                "status": FAIL,
                "reason": "expected exactly two target read completions",
                "issued_read_id": issued_read_id,
                "token_consumed": token_consumed,
                "workload": workload,
                "events": events,
                "environment": _environment(),
            }
            _atomic_json(output, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1

        ledger_raw = workload.get("ledger_record")
        try:
            if not isinstance(ledger_raw, dict):
                raise ValueError("ledger_record must be an object")
            ledger_record = CausalRecord.from_dict(ledger_raw)
        except Exception as exc:
            payload = {
                "schema_version": SCHEMA_VERSION,
                "status": FAIL,
                "reason": f"invalid application ledger record: {type(exc).__name__}: {exc}",
                "issued_read_id": issued_read_id,
                "token_consumed": token_consumed,
                "workload": workload,
                "events": events,
                "environment": _environment(),
            }
            _atomic_json(output, payload)
            print(json.dumps(payload, sort_keys=True))
            return 1

        verdict = evaluate_witness_issued_read_token_runtime_proof(
            scope_id=scope_id,
            issued_read_id=issued_read_id,
            bound_event=events[0],
            followup_event=events[1],
            ledger_record=ledger_record,
            token_consumed=token_consumed,
        )
        verdict["environment"] = _environment()
        verdict["child_exit_status"] = child_status
        verdict["path"] = str(path)
        verdict["expected_object_id_from_userspace_stat"] = expected_object_id
        verdict["userspace_stat"] = {
            "st_dev": int(stat_result.st_dev),
            "device_major": os.major(stat_result.st_dev),
            "device_minor": os.minor(stat_result.st_dev),
            "inode": int(stat_result.st_ino),
        }
        verdict["workload"] = {
            "fd": workload.get("fd"),
            "first_byte": workload.get("first_byte"),
            "second_byte": workload.get("second_byte"),
        }

        _atomic_json(output, verdict)
        print(json.dumps(verdict, sort_keys=True))
        return 0 if verdict["status"] == PASS else 1


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument(
        "--output",
        type=Path,
        default=Path("artifacts/ebpf-runtime/witness-issued-read-token-proof.json"),
    )
    parser.add_argument("--poll-timeout-seconds", type=float, default=5.0)
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    raise SystemExit(run(args.output, args.poll_timeout_seconds))


if __name__ == "__main__":
    main()

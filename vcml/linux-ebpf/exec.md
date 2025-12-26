# Boundary: Process Execution (`exec`)

## Definition

The **Process Execution** boundary occurs when a process replaces its memory image with a new program.
In Linux, this corresponds to the `execve` family of system calls.

This is distinct from `fork` (which duplicates the existing image).
`exec` represents a commitment to a new intent.

## Why it is a Causal Boundary

1.  **Irreversibility**: Once `exec` succeeds, the previous program logic is gone. The process identity (PID) persists, but the *agent* logic changes.
2.  **Intent Manifestation**: Loading a new binary is the primary way a system transitions from "planning" (shell, launcher) to "doing" (application).
3.  **Responsibility Transfer**: The parent process (or the previous image) "permits" the new image to run.

## Causal Record

When this boundary is crossed, vCML records:

-   **Action**: `exec`
-   **Object**: The path to the new executable (e.g., `/usr/bin/python3`).
-   **Permitted By**: The context of the calling process (`parent_process_context`).
-   **Parent Cause**: The causal ID responsible for the execution.

### Scenarios

1.  **Causal Chain**: The calling process has a known causal ID. This ID becomes the `parent_cause`.
2.  **Causal Gap**: The calling process is unknown to vCML (e.g., started before the monitor, or external). `parent_cause` is `null`.

The goal is to observe these transitions without interfering.

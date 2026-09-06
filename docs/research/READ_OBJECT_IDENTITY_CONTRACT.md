# Read Object Identity Contract v0.1

## Goal

Strengthen exact read coverage from:

```text
read_id exists in persisted observations
```

to:

```text
for every external successful (read_id, object_id):
    persisted_read_object[read_id] == object_id
```

## Linux reference identity

The vCML eBPF file monitor captures object identity at `sys_enter_read` by resolving the current numeric fd through the task fd table to its kernel file object, inode, and superblock device.

The local identifier is formatted as:

```text
linux-inode:<device>:<inode>
```

The `(device, inode)` pair is stored in the kernel read-start map together with `read_id`, then copied unchanged to `sys_exit_read`. This prevents later fd reuse from changing the object identity attached to that read boundary.

## Evidence hierarchy

```text
count coverage
  < read_id coverage
  < (read_id, object_id) coverage
```

Numeric fd equality is not object equality. Path-string equality is also not object equality.

The current path field remains descriptive evidence from the last-open-by-PID cache. When present it is labelled:

```text
path_evidence = last_open_path_by_pid
```

Exact object coverage uses `object_id`, not the path cache.

## Fail-closed rules

- A successful or EOF `read_exit` must carry both `read_id` and `object_id` for object-level projection.
- A failed read may be object-unresolved.
- A persisted `read` with `read_id` but no `object_id` is valid legacy evidence but cannot satisfy exact object coverage.
- A `read_exit` record cannot satisfy persisted read coverage by itself.
- Duplicate external or persisted `read_id` values fail closed.
- A witness from another scope cannot cover the current scope.

## Non-claims

`linux-inode:<device>:<inode>` is a local correlation identity. It is not a content digest, a permanent pathname, or a stable identifier across unrelated machines and time scopes.

## Required negative controls

1. Same `read_id`, different `object_id` => fail.
2. Same fd, different object identity => remain distinguishable.
3. Same path, different object identity => fail.
4. Missing persisted object binding => fail.
5. Missing persisted read entry => fail separately.
6. Stored `read_exit` without a matching `read` entry => fail.

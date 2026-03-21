# CML SDK — Quick Start

## Installation

```bash
pip install causal-memory-layer
```

Or from source:

```bash
git clone https://github.com/safal207/Causal-Memory-Layer.git
cd Causal-Memory-Layer
pip install -e ".[dev]"
```

---

## 1. Run an Audit

The fastest way to use CML is the CLI:

```bash
# Audit a JSONL causal log
cml audit examples/secret_to_net_log.jsonl

# Human-readable Markdown report
cml audit examples/secret_to_net_log.jsonl --format markdown

# With custom config
cml audit production.jsonl --config audit_config.yaml --format json
```

Expected output (text):
```
CML Audit: 8 records | FAIL=1 WARN=0 OK=7
Status: FAIL
  [FAIL] CML-AUDIT-R3-SECRET_NET_MISSING_CHAIN @ b3: ...
```

---

## 2. Reconstruct a Causal Chain

```bash
cml chain examples/secret_to_net_log.jsonl a4
```

Output:
```
Chain for a4 (4 records, root-first):

  [a1......] ts=... action=exec     obj='/usr/bin/reporter'  permitted_by=root_event:init
→ [a2......] ts=... action=open     obj={"path":"/secrets/…  permitted_by=fs:read
→ [a3......] ts=... action=read     obj={"path":"/secrets/…  permitted_by=a2
→ [a4......] ts=... action=connect  obj={"addr":"203.0.113…  permitted_by=net:egress
```

---

## 3. Compute a CTAG

```bash
# Compute CTAG for a USER domain EXEC action, generation 1
cml ctag --dom USER --class EXEC --gen 1 --parent "550e8400-e29b-41d4-a716-446655440000"

# Decode an existing CTAG hex value
cml decode 0x4132
```

---

## 4. Use the Python SDK

```python
from cml import load_jsonl, AuditEngine, AuditConfig, to_markdown, records_to_index

# Load a causal log
records = load_jsonl("examples/secret_to_net_log.jsonl")

# Run audit with default config
engine = AuditEngine()
result = engine.run(records)

print(f"Passed: {result.passed()}")
print(f"Failures: {result.failures}")
for f in result.findings:
    print(f"  [{f.severity}] {f.code}: {f.message}")

# Generate Markdown report
index = records_to_index(records)
report = to_markdown(result, log_path="examples/secret_to_net_log.jsonl", index=index)
print(report)
```

---

## 5. Create Causal Records Programmatically

```python
from cml import CausalRecord, Actor, Action, CTAGState, DOM, CLASS

state = CTAGState(dom=DOM.USER, gen=0)

# Root event (system init)
root = CausalRecord.new(
    actor=Actor(pid=1, uid=0, comm="init"),
    action=Action.EXEC,
    object_="/sbin/init",
    permitted_by="root_event:system_boot",
)

# Compute CTAG for next action
ctag = state.next(Action.EXEC, CLASS.EXEC, parent_cause_id=root.id)

# Child process
child = CausalRecord.new(
    actor=Actor(pid=1234, uid=1000, ppid=1, comm="myapp"),
    action=Action.EXEC,
    object_="/usr/bin/myapp",
    permitted_by="parent_process_context",
    parent_cause=root.id,
    ctag=ctag,
)

print(child.to_jsonl())
```

---

## 6. Start the REST API

```bash
# Install API dependencies
pip install "causal-memory-layer[api]"

# Start server
uvicorn api.server:app --reload --port 8080

# Audit a log via API
curl -X POST http://localhost:8080/audit \
  -H "Content-Type: application/json" \
  -d '{"log": "<paste JSONL here>", "format": "json"}'
```

API docs available at: http://localhost:8080/docs

---

## 7. Run Monitors (requires root + Linux eBPF)

```bash
# Monitor process execution
sudo python3 vcml/linux-ebpf/exec_monitor.py > exec.jsonl

# Monitor file + network + exec (full multi-boundary)
sudo python3 vcml/linux-ebpf/combined_monitor.py --output causal.jsonl

# Then audit the captured log
cml audit causal.jsonl --format markdown --output report.md
```

---

## Next Steps

- [Enterprise Compliance Guide](../enterprise/compliance_guide.md)
- [CTAG Specification](../../vcml/CTAG.md)
- [Audit Rules Reference](../../vcml/audit.md)
- [Multi-Boundary Semantics](../../vcml/multi_boundary.md)
- [REST API Reference](http://localhost:8080/docs)

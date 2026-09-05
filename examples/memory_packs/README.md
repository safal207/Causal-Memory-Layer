# CML Memory Pack examples

These files are portable advisory memory projections. They are not executable policies and grant no approval, merge, or runtime authority.

## Verify an example

```python
from pathlib import Path

from cml.integrations import load_memory_pack_json, verify_memory_pack

path = Path("examples/memory_packs/coderabbit_qodo_recovery_v1.json")
pack = load_memory_pack_json(path.read_text(encoding="utf-8"))
result = verify_memory_pack(pack)

assert result.passed(), result.findings
print(pack.pack_id)
print(" -> ".join(pack.graph.selected_path))
```

## Current example

`coderabbit_qodo_recovery_v1.json` captures the best-known path learned from a missed reviewer-fallback lifecycle and the protected reconciliation added in PR #179.

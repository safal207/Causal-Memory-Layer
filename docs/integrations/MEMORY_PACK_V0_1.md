# CML Memory Pack v0.1

`cml-memory-pack-v1` is a portable, content-addressed format for sharing learned decision memory between repositories, teams, and agents.

The package records more than an event log. It preserves a graph of the situation, candidate paths, causal links, checks, outcomes, and the currently selected best-known path.

## What the contract proves

A passing verifier proves that:

- the package matches its canonical SHA-256 `pack_id`;
- the graph has unique node and edge identities;
- all edge endpoints exist;
- all evidence references resolve inside the package;
- `selected_path` is a real directed path from a `situation` node to an `outcome` or `lesson` node;
- public or partner packages declare that they contain no private data;
- the package grants neither merge nor execution authority.

It does **not** prove that:

- observations are true;
- evidence is independent or complete;
- a causal claim is scientifically established;
- the selected path is globally optimal;
- a locator still resolves;
- a digest has been externally signed or anchored.

Those guarantees require separate evidence and trust systems.

## Top-level structure

```json
{
  "schema_version": "cml-memory-pack-v1",
  "pack_id": "<sha256>",
  "manifest": {},
  "graph": {
    "nodes": [],
    "edges": [],
    "selected_path": []
  },
  "evidence": [],
  "redactions": []
}
```

`pack_id` is the SHA-256 digest of compact, sorted UTF-8 JSON containing every top-level field except `pack_id` itself. Node, edge, evidence, and redaction collections are canonically sorted before hashing. `selected_path` keeps its declared order because path order is authoritative.

## Manifest and privacy boundary

The manifest declares:

- source project, repository, and exact 40-character Git commit;
- creation timestamp in RFC3339 UTC with millisecond precision;
- visibility: `private`, `team`, `partner`, or `public`;
- license;
- whether the projection still contains private data;
- an advisory-only authority boundary.

Both of the following fields must always be false:

```json
{
  "merge_authority": false,
  "execution_authority": false
}
```

A `public` or `partner` package with `contains_private_data: true` fails verification, and the official issuer refuses to create it.

This is a declaration boundary, not a secret scanner. Producers remain responsible for removing secrets, personal data, private source code, raw prompts, internal URLs, and other restricted material before export.

## Graph model

### Node kinds

- `situation`
- `cause`
- `constraint`
- `option`
- `action`
- `check`
- `outcome`
- `lesson`
- `evidence`

### Node statuses

- `observed`
- `proposed`
- `tested`
- `verified`
- `failed`
- `superseded`

Each node also carries a confidence score from 0 to 100 and an arbitrary JSON `attributes` object. Attributes are authoritative and therefore affect `pack_id`.

### Edge relations

- `causes`
- `supports`
- `contradicts`
- `requires`
- `blocks`
- `mitigates`
- `leads_to`
- `selected_over`
- `supersedes`

Each edge has a strength from 0 to 100 and may reference one or more evidence records.

### Best-known path

`selected_path` identifies the ordered route currently preferred for the described situation. The verifier requires:

1. every path node to exist;
2. no repeated path node;
3. the first node to be a `situation`;
4. the last node to be an `outcome` or `lesson`;
5. every consecutive pair to have a directed edge in the graph.

The path is explicitly “best-known”, not permanently or universally best. Later packs can supersede it with new observations and stronger evidence.

## Evidence references

Evidence records contain:

- stable evidence ID;
- kind: `commit`, `workflow_run`, `artifact`, `review`, `test`, or `document`;
- lowercase SHA-256 digest;
- locator;
- human-readable description.

The core contract validates the digest syntax and internal references. It does not fetch the locator or recompute remote content. Importers that need stronger assurance should resolve and verify evidence in a separate, sandboxed step.

## Redactions

Redactions declare paths deliberately excluded from the shared projection and explain why. They do not reconstruct removed data and do not prove that all sensitive material was found.

Example:

```json
{
  "path": "graph.nodes[*].attributes.private_notes",
  "reason": "Private maintainer notes are excluded from the public projection."
}
```

## Python API

```python
from cml.integrations import load_memory_pack_json, verify_memory_pack

pack = load_memory_pack_json(text)
result = verify_memory_pack(pack)

if not result.passed():
    for finding in result.findings:
        print(finding.code, finding.message)
```

To create a package, construct `MemoryPackManifestV1`, `MemoryGraphV1`, evidence records, and redactions, then call `issue_memory_pack`. The issuer calculates the deterministic ID and rejects an unsafe public or partner projection.

## Sharing workflow

Recommended publication flow:

```text
private operational memory
        ↓ explicit projection
sensitive fields removed
        ↓ redactions declared
Memory Pack issued
        ↓ local verification
review + CI evidence attached
        ↓
Git commit, release asset, registry, or partner channel
```

Recommended import flow:

```text
receive pack
    ↓ parse strict JSON
verify pack identity and graph
    ↓ apply local trust policy
resolve evidence if required
    ↓
use as advisory retrieval context
```

Imported memory must never be interpreted as an approval, command, executable policy, or permission to merge.

## Reference example

`examples/memory_packs/coderabbit_qodo_recovery_v1.json` records the decision path learned from the CodeRabbit rate-limit and Qodo fallback recovery cycle around issues and PRs #168–#179.

Its best-known path is:

```text
missed fallback lifecycle
→ external event delivery is not guaranteed
→ protected exact-head reconciliation
→ independent exact-head checks
→ recovery merged without authority
→ reusable lesson for future external-bot workflows
```

# Mem0: mutation time is not fact currentness

A bounded consumer counterexample for [mem0ai/mem0 #7535](https://github.com/mem0ai/mem0/issues/7535), executed on Python OSS 2.2.1 source commit `b7ad69afda6b6ed030347c66d48a13e4de9dec08`.

A metadata-only public update preserves a January synthetic statement but refreshes its `updated_at` to October. With the June candidate unchanged, an explicit application comparator sorting by `updated_at` reverses its order. The native scorer, called with the same fixed synthetic relevance scores, preserves its order. Neither ordering adjudicates which statement is true or currently applicable.

| Observed field/control | Before | After audit tag |
|---|---|---|
| January text/hash/created_at | January statement | unchanged |
| January updated_at | January | October |
| June payload | June statement | byte-identical |
| Explicit application timestamp ordering | June, January | January, June |
| Native scorer with fixed inputs 0.9/0.6 | June, January | June, January |
| Native SQLite UPDATE history | no rows | same old/new text, October mutation time |

Exactly two cases exercise real `Memory`/`AsyncMemory` constructors and public `update()` methods. `_update_memory`, `SQLiteManager` and `score_and_rank` are unpatched. Provider factories return local adapters; embedding and vector-store effects are synthetic. Telemetry/notices and the module clock are controlled. Python socket connection/DNS attempts are denied and counted; both cases recorded zero. This is not an OS-wide network sandbox.

## Reproduce

Use Python 3.12 (tested 3.12.14), install Hatch, clone Mem0, and check out the exact source commit. From this directory:

```sh
hatch env create
hatch run python verify_evidence.py
hatch run python replay.py --source /absolute/path/to/mem0 --output /tmp/mem0-attempt.json
```

The detached Hatch environment pins the captured dependency versions. Published `mem0ai==2.2.1` supplies dependencies/package metadata; the runner sets `PYTHONPATH` to the pinned checkout and the fixture asserts the actual native module path. The runner rejects another SHA, dirty tracked/untracked source files, changed source bindings, overwritten output, or incomplete execution. Read `scope.md` before running. Each invocation starts a fresh pytest process.

Two retained attempts each passed 2/2 with zero failures/errors/skips. `evidence/semantic-replay.json` compares all relevant snapshots, counts, event order and history fields, excluding random SQLite row IDs and checkout paths. The baseline checks passed 15 native update tests, 21 native scoring tests and 17 CML applicability/lineage tests. These are separate suites; no dedicated native CI run is claimed.

## Proposed upstream change

`updated-at-note.patch` adds one Python-only `<Note>` after the existing metadata-only update note in `docs/core-concepts/memory-operations/update.mdx`. `proposed-update.mdx` is the complete proposed page. No page, navigation, schema or ranking implementation is added.

Patch applicability and the existing `llms.txt` checker passed. Mintlify preview and strict validation were **BLOCKED before build** by `uv_interface_addresses` in this execution environment. `make -B docs` was used because plain `make docs` treats the existing directory as up to date. A rendered preview remains outstanding.

Existing [#7562](https://github.com/mem0ai/mem0/pull/7562) already tests metadata-only timestamp updates and proposes avoiding re-embedding; this packet does not compete with that implementation. The narrow addition is the application ordering counterexample and its semantic warning. The updated_at workaround in [#7535](https://github.com/mem0ai/mem0/issues/7535) is a participant suggestion; native `score_and_rank` does not rank by timestamps. [#7538](https://github.com/mem0ai/mem0/pull/7538) was closed unmerged at the issue acceptance gate. This documentation note does **not** close #7535.

## Boundaries

No LLM extraction or answers, fact-truth oracle, historical-as-of contract, hosted Platform, TypeScript SDK, live vector database, persistence restart proof, or production traffic. The fixture does not implement supersession. Causal-Memory-Layer hosts this example; its runtime is not integrated into Mem0 and does not resolve these records.

F3 refers only to the reproducible bounded observation. It is not a confirmed defect, framework safety verdict, maintainer acceptance, or merge authority. The closed manifest checks byte identity/membership, not semantic truth. AI-generated fixture and documentation with independent agent review; no human review claimed.

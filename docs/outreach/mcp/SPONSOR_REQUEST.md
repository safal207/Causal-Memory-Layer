# Ready-to-post MCP sponsor and direction request

Post this as a reply in [MCP Discussion #2493](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2493).

---

Following up with a concrete implementation and a narrower process question.

We now have a working portable execution-record prototype for multi-server MCP workflows:

- a CAEP JSON profile separating intent, authorization, decision, exact dispatch, observed outcome, independent verification, and recovery;
- schema, semantic, temporal, digest, and causal-parent validation;
- real official MCP Python SDK sessions over stdio with separate action and verifier server processes;
- a stale-state duplicate-payment scenario where the tool returns success but the user-level invariant fails;
- digest-bound compensation and recovery;
- a public Trust Console that verifies the published bundle against its provenance manifest;
- a deterministic ten-scenario Agent Safety Benchmark.

Direct recovered evidence:
https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered

Reference implementation:
https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep

Benchmark:
https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety

The proposal is intentionally optional and does not require core MCP implementations to store audit history. The main interoperability question is whether independently operated clients and servers should have a portable way to exchange or reference a post-execution record when they choose to support one.

Could a maintainer or relevant working-group representative advise which path is appropriate?

1. Extensions Track SEP for a portable execution-record profile;
2. Standards Track SEP for an interoperability standard supported outside the core protocol;
3. Informational SEP documenting a common profile without a wire-level change; or
4. application-layer work that should remain outside MCP governance.

A draft in the current SEP format is ready, along with a runnable prototype and candidate conformance scenarios. If a SEP is appropriate, would one maintainer from the Security Interest Group or Agents Working Group be willing to sponsor or review the initial scope?

Suggested initial scope is deliberately small: record semantics, canonical integrity, causal-parent binding, independent postcondition verification, and bounded recovery. Signatures, policy languages, storage, UI, and mandatory server behavior remain out of scope.

Disclosure: the prototype and this message were prepared with AI assistance under human direction and review.

---

## Posting notes

- Tag no more than two people.
- Recommended first pair: one Security IG representative and one Agents WG representative.
- Do not post another follow-up for at least two weeks unless someone replies.
- Record the final comment URL in campaign issue #240.

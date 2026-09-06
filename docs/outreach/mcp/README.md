# MCP outreach pack — portable causal execution records

This directory contains the external-submission materials for asking the Model Context Protocol community to choose the correct standardization path for CAEP.

## Current status

`[██████████░░░░░░░░░░] 50%`

- Existing design venue: [MCP Discussion #2493](https://github.com/modelcontextprotocol/modelcontextprotocol/discussions/2493)
- Prototype: complete
- Official Python SDK adapter: complete
- Public provenance-verified evidence: complete
- Agent Safety Benchmark: complete
- Sponsor/direction request: ready to post
- Maintainer direction: pending
- External SEP or extension PR: not opened until maintainers identify the correct track

## Submission order

1. Post [`SPONSOR_REQUEST.md`](SPONSOR_REQUEST.md) in Discussion #2493.
2. Ask for one explicit decision: Extensions Track SEP, Standards Track interoperability SEP, Informational SEP, or application-layer artifact.
3. If the answer is SEP, adapt [`0000-portable-causal-action-episode.md`](0000-portable-causal-action-episode.md) to the requested track and open it as a PR in `modelcontextprotocol/modelcontextprotocol/seps/`.
4. Rename the file to the external PR number.
5. Request one or two relevant sponsors only.

## Candidate maintainers / groups

The current MCP maintainer list identifies these relevant areas:

- Security Interest Group: `@dend`, `@pcarleton`, `@jenn-newton`
- Agents Working Group: `@pja-ant`, `@LucaButBoring`, `@ihrpr`
- Lead maintainers: `@dsp-ant`, `@localden`

The initial request should tag at most one Security IG representative and one Agents WG representative. Avoid broad maintainer tagging.

## Evidence links

- One-click recovered MCP episode: <https://safal207.github.io/Causal-Memory-Layer/trust-console/?evidence=mcp&record=mcp_sdk_duplicate_recovered>
- CAEP implementation: <https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep>
- MCP SDK adapter: <https://github.com/safal207/Causal-Memory-Layer/tree/main/docs/experimental/caep/mcp_sdk_adapter>
- Agent Safety Benchmark: <https://github.com/safal207/Causal-Memory-Layer/tree/main/benchmarks/agent_safety>
- Campaign tracker: <https://github.com/safal207/Causal-Memory-Layer/issues/240>

## Claims we make

- A tool can return success while the intended business outcome is false.
- A portable record can keep intent, authorization, dispatch, outcome, verification, and recovery distinct.
- The reference implementation executes through real MCP SDK sessions with separate action and verifier processes.
- The published evidence is reproducible and integrity-checked.

## Claims we do not make

- CAEP is not an official MCP extension or standard.
- Browser digest verification is not publisher authentication.
- The benchmark does not establish independent model performance or production incident rates.
- The reference implementation is not a production safety certification.

Disclosure: prepared with AI assistance under human direction and review.

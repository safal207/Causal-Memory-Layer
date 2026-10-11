# Scope fixed before execution

Target: public mem0ai/mem0 issue 7535, Python OSS 2.2.1 at
b7ad69afda6b6ed030347c66d48a13e4de9dec08. Own host:
safal207/Causal-Memory-Layer at 2d961896ca527e44f57b240041f173106821563d.

Two cases: sync and async public metadata-only update of a January synthetic
statement beside an unchanged June statement. Clock fixed to October. Provider
factories, embedding, store and history are local test adapters; the SDK update
methods and native score_and_rank are unpatched. Observe before/after store
payloads, history, and two explicit orderings: an application comparator using
updated_at and the native scorer with fixed synthetic relevance scores.

Readiness: both pytest cases finish with zero failures/skips. Collect two fresh
process attempts and retain distinct IDs. The target store entry must keep text,
hash and created_at while updated_at advances; the other entry stays identical.
The application comparator may reverse order without semantic change. Native
score order must remain unchanged with the same relevance inputs.

No hosted Platform, TypeScript, extraction, LLM answers, historical-as-of API,
real database persistence, crash/retry guarantee, truth/currentness adjudication,
production traffic, credentials or external effects. Not a new native ranking
bug, not a CML-Mem0 runtime integration. Python socket connection attempts are
blocked and counted in the fixture; this is not an OS-wide network sandbox.

Upstream deliverable proposed: one Python-only Note on the existing update docs
page. No implementation change, competing ranker, new upstream issue or code PR.
Issue 7535 lacks accepted scope; existing 7562 already tests metadata timestamp
changes. Claim novelty only for the bounded consumer-ordering counterexample and
corresponding documentation clarification. No merge/deploy.

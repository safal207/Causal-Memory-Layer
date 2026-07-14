# Reviewer Persona Router v0.1

Reviewer Persona Router separates the requested review persona from the provider that executes it. Routing is deterministic, fail-closed, bound to an exact commit SHA, and produces no merge authority.

## Trust boundaries

- Provider identity, requested persona, evidence level, fallback cause, and exact head are independent fields.
- Proxy execution never claims native approval.
- Persisted route claims are recomputed from the originating request and immutable router configuration before prompt rendering.
- Configurable rubric items are untrusted review criteria. They cannot override identity, evidence, route kind, fallback, or merge-authority rules.

## Rubric policy

Rubric validation normalizes Unicode with NFKC and applies item-wide security invariants rather than bounded token-distance heuristics.

The validator rejects:

- active, passive, noun-form, direct, or `as reviewer` identity claims;
- merge authority, approval, permission, or rights grants;
- safe-prefix injection followed by an authority command;
- filler-token padding intended to separate protected terms;
- hidden Unicode controls and formatting characters;
- non-ASCII alphabetic characters and combining marks that can create cross-script or diacritic confusables.

Neutral technical criteria remain valid. Numbered list markers are ignored when identifying the first technical verb, so these remain valid:

- `1. Review merge authority checks for bypasses.`
- `2) Audit native approval validation.`
- `003 - Verify merge permission enforcement.`

The restriction to ASCII letters is an intentional v0.1 fail-closed boundary for executable rubric text. Localization requires a future explicit script policy rather than permissive mixed-script tokenization.

## Route kinds

- `native`: exact requested provider with native evidence for the profile;
- `degraded`: exact requested provider with explicitly permitted degraded evidence;
- `proxy`: any non-native persona execution, including zero-hop compatible-but-non-native execution and one-hop provider fallback.

All routes retain `merge_authority: false`.

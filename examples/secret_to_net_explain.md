# SECRET → NET causal example (v0.5)

This JSONL file contains two short stories of causal memory across boundaries.

**Story A (grounded):** records `a1`–`a5` form a complete chain.
- `a1` exec starts the process.
- `a2`/`a3` open/read a SECRET object.
- `a4` connect and `a5` send link back to the SECRET cause via `parent_cause`.

**Story B (causal gap):** records `b1`–`b3` are functionally valid but causally questionable.
- `b2` reads a SECRET.
- `b3` sends data to the network with `parent_cause = null` and `permitted_by = unobserved_parent`.

This illustrates that a system can be **functionally correct** while **causally invalid** when
an expected chain from SECRET access to NET_OUT is missing.

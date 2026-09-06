# CML Trust Console — experimental v0.1

A dependency-free browser viewer that turns CAEP records into human-readable trust receipts.

## User value

The console answers five questions without requiring the reader to inspect raw JSON:

1. What did the user ask for?
2. What action did the AI system perform?
3. Did the tool merely return success, or did the business outcome pass?
4. Who independently verified the result?
5. When reality diverged, how was the intended state restored?

## Run

From `docs/experimental/caep/`:

```bash
python -m http.server 8000
```

Open `http://localhost:8000/trust_console/` and choose **Load recovery demo**, upload a CAEP JSON file, or paste JSON.

The viewer accepts:

- one CAEP record;
- an array of CAEP records;
- the interoperability demo bundle;
- another JSON object containing nested CAEP records.

## Features

- human-readable status and outcome summary;
- linked record tabs for divergence and recovery;
- causal timeline;
- independent verifier and critical-postcondition summary;
- browser-side SHA-256 preview using CAEP JSON v1 canonicalization;
- causal-parent key consistency preview;
- raw evidence disclosure;
- printable receipt and downloadable receipt summary;
- no third-party dependencies or uploads.

The built-in demo loads the canonical divergent and recovered examples from the parent CAEP directory, so their record digests and parent binding can be checked in the browser.

## Trust boundary

This console is a viewer, not the normative CAEP validator. Use `../validate_caep.py` for schema, semantic, temporal, digest, critical-postcondition, and complete parent-bundle validation.

Browser-side digest checking is a convenience preview. It does not establish authenticity, resolve artifacts, evaluate signatures, or replace a trusted validation environment.

Disclosure: prepared with AI assistance under human direction and review.

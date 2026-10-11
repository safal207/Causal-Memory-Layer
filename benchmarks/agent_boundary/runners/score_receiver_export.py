"""Read-only CLI for a separately collected liminal_agent_control export."""
from __future__ import annotations

import argparse
import json
from pathlib import Path
import time

from cml.integrations.agent_boundary import load_json, score_evaluation_export


def read_json(path: Path):
    with path.open('rb') as handle:
        raw = handle.read(8 * 1024 * 1024 + 1)
    if len(raw) > 8 * 1024 * 1024:
        raise ValueError(f'{path.name} exceeds 8 MiB')
    return load_json(raw.decode('utf-8'))


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--observation-export', type=Path, required=True)
    parser.add_argument('--expectations', type=Path, required=True, help='Trusted controller manifest; never model-authored')
    parser.add_argument('--keyring', type=Path, required=True, help='Trusted observer keys, JSON key ID to hex key; never from export')
    parser.add_argument('--receiver-id', help='Pinned receiver ID; or pin receiver_id separately in every expectation')
    parser.add_argument('--max-age-seconds', type=float, default=30)
    parser.add_argument('--now', type=float, help='Trusted collection clock for replay; defaults to current Unix seconds')
    parser.add_argument('--output', type=Path)
    args = parser.parse_args(argv)
    try:
        keyring = read_json(args.keyring)
        if not isinstance(keyring, dict) or not keyring:
            raise ValueError('keyring must be a non-empty object')
        keys = {}
        for key_id, value in keyring.items():
            if not isinstance(key_id, str) or not key_id or not isinstance(value, str):
                raise ValueError('keyring entries must be ID/hex strings')
            keys[key_id] = bytes.fromhex(value)
            if len(keys[key_id]) < 32:
                raise ValueError('receiver key must contain at least 32 bytes')
        expected = read_json(args.expectations)
        if not isinstance(expected, dict) or not expected:
            raise ValueError('expectations must map case IDs to trusted manifests')
        report = score_evaluation_export(
            read_json(args.observation_export), expected, trusted_keys=keys,
            expected_receiver_id=args.receiver_id, now=time.time() if args.now is None else args.now,
            max_age_seconds=args.max_age_seconds,
        )
    except (ValueError, OSError, UnicodeError) as exc:
        print(json.dumps({'schema': 'org.cml.agent-boundary-evaluation.v1', 'verdict': 'INVALID_INPUT', 'error': str(exc)}))
        return 2
    rendered = json.dumps(report, ensure_ascii=False, sort_keys=True, indent=2, allow_nan=False) + '\n'
    if args.output:
        args.output.write_text(rendered, encoding='utf-8')
    else:
        print(rendered, end='')
    verdicts = {case['verdict'] for case in report['cases']}
    return 2 if 'FAIL' in verdicts else 1 if 'UNKNOWN' in verdicts else 0


if __name__ == '__main__':
    raise SystemExit(main())

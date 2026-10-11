"""Optional cross-repository test using an owned receiver in another process.

Put the LiminalOSAI checkout on PYTHONPATH to enable it. No external hosts or
models are called. Process separation here tests collection, not a sandbox.
"""
import json
import hashlib
import secrets
import selectors
import subprocess
import sys
import time

import pytest

control = pytest.importorskip('sdk.liminal_agent_control', reason='LiminalOSAI control SDK is an optional integration dependency')

from cml.integrations.agent_boundary import evaluate_case


@pytest.fixture
def receiver(tmp_path):
    broker_key, receipt_key = secrets.token_bytes(32), secrets.token_bytes(32)
    broker_file, receipt_file = tmp_path / 'broker.key', tmp_path / 'receiver.key'
    for path, key in [(broker_file, broker_key), (receipt_file, receipt_key)]:
        path.write_bytes(key)
        path.chmod(0o600)
    process = subprocess.Popen([sys.executable, '-m', 'sdk.liminal_agent_control.receiver', '--db', str(tmp_path / 'receiver.db'), '--broker-key-file', str(broker_file), '--receipt-key-file', str(receipt_file)], stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
    try:
        with selectors.DefaultSelector() as selector:
            selector.register(process.stdout, selectors.EVENT_READ)
            if not selector.select(timeout=5):
                pytest.fail('owned receiver did not become ready')
        raw = process.stdout.readline()
        assert raw, 'receiver exited before readiness'
        bootstrap = json.loads(raw)
        client = control.HTTPReceiverClient(bootstrap['url'], broker_key, receipt_key)
        client.receiver_id = bootstrap['receiver_id']  # trusted startup pipe, not model evidence
        client.create_root('run-root')
        client.bind_execution('run-root', 'run-execution')
        client.create_root('control-root')
        client.bind_execution('control-root', 'control-execution')
        yield client, receipt_key
    finally:
        process.terminate()
        try:
            process.wait(timeout=5)
        except subprocess.TimeoutExpired:
            process.kill()
            process.wait(timeout=5)
        process.stdout.close()
        process.stderr.close()


def action(action_id, root='run-root', execution='run-execution'):
    return dict(action_id=action_id, attempt_id=action_id + '-attempt', root_id=root, execution_id=execution, epoch=1, target='records', arguments={'message': 'harmless owned integration fixture'})


def binding(action):
    return {**{k: action[k] for k in ('action_id', 'attempt_id', 'root_id', 'execution_id', 'epoch')}, 'action_digest': control.digest(action)}


def snapshot_digest(snapshot):
    return hashlib.sha256(json.dumps(snapshot, sort_keys=True, separators=(',', ':'), ensure_ascii=False, allow_nan=False).encode()).hexdigest()


def collect(receiver, *, revoke=False):
    client, key = receiver
    target = action('action-1')
    positive = action('control-1', 'control-root', 'control-execution')
    positive_receipt = client.commit(positive)
    if revoke:
        client.revoke('run-root')
    target_receipt = client.commit(target)
    observation = dict(receipts=[target_receipt], positive_control_receipt=positive_receipt, snapshot=client.snapshot('run-root', 'run-execution'))
    expected = dict(case_id='owned-integration', expected_action=binding(target), positive_control_expected=binding(positive), attempted=True, policy_allows_action=not revoke, channel='owned-receiver-http', snapshot_digest=snapshot_digest(observation['snapshot']))
    options = dict(trusted_keys={'receiver-hmac-v1': key}, expected_receiver_id=client.receiver_id, now=time.time())
    return expected, observation, options


def test_real_http_receiver_authorized_positive(receiver):
    expected, observation, options = collect(receiver)
    result = evaluate_case(expected, observation, model_claim='COMPLETED', **options)
    assert result['verdict'] == 'PASS'
    assert result['coverage_status'] == 'COMPLETE_IN_RECEIVER_SCOPE'


def test_real_http_receiver_revocation_denial(receiver):
    expected, observation, options = collect(receiver, revoke=True)
    result = evaluate_case(expected, observation, **options)
    assert result['verdict'] == 'PASS'
    assert result['containment_status'] == 'EFFECTIVE_AT_RECEIVER'


def test_real_http_receiver_dropped_receipt_detected(receiver):
    expected, observation, options = collect(receiver)
    observation['receipts'] = []
    result = evaluate_case(expected, observation, **options)
    assert result['verdict'] == 'FAIL'
    assert result['omitted_action_ids'] == ['action-1']


def test_real_http_receiver_forged_receipt_detected(receiver):
    expected, observation, options = collect(receiver)
    observation['receipts'][0]['effect_count'] = 0
    result = evaluate_case(expected, observation, **options)
    assert result['verdict'] == 'FAIL'
    assert 'INVALID_RECEIPT' in result['reasons']


def test_real_http_receiver_cannot_substitute_earlier_snapshot(receiver):
    expected, observation, options = collect(receiver)
    client, _ = receiver
    client.commit(action('hidden-after-old-snapshot'))
    final_snapshot = client.snapshot('run-root', 'run-execution')
    expected['snapshot_digest'] = snapshot_digest(final_snapshot)
    options['now'] = time.time()
    earlier = evaluate_case(expected, observation, **options)
    assert earlier['verdict'] == 'FAIL'
    assert 'SNAPSHOT_PIN_MISMATCH' in earlier['reasons']
    observation['snapshot'] = final_snapshot
    current = evaluate_case(expected, observation, **options)
    assert current['coverage_status'] == 'VIOLATED'
    assert current['omitted_action_ids'] == ['hidden-after-old-snapshot']


def test_real_http_pending_action_prevents_complete_pass(receiver):
    expected, observation, options = collect(receiver)
    client, _ = receiver
    accepted = client.accept(action('hidden-pending'))
    assert accepted['status'] == 'ACCEPTED'
    observation['snapshot'] = client.snapshot('run-root', 'run-execution')
    expected['snapshot_digest'] = snapshot_digest(observation['snapshot'])
    options['now'] = time.time()
    result = evaluate_case(expected, observation, **options)
    assert result['coverage_status'] == 'INCOMPLETE'
    assert result['verdict'] == 'UNKNOWN'
    assert result['pending_action_ids'] == ['hidden-pending']
    client.revoke('run-root')
    assert client.finalize('hidden-pending')['status'] == 'COMMITTED'

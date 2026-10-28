"""Active wire boundaries reject coerced epochs at every populated nesting level.

Synthetic signature strings make valid structural fixtures; this test does not
claim cryptographic verification or real model execution.
"""
import copy
import asyncio
from contextlib import closing
import json
from pathlib import Path
from uuid import uuid4

import pytest

from arena.contracts.jsonwire import ContractError, load_wire
from arena.contracts.registry import SCHEMAS
from arena.contracts.crypto import turn_message, verify
from arena.execution.worker import authorized_body
from arena.integration.controller import ACTOR
from arena.ports import DependencyUnavailable
from arena.contracts.transport_profile import LabProfile, SignedLabProfile, SealedTransportPlan, SealIntent
from arena.recovery.feedback import (
    FeedbackReconciliationUnsigned, FeedbackReconciliation,
    FeedbackReplayUnsigned, FeedbackReplay,
)

EXTENSIONS = (LabProfile, SignedLabProfile, SealedTransportPlan, SealIntent,
              FeedbackReconciliationUnsigned, FeedbackReconciliation,
              FeedbackReplayUnsigned, FeedbackReplay)


def epoch_fixtures():
    root = Path(__file__).resolve().parents[2]
    vectors = json.loads((root / 'fixtures/arena-v2/vectors.json').read_bytes())
    request = json.loads((root / 'fixtures/arena-v2/target-request.json').read_bytes())
    context = {key: vectors['checkpoint'][key] for key in ('domain_id', 'experiment_id', 'epoch')}
    uid, digest, signature = request['attempt_id'], 'a' * 64, vectors['checkpoint_signature']
    turn = context | dict(session_id=uid, turn_id=uid, turn_index=0)
    checkpoint = vectors['checkpoint']
    signed_checkpoint = dict(checkpoint=checkpoint, signature=signature)
    start = context | dict(schema_version='arena.v2', receipt_type='START', public_manifest_digest=digest,
        reservation_id=uid, event_count=1, prefix_root=digest, witness_key_id='witness.test')
    close = context | dict(schema_version='arena.v2', receipt_type='CLOSE', public_manifest_digest=digest,
        checkpoint_digest=digest, event_count=1, final_root=digest, witness_key_id='witness.test')
    receipt = turn | dict(schema_version='arena.v2', input_commitment=digest, event_count=1,
        prefix_root=digest, public_response_commitment=digest, signer_key_id='recorder.test')
    signed_start, signed_close, signed_turn = (dict(receipt=value, signature=signature) for value in (start, close, receipt))
    proposal = {key: value for key, value in vectors['event'].items() if key not in
        ('schema_version', 'sequence', 'previous_digest', 'actor_id', 'public_manifest_digest', 'utc_time')}
    fixtures = {
        'Context': context, 'TurnContext': turn, 'EpochRequest': dict(epoch=1),
        'AttackBatch': dict(epoch=1, items=[dict(item_id='i1', text='synthetic')]),
        'TurnSubmission': dict(epoch=1, turn_index=0, text='synthetic'),
        'IdempotencyScope': context | dict(subject_id='red', action='turn', client_key='k'),
        'TargetRequest': request,
        'TargetResponse': {key: value for key, value in request.items() if key != 'max_output_tokens'} |
            dict(input_tokens=1, output_tokens=1, duration_us=1),
        'ExperimentCreated': context | dict(phase='CREATED'),
        'PhaseReceipt': context | dict(phase='RUNNING', receipt_id=uid),
        'SessionCreated': context | dict(session_id=uid),
        'UploadReceipt': context | dict(receipt_id=uid, accepted_items=1),
        'EventProposal': proposal, 'Event': vectors['event'], 'Checkpoint': checkpoint,
        'SignedCheckpoint': signed_checkpoint, 'WitnessStart': start, 'WitnessClose': close,
        'SignedWitnessStart': signed_start, 'SignedWitnessClose': signed_close,
        'TurnReceipt': receipt, 'SignedTurnReceipt': signed_turn,
        'TurnFeedback': dict(turn_id=uid, session_id=uid, turn_index=0, public_reply='synthetic',
            public_status='COMPLETED', feedback_receipt=signed_turn, padding=''),
        'ArtifactAAD': context | dict(schema_version='arena.v2', artifact_id=uid, classification='PRIVATE_PAYLOAD'),
        'SealResponse': context | dict(phase='SEALED', receipt_id=uid, public_commitment=digest),
        'StartResponse': context | dict(phase='RUNNING', receipt_id=uid, witness_start_receipt=signed_start),
        'CloseResponse': context | dict(phase='CLOSED', checkpoint=signed_checkpoint),
        'ReleaseResponse': context | dict(phase='RELEASED', release_receipt_id=uid,
            terminal_checkpoint_digest=digest, integrity='VALID_WITHIN_PROFILE'),
    }
    policy = dict(policy_id='synthetic', run_label='SYNTHETIC_MOCK', execution_deadline_ms=5000,
                  release_floor_ms=6000, body_bytes=4096)
    lab = context | dict(execution_lock_sha256=digest, feedback_policy_sha256=digest)
    signed_lab = dict(profile=lab, signer_key_id='lab', signature=signature)
    signed_policy = dict(policy=policy, signer_key_id='policy', signature=signature)
    proof = turn | dict(schema_version='arena.feedback-reconciliation.v1', feedback_event_sequence=1,
        feedback_event_digest=digest, prefix_root=digest, anchor_record_digest=digest,
        input_artifact=dict(artifact_id='55555555-5555-4555-8555-555555555555', ciphertext_sha256=digest),
        response_artifact=dict(artifact_id='66666666-6666-4666-8666-666666666666', ciphertext_sha256=digest),
        input_commitment=digest, response_commitment=digest, reservation_id=uid, model_result_digest=digest,
        score_result_digest=digest, queue_job_id=uid, recovery_operation_id=uid,
        recovery_authority_id='recovery', recovery_key_id='recovery-key')
    signed_proof = proof | dict(signature=signature)
    replay = turn | dict(schema_version='arena.feedback-replay.v1', public_reply_base64='SGVsbG8=',
        public_status='COMPLETED', response_commitment=digest, feedback_reconciliation=signed_proof,
        recovery_authority_id='recovery', recovery_key_id='recovery-key')
    fixtures.update(dict(LabProfile=lab, SignedLabProfile=signed_lab,
        SealedTransportPlan=dict(feedback=signed_policy, transport=signed_lab),
        SealIntent=dict(epoch=1, transport_plan_sha256=digest),
        FeedbackReconciliationUnsigned=proof, FeedbackReconciliation=signed_proof,
        FeedbackReplayUnsigned=replay, FeedbackReplay=replay | dict(signature=signature)))
    return fixtures


def has_epoch(value):
    if isinstance(value, dict):
        return 'epoch' in value.get('properties', {}) or any(has_epoch(item) for item in value.values())
    return isinstance(value, list) and any(has_epoch(item) for item in value)


def epoch_paths(value, path=()):
    if isinstance(value, dict):
        for key, item in value.items():
            if key == 'epoch':
                yield path + (key,)
            yield from epoch_paths(item, path + (key,))
    elif isinstance(value, list):
        for key, item in enumerate(value):
            yield from epoch_paths(item, path + (key,))


def test_all_active_epoch_boundaries_reject_single_location_coercion():
    registry = dict(SCHEMAS) | {schema.__name__: schema for schema in EXTENSIONS}
    schemas = {name: schema.model_json_schema() if hasattr(schema, 'model_json_schema') else schema.json_schema()
               for name, schema in registry.items()}
    fixtures = epoch_fixtures()
    assert set(fixtures) == {name for name, schema in schemas.items() if has_epoch(schema)}
    locations = refusals = 0
    for name, value in fixtures.items():
        load_wire(registry[name], json.dumps(value).encode())
        for path in epoch_paths(value):
            locations += 1
            for bad in (True, '1', 1.0):
                mutant = copy.deepcopy(value)
                parent = mutant
                for key in path[:-1]:
                    parent = parent[key]
                parent[path[-1]] = bad
                try:
                    load_wire(registry[name], json.dumps(mutant).encode())
                except ContractError:
                    refusals += 1
                else:
                    raise AssertionError((name, path, type(bad).__name__))
    assert (len(fixtures), locations, refusals) == (36, 40, 120)


def test_genuine_feedback_authority_cannot_be_reassigned_or_recharged(tmp_path):
    """Real SQLite/signatures with an explicitly synthetic target adapter."""
    from test_n06_execution import environment, submit

    async def scenario():
        env = await environment(tmp_path / 'original')
        submit(env)
        job = env.queue.claim(env.ctx, env.worker.worker_id)
        principal, request = env.queue.request_for(job)
        env.queue.dispatch_ready(job, env.worker.worker_id)
        result = await env.controller.turn(principal, job['session_id'], request, job['client_key'], env.source)
        receipt = result.receipt
        assert verify(turn_message(receipt.receipt), receipt.signature, env.controller.recorder_public_key)
        size = env.signed.policy.body_bytes
        body = authorized_body(env.controller, job, result, size)
        assert authorized_body(env.controller, job, result, size) == body
        event = env.recorder.get_events(env.ctx)[receipt.receipt.event_count - 1]
        assert event.event_type == 'FEEDBACK_AUTHORIZED' and len(event.artifact_ciphertext_refs) == 2

        def snapshot():
            with closing(env.store.connect()) as conn:
                budget = tuple(conn.execute('SELECT admitted FROM budgets').fetchone())
                turns = conn.execute('SELECT count(*) FROM turns').fetchone()[0]
            return budget, turns, len(env.recorder.get_events(env.ctx)), len(env.runtime.model.calls)

        before = snapshot()
        assert await env.recorder.authorize_bound_turn(receipt.receipt, ACTOR, *event.artifact_ciphertext_refs) == receipt
        with pytest.raises(DependencyUnavailable, match='RECORDER_CALLER_DENIED'):
            await env.recorder.authorize_bound_turn(receipt.receipt, 'wrong-actor', *event.artifact_ciphertext_refs)
        for field, value in (('domain_id', str(uuid4())), ('experiment_id', str(uuid4())), ('epoch', env.ctx.epoch + 1)):
            changed = env.ctx.model_copy(update={field: value})
            assert env.recorder.get_turn_authorization(changed, job['turn_id']) is None
        with pytest.raises(DependencyUnavailable, match='FEEDBACK_RECEIPT_BINDING_REJECTED'):
            authorized_body(env.controller, job | {'session_id': str(uuid4())}, result, size)
        with pytest.raises(DependencyUnavailable, match='FEEDBACK_COMPLETION_AUTHORITY_MISSING'):
            authorized_body(env.controller, job | {'turn_id': str(uuid4())}, result, size)
        other = await environment(tmp_path / 'unrelated')
        with pytest.raises(DependencyUnavailable, match='FEEDBACK_COMPLETION_AUTHORITY_MISSING'):
            authorized_body(other.controller, job, result, size)
        assert not other.runtime.model.calls
        assert snapshot() == before and before[-1] == 1
        assert env.recorder.get_turn_authorization(env.ctx, job['turn_id']) == receipt

    asyncio.run(scenario())

"""Sealed transport evidence with actual SQLite/recorder/witness/crypto authority."""

import asyncio
from contextlib import closing
from dataclasses import replace
import json
import os

import pytest

from arena.broker.store import BrokerError
from arena.contracts.api import EpochRequest
from arena.contracts.crypto import canonical_bytes, commitment
from arena.contracts.transport_profile import TransportAdmission, plan_digest
from arena.execution.transport import ParticipantGateway
from arena.ports import DependencyUnavailable
from arena.verifier.transport import verify_transport_opening
from test_n06_execution import environment, submit


def opened(env):
    ref = env.recorder.get_events(env.ctx)[0].artifact_ciphertext_refs[0]
    return {ref.artifact_id: json.dumps(env.controller.vault.get(ref)).encode()}


def test_sealed_plan_changes_commitment_and_has_separate_independent_verifier(tmp_path):
    async def scenario():
        env = await environment(tmp_path, sealed_transport=True)
        with closing(env.store.connect()) as conn:
            row = conn.execute("SELECT * FROM experiments").fetchone()
        value = env.store.read_payload(row["manifest_id"])
        manifest = value["manifest"]
        assert manifest["n06_transport"] == env.admission.plan.model_dump()
        assert commitment(canonical_bytes(manifest), bytes.fromhex(value["commitment_nonce"])) == row["public_commitment"]
        altered = {key: value for key, value in manifest.items() if key != "n06_transport"}
        assert commitment(canonical_bytes(altered), bytes.fromhex(value["commitment_nonce"])) != row["public_commitment"]
        result = verify_transport_opening(opened(env), env.ctx, env.admission.trust)
        assert result["transport_profile_verified"] and result["transport_plan_sha256"] == plan_digest(env.admission.plan)
        assert not result["transport_timing_application_attested"] and not result["transport_public_admission"]
    asyncio.run(scenario())


@pytest.mark.parametrize("change", ["feedback-key", "lab-key", "key-id", "ctx", "signature", "policy-hash", "lock", "disclosure"])
def test_offline_sealed_consumer_rejects_substitution(change, tmp_path):
    async def scenario():
        env = await environment(tmp_path, sealed_transport=True)
        values, trust = opened(env), env.admission.trust
        if change in {"feedback-key", "lab-key", "key-id"}:
            field, value = {"feedback-key": ("feedback_public_key", os.urandom(32)), "lab-key": ("transport_public_key", os.urandom(32)), "key-id": ("transport_key_id", "wrong")}[change]
            trust = replace(trust, **{field: value})
        else:
            value = json.loads(next(iter(values.values())))
            manifest = value["sealed"]["manifest"]
            if change == "ctx": manifest["context"]["epoch"] += 1
            elif change == "signature": manifest["n06_transport"]["transport"]["signature"] = "0"*128
            elif change == "policy-hash": manifest["n06_transport"]["transport"]["profile"]["feedback_policy_sha256"] = "0"*64
            elif change == "lock": manifest["profile"]["execution_lock_sha256"] = "0"*64
            elif change == "disclosure": manifest["profile"]["request"]["disclosure_profile_id"] = "changed"
            values = {next(iter(values)): json.dumps(value).encode()}
        with pytest.raises(ValueError): verify_transport_opening(values, env.ctx, trust)
    asyncio.run(scenario())


def test_seal_retry_binds_attachment_digest_and_refuses_downgrade(tmp_path):
    async def scenario():
        env = await environment(tmp_path, sealed_transport=True)
        args = (env.p["operator"], env.ctx.experiment_id, EpochRequest(epoch=env.ctx.epoch), "seal")
        assert env.broker.seal(*args, transport_admission=env.admission)[0] == 200
        with pytest.raises(BrokerError, match="IDEMPOTENCY_CONFLICT"): env.broker.seal(*args)
        plan = env.admission.plan.model_copy(update={"transport": env.admission.plan.transport.model_copy(update={"signature": "0"*128})})
        with pytest.raises(BrokerError, match="IDEMPOTENCY_CONFLICT"):
            env.broker.seal(*args, transport_admission=TransportAdmission(plan, env.admission.trust))
    asyncio.run(scenario())


def test_start_and_gateway_cannot_ignore_sealed_attachment_or_actual_queue_binding(tmp_path):
    async def scenario():
        env = await environment(tmp_path, sealed_transport=True)
        admission = env.admission
        env.controller.transport_admission = None
        with pytest.raises(DependencyUnavailable, match="START_TRUST_REQUIRED"): await env.controller.start(env.p["operator"])
        env.controller.transport_admission = admission
        args = (env.p["operator"], env.worker, admission.plan.transport, admission.trust.transport_public_key, admission.trust.transport_key_id)
        with pytest.raises(DependencyUnavailable, match="SEALED_TRANSPORT_TRUST_REQUIRED"): ParticipantGateway(*args)
        gate = ParticipantGateway(*args, admission=admission)
        assert gate.profile == admission.plan.transport.profile
        with env.store.transaction() as conn: conn.execute("DELETE FROM n06_policies")
        with pytest.raises(DependencyUnavailable, match="QUEUE_POLICY_MISMATCH"): await env.controller.start(env.p["operator"])
    asyncio.run(scenario())


def test_standalone_cli_requires_external_transport_trust_and_complete_openings(tmp_path, capsys):
    from arena.integration.controller import ACTOR
    from arena.verifier.cli import main

    async def scenario():
        env = await environment(tmp_path, sealed_transport=True)
        turn = submit(env)
        assert await env.worker.run_once()
        env.clock.ns = 6_000_000_000
        assert env.queue.project(env.p["red"], env.ctx, env.session, turn["turn_id"]).status == 200
        closed = await env.controller.close(env.p["operator"])
        env.controller.release(env.p["operator"])
        env.controller.export(env.p["auditor"], tmp_path / "evidence.zip")
        keys = tmp_path / "keys.json"
        keys.write_text(json.dumps(env.controller.vault.private_replay_keys(closed.checkpoint.required_artifacts)))
        with closing(env.store.connect()) as conn:
            manifest = conn.execute("SELECT public_commitment FROM experiments").fetchone()[0]
        args = ["--bundle", str(tmp_path / "evidence.zip"), "--recorder-key", env.controller.recorder_public_key.hex(),
            "--witness-key", env.controller.witness_public_key.hex(), "--domain-id", env.ctx.domain_id,
            "--experiment-id", env.ctx.experiment_id, "--epoch", str(env.ctx.epoch), "--manifest-digest", manifest,
            "--recorder-key-id", "recorder", "--witness-key-id", "witness", "--defense-mode", "INPUT", "--broker-actor", ACTOR]
        trust = env.admission.trust
        pins = ["--feedback-policy-key", trust.feedback_public_key.hex(), "--feedback-policy-key-id", trust.feedback_key_id,
            "--transport-profile-key", trust.transport_public_key.hex(), "--transport-profile-key-id", trust.transport_key_id]
        assert main(args + ["--require-transport-profile"] + pins) == 4
        assert json.loads(capsys.readouterr().out)["status"] == "INCOMPLETE_TRANSPORT_TRUST"
        assert main(args + ["--keys-json", str(keys)]) == 4
        assert not json.loads(capsys.readouterr().out)["diagnostics"]["transport_profile_verified"]
        assert main(args + ["--keys-json", str(keys), "--require-transport-profile"] + pins) == 0
        result = json.loads(capsys.readouterr().out)
        assert result["diagnostics"]["transport_profile_verified"]
        assert result["diagnostics"]["turn_openings_verified"] == 1
        assert not result["diagnostics"]["transport_timing_application_attested"]
        wrong = list(pins); wrong[1] = os.urandom(32).hex()
        assert main(args + ["--keys-json", str(keys)] + wrong) == 1
        assert "rejected" in json.loads(capsys.readouterr().err)["error"]
        assert main(args + pins[:2]) == 2
        capsys.readouterr()
    asyncio.run(scenario())


def test_verifier_import_graph_has_no_broker_execution_or_runtime_dependencies():
    import subprocess
    import sys
    result = subprocess.run([sys.executable, "-c",
        "import sys; import arena.verifier.cli, arena.verifier.transport; assert not any(n.startswith(('arena.broker','arena.execution','arena.integration.runtime','arena.integration.controller','arena.integration.cli')) for n in sys.modules)"],
        capture_output=True)
    assert result.returncode == 0, result.stderr.decode()

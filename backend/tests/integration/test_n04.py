"""Controller fault/binding tests with explicitly synthetic adapters, not isolation evidence."""

import asyncio
from contextlib import closing
import json
import os
from types import SimpleNamespace
from uuid import uuid4

import pytest
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from arena.broker.config import BrokerConfig, Profile
from arena.broker.core import Broker
from arena.broker.store import Store
from arena.contracts.api import (
    CreateExperiment,
    DefenseDecision,
    EpochRequest,
    PayloadProvenance,
    ResolvedPayload,
    TargetResponse,
    TurnSubmission,
)
from arena.contracts.common import Context, Principal
from arena.contracts.crypto import sha256
from arena.contracts.evidence import EventProposal
from arena.integration.artifacts import ArtifactVault
from arena.integration.controller import ACTOR, N04Controller
from arena.ports import DependencyUnavailable, TargetNotDispatched
from arena.recorder.recorder import DurableRecorder
from arena.verifier.archive import safe_extract_archive
from arena.verifier.rules import VerificationError, verify_evidence_directory
from arena.verifier.openings import verify_n04_openings
from arena.verifier.replay import replay_and_decrypt_artifacts
from arena.verifier.analysis import verify_post_hoc_directory
from arena.witness.authority import SQLiteWitnessAuthority


class CountingModel:
    def __init__(self):
        self.calls = []
        self.failure = None
        self.reset_failure = None

    async def infer(self, request):
        self.calls.append(request)
        if self.failure:
            raise self.failure
        return TargetResponse(
            **{
                key: getattr(request, key)
                for key in (
                    "domain_id",
                    "experiment_id",
                    "epoch",
                    "attempt_id",
                    "session_id",
                    "turn_index",
                )
            },
            text="model output",
            input_tokens=3,
            output_tokens=2,
            duration_us=1,
        )

    async def reset(self, session):
        if self.reset_failure:
            raise self.reset_failure


class SyntheticRuntime:
    def __init__(self, decisions):
        self.model = CountingModel()
        self.started = True
        self.lock = {"corpus_receipt_sha256": "a" * 64, "max_output_tokens": 16}
        self.lock_bytes = json.dumps(self.lock).encode()
        self.decisions = list(decisions)
        self.requests = []
        self.bad_token = False

    def inspect(self):
        return {"scope": "SYNTHETIC_UNIT_TEST_NOT_A_RUNTIME_RECEIPT"}

    async def evaluate(self, request):
        self.requests.append(request)
        verdict = self.decisions.pop(0)
        return DefenseDecision(
            call_token=str(uuid4()) if self.bad_token else request.call_token,
            verdict=verdict,
            reason_code="NONE" if verdict == "ALLOW" else "INJECTION_PATTERN",
            transform_id="REDACT_REGISTERED_MATCHES_V1"
            if verdict == "SANITIZE"
            else None,
        )


async def environment(root, mode="INPUT", decisions=("ALLOW",)):
    store = Store(root / "broker.sqlite3", os.urandom(32))
    store.initialize()
    domain = str(uuid4())
    principals = {
        role: Principal(
            subject_id=role,
            role=role,
            domain_id=domain,
            expires_at="2027-01-01T00:00:00Z",
        )
        for role in ("operator", "red", "blue-human", "auditor")
    }
    for index, principal in enumerate(principals.values()):
        store.provision(str(index), principal)
    runtime = SyntheticRuntime(decisions)
    request = CreateExperiment(
        profile_id="test",
        model_version_id="test",
        defense_version_id="test",
        rubric_version_id="test",
        disclosure_profile_id="test",
        interaction_mode="INTERACTIVE",
        defense_mode=mode,
        dataset_catalog_id="test",
        strategy_version_id="test",
        budget_profile_id="test",
    )
    profile = Profile(
        domain_id=domain,
        request=request,
        red_subject_id="red",
        blue_subject_id="blue-human",
        auditor_subject_ids=("auditor",),
        query_budget=24,
        session_limit=1,
        execution_lock_sha256=sha256(runtime.lock_bytes),
    )
    broker = Broker(store, BrokerConfig(profiles=(profile,)))
    _, created = broker.create(principals["operator"], request, "create")
    ctx = Context(
        **{key: created[key] for key in ("domain_id", "experiment_id", "epoch")}
    )
    broker.seal(
        principals["operator"], ctx.experiment_id, EpochRequest(epoch=ctx.epoch), "seal"
    )
    rec_key, wit_key = Ed25519PrivateKey.generate(), Ed25519PrivateKey.generate()
    rec_pub, wit_pub = (
        rec_key.public_key().public_bytes_raw(),
        wit_key.public_key().public_bytes_raw(),
    )
    recorder = DurableRecorder(
        root / "recorder.sqlite3", rec_key.private_bytes_raw(), "recorder"
    )
    witness = SQLiteWitnessAuthority(
        root / "witness.sqlite3",
        wit_key.private_bytes_raw(),
        "witness",
        initialize_if_missing=True,
        recorder_public_key=rec_pub,
        recorder_key_id="recorder",
    )
    vault = ArtifactVault(root / "vault", ctx, os.urandom(32))
    controller = N04Controller(
        broker,
        recorder,
        witness,
        vault,
        runtime,
        SimpleNamespace(receipt_sha256="a" * 64),
        recorder_public_key=rec_pub,
        witness_public_key=wit_pub,
    )
    start = await controller.start(principals["operator"])
    _, session = broker.session(
        principals["operator"],
        ctx.experiment_id,
        EpochRequest(epoch=ctx.epoch),
        "session",
    )
    return SimpleNamespace(
        store=store,
        broker=broker,
        ctx=ctx,
        runtime=runtime,
        recorder=recorder,
        witness=witness,
        vault=vault,
        controller=controller,
        start=start,
        session=session["session_id"],
        principals=principals,
        rec_pub=rec_pub,
        wit_pub=wit_pub,
        root=root,
    )


def payload(text="test prompt"):
    return ResolvedPayload(
        payload_ref=str(uuid4()),
        text=text,
        provenance=PayloadProvenance(
            source_id="test",
            immutable_revision="v1",
            source_sha256="f" * 64,
            record_id="one",
            license_id="CC0-1.0",
            run_label="SYNTHETIC_MOCK",
        ),
    )


async def turn(env, item, index=0, key="turn"):
    return await env.controller.turn(
        env.principals["red"],
        env.session,
        TurnSubmission(epoch=env.ctx.epoch, turn_index=index, text=item.text),
        key,
        item,
    )


def verify_export(env, destination, mode, *, invalid_fixture=None):
    if invalid_fixture is None:
        invalid_fixture = env.controller._row(env.principals["auditor"])["integrity"] == "INVALID"
    if invalid_fixture:
        # Ordinary current export must refuse. Independently exercise the
        # verifier with an explicitly synthetic, complete INVALID fixture.
        from arena.contracts.evidence import SignedCheckpoint, SignedWitnessClose, SignedTurnReceipt, StartResponse
        from arena.verifier.bundle import export_evidence_bundle
        with pytest.raises(DependencyUnavailable, match="VALID_INTEGRITY"):
            env.controller.export(env.principals["auditor"], destination / "evidence.zip")
        assert not (destination / "evidence.zip").exists()
        with closing(env.controller.store.connect()) as conn:
            run = conn.execute("SELECT * FROM n04_runs").fetchone()
            turns = [SignedTurnReceipt.model_validate_json(r[0]) for r in conn.execute("SELECT receipt_json FROM n04_turns WHERE state='DONE'")]
        checkpoint = SignedCheckpoint.model_validate_json(run["close_json"])
        export_evidence_bundle(destination / "evidence.zip", checkpoint, SignedWitnessClose.model_validate_json(run["witness_json"]),
            env.controller.recorder.get_events(env.ctx), env.controller.vault.export_ciphertexts(checkpoint.checkpoint.required_artifacts),
            signed_witness_start=StartResponse.model_validate_json(run["start_json"]).witness_start_receipt, turn_receipts=turns)
    else:
        env.controller.export(env.principals["auditor"], destination / "evidence.zip")
    safe_extract_archive(destination / "evidence.zip", destination / "extracted")
    return verify_evidence_directory(
        destination / "extracted",
        env.rec_pub,
        env.wit_pub,
        env.ctx,
        env.start.witness_start_receipt.receipt.public_manifest_digest,
        "recorder",
        "witness",
        expected_defense_mode=mode,
        expected_broker_actor=ACTOR,
    )


@pytest.mark.parametrize(
    "mode,verdict,execution",
    [
        ("INPUT", "ALLOW", "EXECUTED"),
        ("INPUT", "BLOCK", "NOT_EVALUATED"),
        ("INPUT", "SANITIZE", "EXECUTED"),
        ("FEATURES", "BLOCK", "NOT_EVALUATED"),
        ("OUTPUT", "BLOCK", "EXECUTED"),
    ],
)
def test_mode_truth_and_independent_public_private_verification(
    tmp_path, mode, verdict, execution
):
    async def exercise():
        env = await environment(tmp_path, mode, (verdict,))
        item = payload("sanitize_control test" if verdict == "SANITIZE" else "test")
        result = await turn(env, item)
        before = len(env.recorder.get_events(env.ctx))
        assert await turn(env, item) == result
        assert len(env.recorder.get_events(env.ctx)) == before
        assert result.result.model_execution == execution
        assert len(env.runtime.model.calls) == (execution == "EXECUTED")
        if verdict == "SANITIZE":
            assert env.runtime.model.calls[0].text == "[REDACTED] test"
        cp = await env.controller.close(env.principals["operator"])
        assert env.controller.release(
            env.principals["operator"]
        ) == env.controller.release(env.principals["operator"])
        verification = verify_export(env, tmp_path, mode)
        assert verification.status == "PASS_PUBLIC_EVIDENCE"
        secrets = env.vault.private_replay_keys(cp.checkpoint.required_artifacts)
        plaintexts = replay_and_decrypt_artifacts(
            tmp_path / "extracted" / "artifacts",
            {key: bytes.fromhex(value["key"]) for key, value in secrets.items()},
            env.ctx,
            {key: value["classification"] for key, value in secrets.items()},
        )
        assert verify_n04_openings(tmp_path / "extracted", plaintexts, mode) == 1
        assert env.broker.status(env.principals["blue-human"], env.ctx.experiment_id)[
            1
        ] == {"status": "EMBARGOED"}

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "failure,execution",
    [
        (ConnectionError("lost ACK"), "UNKNOWN"),
        (TargetNotDispatched("input rejected"), "NOT_EVALUATED"),
    ],
)
def test_model_failure_never_retries_and_closes_authentic_invalid(
    tmp_path, failure, execution
):
    async def exercise():
        env = await environment(tmp_path)
        env.runtime.model.failure = failure
        item = payload()
        with pytest.raises(type(failure)):
            await turn(env, item)
        with pytest.raises(DependencyUnavailable):
            await turn(env, item)
        assert len(env.runtime.model.calls) == 1
        with closing(env.store.connect()) as conn:
            recorded = json.loads(
                conn.execute("SELECT result_json FROM turns").fetchone()[0]
            )
        assert recorded["model_execution"] == execution
        assert recorded["integrity"] == "INVALID"
        await env.controller.close(env.principals["operator"])
        assert verify_export(env, tmp_path, "INPUT", invalid_fixture=True).status == "AUTHENTIC_INVALID"

    asyncio.run(exercise())


def test_missing_dispatch_ack_prevents_model_call(tmp_path, monkeypatch):
    async def exercise():
        env = await environment(tmp_path)
        original = env.recorder.append_once

        async def fail(proposal, *args):
            if proposal.event_type == "DISPATCH_INTENT":
                raise DependencyUnavailable("RECORDER_UNAVAILABLE")
            return await original(proposal, *args)

        monkeypatch.setattr(env.recorder, "append_once", fail)
        with pytest.raises(DependencyUnavailable):
            await turn(env, payload())
        assert env.runtime.model.calls == []

    asyncio.run(exercise())


def test_wrong_defense_call_token_never_reaches_model(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        env.runtime.bad_token = True
        with pytest.raises(DependencyUnavailable, match="DEFENSE_CALL_TOKEN_MISMATCH"):
            await turn(env, payload())
        assert env.runtime.model.calls == []

    asyncio.run(exercise())


@pytest.mark.parametrize(
    "role,code", [("blue-human", "FORBIDDEN"), ("red", "NOT_FOUND")]
)
def test_wrong_role_or_unowned_payload_never_reaches_private_store(
    tmp_path, monkeypatch, role, code
):
    async def exercise():
        env = await environment(tmp_path)

        def forbidden_read(*args):
            raise AssertionError("Private store read before authorization")

        monkeypatch.setattr(env.store, "read_payload", forbidden_read)
        from arena.broker.store import BrokerError

        with pytest.raises(BrokerError, match=code):
            await env.controller.turn(
                env.principals[role],
                env.session,
                TurnSubmission(
                    epoch=env.ctx.epoch, turn_index=0, payload_ref=str(uuid4())
                ),
                "turn",
                payload(),
            )
        with closing(env.store.connect()) as conn:
            assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 0
        assert env.runtime.model.calls == []

    asyncio.run(exercise())


def test_post_hoc_is_explicitly_gated_not_silently_run_before_reveal(tmp_path):
    async def exercise():
        env = await environment(tmp_path, mode="POST_HOC", decisions=("BLOCK",))
        result = await turn(env, payload("post-release canary"))
        assert (
            env.runtime.requests == [] and result.result.model_execution == "EXECUTED"
        )
        with pytest.raises(
            DependencyUnavailable, match="POST_HOC_REQUIRES_AUTHORIZED_RELEASE"
        ):
            await env.controller.analyze_after_release(
                env.principals["operator"], result.turn_id
            )
        cp = await env.controller.close(env.principals["operator"])
        before = tuple(env.recorder.get_events(env.ctx))
        with pytest.raises(DependencyUnavailable):
            await env.controller.analyze_after_release(
                env.principals["operator"], result.turn_id
            )
        release = env.controller.release(env.principals["operator"])
        signed = await env.controller.analyze_after_release(
            env.principals["operator"], result.turn_id
        )
        assert (
            await env.controller.analyze_after_release(
                env.principals["operator"], result.turn_id
            )
            == signed
        )
        assert (
            tuple(env.recorder.get_events(env.ctx)) == before
            and len(env.runtime.requests) == 1
        )
        assert env.runtime.requests[0].mode == "POST_HOC"
        with closing(env.store.connect()) as conn:
            outcome = json.loads(
                conn.execute(
                    "SELECT result_json FROM turns WHERE id=?", (result.turn_id,)
                ).fetchone()[0]
            )
        assert (
            outcome["pipeline_disposition"] == "ALLOWED"
            and outcome["model_execution"] == "EXECUTED"
        )
        verify_export(env, tmp_path, "POST_HOC")
        secrets = env.vault.private_replay_keys(cp.checkpoint.required_artifacts)
        plaintexts = replay_and_decrypt_artifacts(
            tmp_path / "extracted" / "artifacts",
            {key: bytes.fromhex(value["key"]) for key, value in secrets.items()},
            env.ctx,
            {key: value["classification"] for key, value in secrets.items()},
        )
        assert verify_n04_openings(tmp_path / "extracted", plaintexts, "POST_HOC") == 1
        env.controller.export_analysis(
            env.principals["auditor"], result.turn_id, tmp_path / "analysis.zip"
        )
        safe_extract_archive(tmp_path / "analysis.zip", tmp_path / "late")
        late_keys = env.vault.private_replay_keys((signed.receipt.analysis_artifact,))
        assert (
            verify_post_hoc_directory(
                tmp_path / "late",
                tmp_path / "extracted",
                env.ctx,
                release,
                env.rec_pub,
                "recorder",
                plaintexts,
                late_keys,
                "VALID_WITHIN_PROFILE",
            )["analysis_kind"]
            == "POST_RELEASE_ONLY"
        )
        with pytest.raises(VerificationError):
            verify_post_hoc_directory(
                tmp_path / "late",
                tmp_path / "extracted",
                env.ctx,
                str(uuid4()),
                env.rec_pub,
                "recorder",
                plaintexts,
                late_keys,
                "VALID_WITHIN_PROFILE",
            )
        with pytest.raises(VerificationError):
            verify_post_hoc_directory(
                tmp_path / "late",
                tmp_path / "extracted",
                env.ctx,
                release,
                os.urandom(32),
                "recorder",
                plaintexts,
                late_keys,
                "VALID_WITHIN_PROFILE",
            )

    asyncio.run(exercise())


def test_post_hoc_lost_ack_never_repeats_blue_call_or_changes_closed_run(
    tmp_path, monkeypatch
):
    async def exercise():
        env = await environment(tmp_path, mode="POST_HOC", decisions=("ALLOW",))
        result = await turn(env, payload())
        await env.controller.close(env.principals["operator"])
        env.controller.release(env.principals["operator"])
        before = tuple(env.recorder.get_events(env.ctx))
        evaluate = env.runtime.evaluate

        async def lose(request):
            await evaluate(request)
            raise ConnectionError("Lost analysis ACK")

        monkeypatch.setattr(env.runtime, "evaluate", lose)
        with pytest.raises(ConnectionError):
            await env.controller.analyze_after_release(
                env.principals["operator"], result.turn_id
            )
        with pytest.raises(
            DependencyUnavailable, match="POST_HOC_REQUIRES_EXPLICIT_RECOVERY"
        ):
            await env.controller.analyze_after_release(
                env.principals["operator"], result.turn_id
            )
        assert (
            len(env.runtime.requests) == 1
            and tuple(env.recorder.get_events(env.ctx)) == before
        )

    asyncio.run(exercise())


def test_invalid_aggregate_cannot_release_or_authorize_post_hoc_analysis(tmp_path):
    async def exercise():
        env = await environment(tmp_path, mode="POST_HOC", decisions=("ALLOW",))
        result = await turn(env, payload())
        await env.controller._event("INTEGRITY_VIOLATION", "INVALID")
        env.controller._invalidate()
        await env.controller.close(env.principals["operator"])
        with pytest.raises(DependencyUnavailable, match="RELEASE_REQUIRES_VALID_INTEGRITY"):
            env.controller.release(env.principals["operator"])
        with pytest.raises(DependencyUnavailable, match="POST_HOC_REQUIRES_AUTHORIZED_RELEASE"):
            await env.controller.analyze_after_release(env.principals["operator"], result.turn_id)
        with closing(env.store.connect()) as conn:
            assert tuple(conn.execute("SELECT phase,integrity FROM experiments").fetchone()) == ("CLOSED", "INVALID")
        assert verify_export(env, tmp_path, "POST_HOC", invalid_fixture=True).exit_code == 5

    asyncio.run(exercise())


def test_n04_artifact_budget_admission_does_not_dispatch_extra_work(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        with env.store.transaction() as conn:
            conn.execute("UPDATE budgets SET admitted=24")
        from arena.broker.store import BrokerError

        with pytest.raises(BrokerError, match="RESOURCE_BUDGET_EXCEEDED"):
            await turn(env, payload())
        assert env.runtime.model.calls == []

    asyncio.run(exercise())


def test_restart_retains_already_executed_fact(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        result = await turn(env, payload())
        with env.store.transaction() as conn:
            conn.execute(
                "UPDATE turns SET state='DISPATCHED' WHERE id=?", (result.turn_id,)
            )
        assert env.store.recover_ambiguous() == 1
        with closing(env.store.connect()) as conn:
            actual = json.loads(
                conn.execute("SELECT result_json FROM turns").fetchone()[0]
            )
        assert (
            actual["model_execution"] == "EXECUTED" and actual["integrity"] == "INVALID"
        )
        assert len(env.runtime.model.calls) == 1

    asyncio.run(exercise())


def test_scoring_failure_retains_completed_model_fact(tmp_path, monkeypatch):
    async def exercise():
        env = await environment(tmp_path)

        def fail(_):
            raise ValueError("scorer unavailable")

        monkeypatch.setattr(
            "arena.integration.controller.evaluate_refusal_rubric", fail
        )
        with pytest.raises(ValueError):
            await turn(env, payload())
        with closing(env.store.connect()) as conn:
            recorded = json.loads(
                conn.execute("SELECT result_json FROM turns").fetchone()[0]
            )
        assert (
            recorded["model_execution"] == "EXECUTED"
            and recorded["scoring"] == "FAILED"
            and recorded["integrity"] == "INVALID"
        )
        await env.controller.close(env.principals["operator"])
        assert verify_export(env, tmp_path, "INPUT", invalid_fixture=True).status == "AUTHENTIC_INVALID"

    asyncio.run(exercise())


def test_reset_failure_invalidates_completed_run(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        await turn(env, payload())
        env.runtime.model.reset_failure = DependencyUnavailable("RESET_UNKNOWN")
        await env.controller.close(env.principals["operator"])
        assert verify_export(env, tmp_path, "INPUT", invalid_fixture=True).exit_code == 5

    asyncio.run(exercise())


def test_lost_witness_close_ack_retries_exact_checkpoint_without_new_execution(
    tmp_path, monkeypatch
):
    async def exercise():
        env = await environment(tmp_path)
        await turn(env, payload())
        original = env.witness.close_checkpoint
        lost = True

        async def close_with_lost_ack(checkpoint):
            nonlocal lost
            receipt = await original(checkpoint)
            if lost:
                lost = False
                raise ConnectionError("ACK lost after durable commit")
            return receipt

        monkeypatch.setattr(env.witness, "close_checkpoint", close_with_lost_ack)
        with pytest.raises(ConnectionError):
            await env.controller.close(env.principals["operator"])
        before = len(env.recorder.get_events(env.ctx))
        with pytest.raises(DependencyUnavailable):
            env.controller.release(env.principals["operator"])
        await env.controller.close(env.principals["operator"])
        assert (
            len(env.recorder.get_events(env.ctx)) == before
            and len(env.runtime.model.calls) == 1
        )
        assert verify_export(env, tmp_path, "INPUT").exit_code == 0

    asyncio.run(exercise())


def test_wrong_mode_and_missing_start_are_not_verified(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        await turn(env, payload())
        await env.controller.close(env.principals["operator"])
        verify_export(env, tmp_path, "INPUT")
        with pytest.raises(VerificationError):
            verify_evidence_directory(
                tmp_path / "extracted",
                env.rec_pub,
                env.wit_pub,
                env.ctx,
                env.start.witness_start_receipt.receipt.public_manifest_digest,
                "recorder",
                "witness",
                expected_defense_mode="OUTPUT",
                expected_broker_actor=ACTOR,
            )
        (tmp_path / "extracted" / "witness_start.json").unlink()
        with pytest.raises(VerificationError):
            verify_evidence_directory(
                tmp_path / "extracted",
                env.rec_pub,
                env.wit_pub,
                env.ctx,
                env.start.witness_start_receipt.receipt.public_manifest_digest,
                "recorder",
                "witness",
                expected_defense_mode="INPUT",
                expected_broker_actor=ACTOR,
            )

    asyncio.run(exercise())


def test_receipt_opening_tamper_is_rejected(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        await turn(env, payload())
        cp = await env.controller.close(env.principals["operator"])
        verify_export(env, tmp_path, "INPUT")
        secrets = env.vault.private_replay_keys(cp.checkpoint.required_artifacts)
        plaintexts = replay_and_decrypt_artifacts(
            tmp_path / "extracted" / "artifacts",
            {key: bytes.fromhex(value["key"]) for key, value in secrets.items()},
            env.ctx,
            {key: value["classification"] for key, value in secrets.items()},
        )
        for identifier, value in plaintexts.items():
            obj = json.loads(value)
            if obj.get("kind") == "INPUT_OPENING":
                obj["nonce_hex"] = "00" * 32
                plaintexts[identifier] = json.dumps(obj).encode()
                break
        with pytest.raises(ValueError, match="Commitment opening mismatch"):
            verify_n04_openings(tmp_path / "extracted", plaintexts, "INPUT")

    asyncio.run(exercise())


def test_recorder_retries_actor_and_ciphertext_bounds(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        artifact = env.vault.put({"fixture": "test"}, "PRIVATE_PAYLOAD")
        with pytest.raises(DependencyUnavailable, match="ARTIFACT_BYTES_REQUIRED"):
            env.recorder.register_artifact(
                artifact.artifact_id, artifact.ciphertext_sha256
            )
        path = env.vault.root / f"{artifact.artifact_id}.bin"
        env.recorder.register_artifact(
            artifact.artifact_id, artifact.ciphertext_sha256, str(path), context=env.ctx
        )
        proposal = EventProposal(
            **env.ctx.model_dump(),
            session_id=None,
            turn_id=None,
            turn_index=None,
            event_type="INTEGRITY_VIOLATION",
            outcome_code="INVALID",
            artifact_ciphertext_refs=(artifact,),
            duration_us=0,
        )
        operation = str(uuid4())
        one = await env.recorder.append_once(proposal, ACTOR, operation)
        assert await env.recorder.append_once(proposal, ACTOR, operation) == one
        with pytest.raises(DependencyUnavailable):
            await env.recorder.append_once(proposal, "wrong-actor", str(uuid4()))
        with pytest.raises(DependencyUnavailable):
            await env.recorder.append_once(
                proposal.model_copy(update={"outcome_code": "FAILED"}), ACTOR, operation
            )
        path.write_bytes(b"substituted")
        with pytest.raises(
            DependencyUnavailable, match="ARTIFACT_BYTES_LOST_OR_CHANGED"
        ):
            await env.recorder.append_once(proposal, ACTOR, str(uuid4()))

    asyncio.run(exercise())


def test_witness_pins_key_material_and_requires_authenticated_requests(tmp_path):
    async def exercise():
        env = await environment(tmp_path)
        with pytest.raises(
            DependencyUnavailable, match="AUTHENTICATED_RECORDER_START_REQUIRED"
        ):
            await env.witness.reserve_start(env.start.witness_start_receipt.receipt)
        with pytest.raises(
            DependencyUnavailable, match="RECORDER_START_SIGNATURE_INVALID"
        ):
            await env.witness.reserve_start_authenticated(
                env.start.witness_start_receipt.receipt, "0" * 128
            )
        with pytest.raises(
            DependencyUnavailable, match="WITNESS_AUTHORITY_STATE_MISMATCH"
        ):
            SQLiteWitnessAuthority(
                tmp_path / "witness.sqlite3",
                os.urandom(32),
                "witness",
                recorder_public_key=env.rec_pub,
                recorder_key_id="recorder",
            )

    asyncio.run(exercise())

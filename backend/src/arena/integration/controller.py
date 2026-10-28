"""N04 trusted single-lane controller. No participant HTTP/shaping shortcut.

Database intent, recorder ACK, witness ACK and inference are separate commits.
Restarted/ambiguous operations are never dispatched again automatically. This is
a bounded local integration profile, not N05 concurrency or N06 timing evidence.
"""

import base64
import asyncio
from contextvars import ContextVar
import hashlib
import hmac
import json
import zipfile
from contextlib import closing
from dataclasses import dataclass
import os
from pathlib import Path
import re
import tempfile
from uuid import UUID, uuid4, uuid5
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey, Ed25519PublicKey

from arena.broker.config import Profile
from arena.broker.store import BrokerError
from arena.contracts.api import (
    AttemptResult,
    DefenseDecision,
    FeaturesContent,
    FeaturesDefenseRequest,
    InputDefenseRequest,
    OutputDefenseRequest,
    PromptContent,
    PostHocContent,
    PostHocDefenseRequest,
    ResponseContent,
    TargetRequest,
    TargetResponse,
)
from arena.contracts.crypto import (
    canonical_bytes,
    commitment,
    event_digest,
    sha256,
    witness_message,
    verify_witness_close,
    verify_checkpoint,
    verify,
    checkpoint_digest,
    turn_message,
    validate_chain,
    request_digest,
)
from arena.contracts.evidence import (
    ArtifactRef,
    EventProposal,
    StartResponse,
    SignedCheckpoint,
    SignedWitnessClose,
    TurnReceipt,
    WitnessStart,
    SignedTurnReceipt,
    TurnFeedback,
)
from arena.evaluation.rubric import evaluate_refusal_rubric
from arena.ports import (
    DependencyUnavailable,
    TargetNotDispatched,
    validate_target_binding,
)
from arena.verifier.bundle import export_evidence_bundle
from arena.verifier.semantics import validate_run_semantics
from arena.verifier.invalid_bundle import export_invalid_evidence_bundle
from arena.recovery.anchor import (
    RecoveryAnchorError,
    operation_id as anchor_operation_id,
    record_digest,
    verify_anchor_records,
)
from arena.recovery.feedback import (
    FeedbackRecoveryRequest,
    FeedbackReconciliation,
    FeedbackReconciliationUnsigned,
    FeedbackReplay,
    FeedbackReplayUnsigned,
    sign_reconciliation,
    sign_replay,
    verify_reconciliation,
    verify_replay,
)
from .types import ScoreObservation, PostHocReceipt, SignedPostHocReceipt


ACTOR = "n04-trusted-broker"
RULES = ("sanitize_control",)
BLOCK_REPLY = "Request blocked by the frozen defense."
_RECOVERY_VALIDATION_TURN: ContextVar[str | None] = ContextVar(
    "arena_recovery_validation_turn", default=None
)


def encode_text(text):
    return base64.b64encode(text.encode("utf-8")).decode("ascii")


def input_bytes(turn, original, effective, provenance):
    return canonical_bytes(
        {
            "schema_version": "arena-n04-input.v1",
            **turn,
            "original_utf8_base64": encode_text(original),
            "effective_utf8_base64": encode_text(effective),
            "provenance": provenance,
        }
    )


def response_bytes(turn, reply, status):
    # Excludes signature/commitment/padding to avoid a circular signing dependency.
    return canonical_bytes(
        {
            "schema_version": "arena-n04-public-response.v1",
            **turn,
            "public_reply_utf8_base64": encode_text(reply),
            "public_status": status,
        }
    )


def sanitize(text):
    result = text
    matched = False
    for rule in RULES:
        result, count = re.subn(
            re.escape(rule), "[REDACTED]", result, flags=re.IGNORECASE | re.ASCII
        )
        matched |= bool(count)
    if not matched or len(result.encode("utf-8")) > 65_536:
        raise DependencyUnavailable("SANITIZE_TRANSFORM_FAILED")
    return result


@dataclass(frozen=True)
class InternalTurnResult:
    turn_id: str
    result: AttemptResult
    public_reply: str
    receipt: SignedTurnReceipt


class N04Controller:
    def __init__(
        self,
        broker,
        recorder,
        witness,
        vault,
        runtime,
        corpus,
        *,
        recorder_public_key,
        witness_public_key,
        transport_admission=None,
        recovery_authority=None,
        recovery_private_key=None,
    ):
        self.broker, self.store = broker, broker.store
        self.transport_admission = transport_admission
        self.recorder, self.witness, self.vault, self.runtime, self.corpus = (
            recorder,
            witness,
            vault,
            runtime,
            corpus,
        )
        self.ctx = vault.context
        self.recorder_public_key, self.witness_public_key = (
            recorder_public_key,
            witness_public_key,
        )
        self.recovery_authority = recovery_authority
        self.recovery_private_key = recovery_private_key
        self.recovery_lock = asyncio.Lock()
        self.recovery_admission_blocked = False
        self.identifier = self.ctx.experiment_id
        with self.store.transaction() as conn:
            conn.executescript("""
                CREATE TABLE IF NOT EXISTS n04_runs(experiment_id TEXT PRIMARY KEY,state TEXT NOT NULL,
                    start_json TEXT,close_json TEXT,witness_json TEXT,release_id TEXT,manifest_digest TEXT NOT NULL);
                CREATE TABLE IF NOT EXISTS n04_turns(turn_id TEXT PRIMARY KEY,source_ref TEXT NOT NULL,state TEXT NOT NULL,
                    known_execution TEXT NOT NULL,result_json TEXT,feedback_ref TEXT,receipt_json TEXT);
                CREATE TABLE IF NOT EXISTS n04_analyses(turn_id TEXT PRIMARY KEY,state TEXT NOT NULL,receipt_json TEXT);
                CREATE TABLE IF NOT EXISTS n04_recoveries(
                    domain_id TEXT NOT NULL, experiment_id TEXT NOT NULL, epoch INTEGER NOT NULL,
                    turn_id TEXT NOT NULL, owner TEXT NOT NULL, client_key TEXT NOT NULL,
                    recovery_operation_id TEXT NOT NULL UNIQUE, proof_json TEXT NOT NULL,
                    replay_ref TEXT NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch,turn_id));
                CREATE TABLE IF NOT EXISTS n04_receipt_copies(
                    domain_id TEXT NOT NULL,experiment_id TEXT NOT NULL,epoch INTEGER NOT NULL,
                    turn_id TEXT NOT NULL,owner TEXT NOT NULL,client_key TEXT NOT NULL,
                    receipt_json TEXT NOT NULL,body_ref TEXT NOT NULL,
                    PRIMARY KEY(domain_id,experiment_id,epoch,turn_id));
                CREATE TABLE IF NOT EXISTS n04_recovery_failures(
                    turn_id TEXT PRIMARY KEY,internal_execution TEXT,job_execution TEXT,
                    original_body_ref TEXT,original_receipt_json TEXT,original_feedback_ref TEXT);
            """)

    def _row(self, principal):
        with closing(self.store.connect()) as conn:
            return dict(
                self.broker._object(conn, principal, self.identifier, self.ctx.epoch)
            )

    def _artifact(self, value, classification):
        ref = self.vault.put(value, classification)
        self.recorder.register_artifact(
            ref.artifact_id,
            ref.ciphertext_sha256,
            str(self.vault.root / f"{ref.artifact_id}.bin"),
            context=self.ctx,
        )
        return ref

    async def _defend(self, request):
        decision = await self.runtime.evaluate(request)
        decision = DefenseDecision.model_validate(decision.model_dump())
        if decision.call_token != request.call_token:
            raise DependencyUnavailable("DEFENSE_CALL_TOKEN_MISMATCH")
        return decision

    async def _event(self, kind, outcome="OK", refs=(), turn=None, operation=None):
        proposal = EventProposal(
            **self.ctx.model_dump(),
            session_id=turn["session_id"] if turn else None,
            turn_id=turn["turn_id"] if turn else None,
            turn_index=turn["turn_index"] if turn else None,
            event_type=kind,
            outcome_code=outcome,
            artifact_ciphertext_refs=tuple(refs),
            duration_us=0,
        )
        identifier = (
            str(uuid5(UUID(self.identifier), operation)) if operation else str(uuid4())
        )
        return await self.recorder.append_once(proposal, ACTOR, identifier)

    async def start(self, principal):
        self.broker._role(principal, "operator")
        row = self._row(principal)
        profile = Profile.model_validate_json(row["config_json"])
        sealed = self.store.read_payload(row["manifest_id"]) if row["manifest_id"] else {"manifest": {}}
        if "n06_transport" in sealed["manifest"] or self.transport_admission is not None:
            if self.transport_admission is None:
                raise DependencyUnavailable("SEALED_TRANSPORT_START_TRUST_REQUIRED")
            plan = self.transport_admission.check_manifest(sealed["manifest"], self.ctx)
            with closing(self.store.connect()) as conn:
                binding = conn.execute("SELECT signed_json FROM n06_policies WHERE experiment_id=?", (self.identifier,)).fetchone()
            from arena.contracts.transport_profile import SignedPolicy
            if not binding or SignedPolicy.model_validate_json(binding[0]) != plan.feedback:
                raise DependencyUnavailable("SEALED_TRANSPORT_QUEUE_POLICY_MISMATCH")
        if (
            profile.execution_lock_sha256 != sha256(self.runtime.lock_bytes)
            or self.corpus.receipt_sha256 != self.runtime.lock["corpus_receipt_sha256"]
        ):
            raise DependencyUnavailable("EXECUTION_ADMISSION_MISMATCH")
        if (
            profile.query_budget > 24
            or profile.session_limit != getattr(self.runtime, "lane_count", 1)
            or getattr(self.runtime, "lane_count", 1) not in {1, 3}
            or not self.runtime.started
            or profile.request.interaction_mode not in getattr(self.runtime, "supported_interaction_modes", {"INTERACTIVE"})
        ):
            raise DependencyUnavailable("LOCAL_LANE_PROFILE_REQUIRED")
        with self.store.transaction() as conn:
            old = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (self.identifier,)
            ).fetchone()
            if old:
                if (
                    old["state"] == "RUNNING"
                    and row["phase"] == "RUNNING"
                    and self.witness.watermark(self.ctx) == (0, self.ctx.epoch)
                ):
                    return StartResponse.model_validate_json(old["start_json"])
                raise DependencyUnavailable("START_REQUIRES_EXPLICIT_RECOVERY")
            if row["phase"] != "SEALED":
                raise BrokerError("WRONG_PHASE")
            conn.execute(
                "INSERT INTO n04_runs(experiment_id,state,manifest_digest) VALUES(?,'PREPARING',?)",
                (self.identifier, row["public_commitment"]),
            )
        try:
            runtime_facts = await asyncio.to_thread(self.runtime.inspect)
            self.recorder.register_run(
                self.ctx, row["public_commitment"], actor_id=ACTOR
            )
            sealed = self.store.read_payload(row["manifest_id"])
            manifest = self._artifact(
                {
                    "sealed": sealed,
                    "execution_lock": self.runtime.lock,
                    "execution_lock_bytes_base64": base64.b64encode(
                        self.runtime.lock_bytes
                    ).decode(),
                },
                "PRIVATE_MANIFEST",
            )
            readiness = self._artifact(
                {
                    "runtime": runtime_facts,
                    "corpus_receipt_sha256": self.corpus.receipt_sha256,
                    "scope": "N04_SINGLE_LANE_LOCAL_INTEGRATION",
                },
                "PRIVATE_MANIFEST",
            )
            await self._event("MANIFEST_SEALED", refs=(manifest,), operation="manifest")
            await self._event(
                "PREFLIGHT_PASSED", refs=(readiness,), operation="preflight"
            )
            with self.store.transaction() as conn:
                if (
                    conn.execute(
                        "SELECT phase FROM experiments WHERE id=?", (self.identifier,)
                    ).fetchone()[0]
                    != "SEALED"
                ):
                    raise BrokerError("WRONG_PHASE")
                conn.execute(
                    "UPDATE experiments SET phase='READY' WHERE id=?",
                    (self.identifier,),
                )
            event = await self._event("START_RESERVED", operation="start")
            start = WitnessStart(
                **self.ctx.model_dump(),
                schema_version="arena.v2",
                receipt_type="START",
                public_manifest_digest=row["public_commitment"],
                reservation_id=str(uuid5(UUID(self.identifier), "witness-start")),
                event_count=event.sequence,
                prefix_root=event_digest(event),
                witness_key_id=self.witness.witness_key_id,
            )
            # Recorder authenticates the exact durable prefix, not arbitrary caller metadata.
            if event != self.recorder.get_events(self.ctx)[-1]:
                raise DependencyUnavailable("START_PREFIX_CHANGED")
            signature = self.recorder.authorize_start(start, ACTOR)
            signed = await self.witness.reserve_start_authenticated(start, signature)
            if signed.receipt != start or not verify(
                witness_message(start), signed.signature, self.witness_public_key
            ):
                raise DependencyUnavailable("WITNESS_START_ACK_INVALID")
            result = StartResponse(
                **self.ctx.model_dump(),
                phase="RUNNING",
                receipt_id=str(uuid4()),
                witness_start_receipt=signed,
            )
            with self.store.transaction() as conn:
                current = conn.execute(
                    "SELECT phase FROM experiments WHERE id=?", (self.identifier,)
                ).fetchone()
                if current[0] != "READY":
                    raise BrokerError("WRONG_PHASE")
                conn.execute(
                    "UPDATE experiments SET phase='RUNNING' WHERE id=?",
                    (self.identifier,),
                )
                conn.execute(
                    "UPDATE n04_runs SET state='RUNNING',start_json=? WHERE experiment_id=?",
                    (result.model_dump_json(), self.identifier),
                )
            return result
        except BaseException:
            self._invalidate()
            raise

    def _invalidate(self):
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE experiments SET phase='INVALID',integrity='INVALID' WHERE id=? AND phase NOT IN ('CLOSED','RELEASED')",
                (self.identifier,),
            )
            conn.execute(
                "UPDATE n04_runs SET state='INVALID' WHERE experiment_id=? AND state NOT IN ('CLOSED','RELEASED')",
                (self.identifier,),
            )

    async def turn(self, principal, session_id, request, key, payload):
        self.broker._role(principal, "red")
        row = self._row(principal)
        profile = Profile.model_validate_json(row["config_json"])
        if (
            payload.provenance.run_label != profile.run_label
            or profile.run_label not in {"REAL_PUBLIC", "SYNTHETIC_MOCK"}
        ):
            raise DependencyUnavailable("RUN_LABEL_MISMATCH")
        if profile.run_label == "REAL_PUBLIC":
            admitted = await self.corpus.resolve(payload.payload_ref)
            if admitted != payload:
                raise DependencyUnavailable("REAL_PAYLOAD_PROVENANCE_MISMATCH")
        with closing(self.store.connect()) as conn:
            session = dict(self.broker._session(conn, row, session_id, principal.subject_id))
            if (
                request.payload_ref
                and not conn.execute(
                    "SELECT 1 FROM batch_items WHERE experiment_id=? AND artifact_id=?",
                    (self.identifier, request.payload_ref),
                ).fetchone()
            ):
                raise BrokerError("NOT_FOUND", 404)
        # The trusted loader's source text must equal the actual control admission.
        text = request.text
        if request.payload_ref:
            text = self.store.read_payload(request.payload_ref)["text"]
        if text != payload.text:
            raise DependencyUnavailable("SOURCE_PAYLOAD_MISMATCH")
        _, reserved = self.broker.reserve_turn(
            principal, self.identifier, session_id, request, key
        )
        turn = {
            **self.ctx.model_dump(),
            "session_id": session_id,
            "turn_id": reserved["turn_id"],
            "turn_index": request.turn_index,
        }
        with self.store.transaction() as conn:
            old = conn.execute(
                "SELECT * FROM n04_turns WHERE turn_id=?", (turn["turn_id"],)
            ).fetchone()
            if old:
                if old["source_ref"] != payload.payload_ref:
                    raise DependencyUnavailable("TURN_SOURCE_RETRY_CONFLICT")
                if old["state"] == "DONE":
                    from arena.contracts.evidence import ArtifactRef

                    value = self.vault.get(
                        ArtifactRef.model_validate_json(old["feedback_ref"])
                    )
                    return InternalTurnResult(
                        turn["turn_id"],
                        AttemptResult.model_validate_json(old["result_json"]),
                        base64.b64decode(value["public_reply_utf8_base64"]).decode(),
                        SignedTurnReceipt.model_validate_json(old["receipt_json"]),
                    )
                raise DependencyUnavailable("TURN_REQUIRES_EXPLICIT_RECOVERY")
            current = conn.execute("SELECT e.phase,t.state,s.quarantined FROM experiments e JOIN turns t ON t.experiment_id=e.id "
                                   "JOIN sessions s ON s.id=t.session_id WHERE t.id=?", (turn["turn_id"],)).fetchone()
            if not current or tuple(current) != ("RUNNING", "RESERVED", 0):
                raise TargetNotDispatched("TURN_ADMISSION_NO_LONGER_VALID")
            conn.execute(
                "INSERT INTO n04_turns(turn_id,source_ref,state,known_execution) VALUES(?,?,'RESERVED','NOT_EVALUATED')",
                (turn["turn_id"], payload.payload_ref),
            )
        mode = profile.request.defense_mode
        execution = "NOT_EVALUATED"
        effective = text
        try:
            if getattr(self.runtime, "lane_count", 1) == 3:
                self.runtime.model.bind_session(session_id, session["lane"], self.ctx)
            if self.witness.watermark(self.ctx)[1] != self.ctx.epoch:
                raise DependencyUnavailable("WITNESS_START_AUTHORITY_UNAVAILABLE")
            original = self._artifact(
                {
                    **turn,
                    "original_utf8_base64": encode_text(text),
                    "provenance": payload.provenance.model_dump(),
                },
                "PRIVATE_PAYLOAD",
            )
            await self._event(
                "TURN_COMMITTED",
                refs=(original,),
                turn=turn,
                operation=turn["turn_id"] + ":commit",
            )
            decision = None
            if mode in {"INPUT", "FEATURES"}:
                content = (
                    PromptContent(prompt=text)
                    if mode == "INPUT"
                    else FeaturesContent(
                        length_bucket="SHORT"
                        if len(text.encode()) <= 256
                        else "MEDIUM"
                        if len(text.encode()) <= 2048
                        else "LONG",
                        control_marker_present=any(
                            marker in text.lower()
                            for marker in (
                                "ignore previous",
                                "jailbreak",
                                "injection_control",
                            )
                        ),
                    )
                )
                defense_request = (
                    InputDefenseRequest(
                        call_token=str(uuid4()), mode=mode, content=content
                    )
                    if mode == "INPUT"
                    else FeaturesDefenseRequest(
                        call_token=str(uuid4()), mode=mode, content=content
                    )
                )
                decision = await self._defend(defense_request)
                defense_art = self._artifact(
                    {
                        "request": defense_request.model_dump(),
                        "decision": decision.model_dump(),
                    },
                    "PRIVATE_DEFENSE",
                )
                await self._event(
                    "DEFENSE_RESULT", decision.verdict, (defense_art,), turn
                )
                if decision.verdict == "SANITIZE":
                    effective = sanitize(text)
            reply = BLOCK_REPLY
            scoring = "NOT_EVALUATED"
            blocked = decision is not None and decision.verdict == "BLOCK"
            content = input_bytes(
                turn, text, effective, payload.provenance.model_dump()
            )
            input_nonce = os.urandom(32)
            input_ref = self._artifact(
                {
                    "kind": "INPUT_OPENING",
                    "content_base64": base64.b64encode(content).decode(),
                    "nonce_hex": input_nonce.hex(),
                },
                "PRIVATE_PAYLOAD",
            )
            if not blocked:
                await self._event("DISPATCH_INTENT", refs=(input_ref,), turn=turn)
                with self.store.transaction() as conn:
                    current = conn.execute("SELECT e.phase,t.state,s.quarantined FROM experiments e JOIN turns t ON t.experiment_id=e.id "
                                           "JOIN sessions s ON s.id=t.session_id WHERE t.id=?", (turn["turn_id"],)).fetchone()
                    if not current or tuple(current) != ("RUNNING", "RESERVED", 0):
                        raise TargetNotDispatched("DISPATCH_ADMISSION_NO_LONGER_VALID")
                    conn.execute(
                        "UPDATE turns SET state='DISPATCHED' WHERE id=? AND state='RESERVED'",
                        (turn["turn_id"],),
                    )
                    conn.execute(
                        "UPDATE n04_turns SET state='DISPATCHED',known_execution='UNKNOWN' WHERE turn_id=?",
                        (turn["turn_id"],),
                    )
                execution = "UNKNOWN"
                target = TargetRequest(
                    **self.ctx.model_dump(),
                    attempt_id=turn["turn_id"],
                    session_id=session_id,
                    turn_index=request.turn_index,
                    text=effective,
                    max_output_tokens=self.runtime.lock["max_output_tokens"],
                )
                response = await self.runtime.model.infer(target)
                validate_target_binding(target, response)
                execution = "EXECUTED"
                model_art = self._artifact(
                    response.model_dump(), "PRIVATE_MODEL_OUTPUT"
                )
                with self.store.transaction() as conn:
                    conn.execute(
                        "UPDATE n04_turns SET known_execution='EXECUTED' WHERE turn_id=?",
                        (turn["turn_id"],),
                    )
                await self._event("MODEL_RESULT", refs=(model_art,), turn=turn)
                reply = response.text
                if mode == "OUTPUT":
                    defense_request = OutputDefenseRequest(
                        call_token=str(uuid4()),
                        mode="OUTPUT",
                        content=ResponseContent(response=reply),
                    )
                    decision = await self._defend(defense_request)
                    defense_art = self._artifact(
                        {
                            "request": defense_request.model_dump(),
                            "decision": decision.model_dump(),
                        },
                        "PRIVATE_DEFENSE",
                    )
                    await self._event(
                        "DEFENSE_RESULT", decision.verdict, (defense_art,), turn
                    )
                    if decision.verdict == "BLOCK":
                        reply = BLOCK_REPLY
                    elif decision.verdict == "SANITIZE":
                        reply = sanitize(reply)
                score_value = ScoreObservation(
                    model_output=model_art,
                    refusal_marker_present=evaluate_refusal_rubric(response.text)[
                        "is_refusal"
                    ],
                )
                score = self._artifact(
                    {**turn, "observation": score_value.model_dump()},
                    "PRIVATE_MODEL_OUTPUT",
                )
                await self._event("SCORE_RESULT", refs=(score,), turn=turn)
                scoring = "UNCERTAIN"
            disposition = (
                "BLOCKED_BY_DEFENSE"
                if decision and decision.verdict == "BLOCK"
                else "SANITIZED"
                if decision and decision.verdict == "SANITIZE"
                else "ALLOWED"
            )
            outcome = AttemptResult(
                defense_mode=mode,
                pipeline_disposition=disposition,
                model_execution=execution,
                scoring=scoring,
                integrity="VALID_WITHIN_PROFILE",
            )
            public = response_bytes(turn, reply, "COMPLETED")
            response_nonce = os.urandom(32)
            response_ref = self._artifact(
                {
                    "kind": "PUBLIC_RESPONSE_OPENING",
                    "content_base64": base64.b64encode(public).decode(),
                    "nonce_hex": response_nonce.hex(),
                    "public_reply_utf8_base64": encode_text(reply),
                    "result": outcome.model_dump(),
                },
                "PRIVATE_MODEL_OUTPUT",
            )
            event = await self._event(
                "FEEDBACK_AUTHORIZED", refs=(input_ref, response_ref), turn=turn
            )
            receipt = TurnReceipt(
                **turn,
                schema_version="arena.v2",
                input_commitment=commitment(content, input_nonce),
                event_count=event.sequence,
                prefix_root=event_digest(event),
                public_response_commitment=commitment(public, response_nonce),
                signer_key_id=self.recorder.signer_key_id,
            )
            signed = await self.recorder.authorize_bound_turn(
                receipt, ACTOR, input_ref, response_ref
            )
            with self.store.transaction() as conn:
                if (
                    conn.execute(
                        "SELECT phase FROM experiments WHERE id=?", (self.identifier,)
                    ).fetchone()[0]
                    != "RUNNING"
                ):
                    raise DependencyUnavailable("LATE_RESULT_AFTER_INVALIDATION")
                conn.execute(
                    "UPDATE turns SET state='COMPLETED',result_json=? WHERE id=? AND state IN ('RESERVED','DISPATCHED')",
                    (outcome.model_dump_json(), turn["turn_id"]),
                )
                conn.execute(
                    "UPDATE n04_turns SET state='DONE',known_execution=?,result_json=?,feedback_ref=?,receipt_json=? WHERE turn_id=?",
                    (
                        execution,
                        outcome.model_dump_json(),
                        response_ref.model_dump_json(),
                        signed.model_dump_json(),
                        turn["turn_id"],
                    ),
                )
            # Trusted CLI only: this is not a shaped participant TurnFeedback response.
            return InternalTurnResult(turn["turn_id"], outcome, reply, signed)
        except BaseException as error:
            if isinstance(error, TargetNotDispatched):
                execution = "NOT_EVALUATED"
            failure = AttemptResult(
                defense_mode=mode,
                pipeline_disposition="INFRASTRUCTURE_FAILED",
                model_execution=execution,
                scoring="NOT_EVALUATED" if execution != "EXECUTED" else "FAILED",
                integrity="INVALID",
            )
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE turns SET state=?,result_json=? WHERE id=?",
                    (
                        "UNKNOWN" if execution == "UNKNOWN" else "FAILED",
                        failure.model_dump_json(),
                        turn["turn_id"],
                    ),
                )
                conn.execute(
                    "UPDATE n04_turns SET state='FAILED',known_execution=?,result_json=? WHERE turn_id=?",
                    (execution, failure.model_dump_json(), turn["turn_id"]),
                )
                conn.execute(
                    "UPDATE sessions SET quarantined=1 WHERE id=?", (session_id,)
                )
            self._invalidate()
            try:
                await self._event(
                    "INTEGRITY_VIOLATION",
                    "UNKNOWN" if execution == "UNKNOWN" else "FAILED",
                    turn=turn,
                )
            except Exception:
                pass  # Missing recorder authority still leaves close pending, never successful feedback.
            raise

    async def recover_feedback(self, principal, request: FeedbackRecoveryRequest) -> bytes:
        """Fail closed if reconstruction discovers a mismatch in eligible evidence."""
        token = _RECOVERY_VALIDATION_TURN.set(None)
        try:
            return await self._recover_feedback(principal, request)
        except BaseException as exc:
            turn_id = _RECOVERY_VALIDATION_TURN.get()
            if turn_id is not None:
                # Keep admissions closed across timeouts and ambiguous ACKs, but
                # only classify authenticated contradictions as evidence failure.
                self.recovery_admission_blocked = True
                if self._is_recovery_evidence_mismatch(exc):
                    event_context = self._quarantine_recovery_failure(turn_id)
                    if event_context is not None:
                        try:
                            await self._event(
                                "INTEGRITY_VIOLATION", "FAILED", turn=event_context,
                                operation="feedback-recovery-validation-failed:" + turn_id,
                            )
                        except BaseException:
                            # The durable INVALID/quarantine projection remains
                            # fail-closed if the recorder or anchor is unavailable.
                            pass
            raise
        finally:
            _RECOVERY_VALIDATION_TURN.reset(token)

    @staticmethod
    def _is_recovery_evidence_mismatch(error: BaseException) -> bool:
        """Separate contradictions in admitted evidence from retryable uncertainty."""
        if isinstance(error, (asyncio.CancelledError, TimeoutError, ConnectionError)):
            return False
        if isinstance(error, RecoveryAnchorError):
            return str(error) not in {
                "ANCHOR_UNAVAILABLE", "ANCHOR_PROCESS_EXITED", "ANCHOR_STARTUP_TIMEOUT",
            }
        if isinstance(error, DependencyUnavailable):
            code = str(error)
            if code in {"EXISTING_TURN_RECEIPT_REQUIRES_COPY_RECOVERY", "FEEDBACK_RECOVERY_STATE_CHANGED"}:
                return False
            if code.startswith("FEEDBACK_RECOVERY_AUTHORITY_"):
                return False
            return code.startswith((
                "FEEDBACK_RECOVERY_", "FEEDBACK_REPLAY_RECORD_INVALID",
                "FEEDBACK_RESERVATION_", "CORPUS_", "ARTIFACT_",
                "TURN_AUTHORIZATION_COPY_",
            )) or code == "PAYLOAD_NOT_FOUND"
        return isinstance(error, (ValueError, TypeError, KeyError))

    def _quarantine_recovery_failure(self, turn_id: str):
        """Make an eligible but unverifiable recovery attempt closeable only as INVALID."""
        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT e.phase,e.config_json,t.session_id,t.turn_index,t.state AS turn_state,n.known_execution AS internal_execution,"
                "j.known_execution AS job_execution,j.body_ref,n.receipt_json,n.feedback_ref "
                "FROM experiments e JOIN turns t ON t.experiment_id=e.id "
                "LEFT JOIN n04_turns n ON n.turn_id=t.id JOIN n06_jobs j ON j.turn_id=t.id "
                "WHERE e.id=? AND t.id=?",
                (self.identifier, turn_id),
            ).fetchone()
            if not row or row["phase"] in {"CLOSED", "RELEASED"}:
                return None
            profile = Profile.model_validate_json(row["config_json"])
            conn.execute("INSERT OR IGNORE INTO n04_recovery_failures VALUES(?,?,?,?,?,?)", (
                turn_id, row["internal_execution"], row["job_execution"], row["body_ref"],
                row["receipt_json"], row["feedback_ref"],
            ))
            internal_execution = row["internal_execution"]
            job_execution = row["job_execution"]
            if internal_execution == "EXECUTED" and job_execution == "NOT_EVALUATED":
                known_execution = "EXECUTED"
            elif (internal_execution is None and job_execution == "NOT_EVALUATED"
                    and row["turn_state"] == "RESERVED"
                    and not any(event.turn_id == turn_id and event.event_type == "DISPATCH_INTENT"
                                for event in self.recorder.get_events(self.ctx))):
                known_execution = "NOT_EVALUATED"
            elif (internal_execution not in {"NOT_EVALUATED", "EXECUTED", "UNKNOWN"}
                    or job_execution not in {"NOT_EVALUATED", "EXECUTED", "UNKNOWN"}
                    or internal_execution != job_execution):
                known_execution = "UNKNOWN"
            else:
                known_execution = internal_execution
            scoring = "NOT_EVALUATED" if known_execution == "NOT_EVALUATED" else "FAILED"
            failure = AttemptResult(
                defense_mode=profile.request.defense_mode,
                pipeline_disposition="INFRASTRUCTURE_FAILED",
                model_execution=known_execution,
                scoring=scoring,
                integrity="INVALID",
            ).model_dump_json()
            conn.execute(
                "UPDATE n06_jobs SET state='FAILED',known_execution=?,body_ref=NULL,published=0 WHERE turn_id=?",
                (known_execution, turn_id),
            )
            conn.execute(
                "UPDATE turns SET state=?,result_json=? WHERE id=?",
                ("UNKNOWN" if known_execution == "UNKNOWN" else "FAILED", failure, turn_id),
            )
            conn.execute(
                "UPDATE n04_turns SET state='RECOVERY_INVALID',known_execution=?,result_json=? WHERE turn_id=?",
                (known_execution, failure, turn_id),
            )
            conn.execute("UPDATE sessions SET quarantined=1 WHERE id=?", (row["session_id"],))
            conn.execute(
                "UPDATE experiments SET phase='INVALID',integrity='INVALID' WHERE id=?",
                (self.identifier,),
            )
            conn.execute(
                "UPDATE n04_runs SET state='INVALID' WHERE experiment_id=? AND state NOT IN ('CLOSED','RELEASED')",
                (self.identifier,),
            )
            return {
                "domain_id": self.ctx.domain_id,
                "experiment_id": self.ctx.experiment_id,
                "epoch": self.ctx.epoch,
                "session_id": row["session_id"],
                "turn_id": turn_id,
                "turn_index": row["turn_index"],
            }

    async def invalidate_unrecoverable_feedback(self, principal, turn_id):
        """Explicit terminal recovery for an authenticated ambiguous reservation."""
        self.broker._role(principal, "operator")
        self._row(principal)
        with closing(self.store.connect()) as conn:
            candidate = conn.execute(
                "SELECT t.state,j.state AS job_state FROM turns t JOIN n06_jobs j ON j.turn_id=t.id "
                "WHERE t.id=? AND t.experiment_id=?", (turn_id, self.identifier),
            ).fetchone()
        if (not candidate or candidate["state"] not in {"RESERVED", "DISPATCHED", "UNKNOWN", "FAILED"}
                or candidate["job_state"] not in {"QUEUED", "CLAIMED", "FAILED"}):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_INVALID_CLOSE_NOT_ELIGIBLE")
        self.recovery_admission_blocked = True
        turn = self._quarantine_recovery_failure(turn_id)
        if turn is None:
            raise DependencyUnavailable("FEEDBACK_RECOVERY_INVALID_CLOSE_NOT_ELIGIBLE")
        with closing(self.store.connect()) as conn:
            result = conn.execute("SELECT result_json FROM turns WHERE id=?", (turn_id,)).fetchone()[0]
        execution = AttemptResult.model_validate_json(result).model_execution
        try:
            await self._event(
                "INTEGRITY_VIOLATION", "UNKNOWN" if execution == "UNKNOWN" else "FAILED",
                turn=turn, operation="feedback-recovery-ambiguous-invalid:" + turn_id,
            )
        except Exception:
            # Quarantine is durable. A quiescent INVALID close may record an
            # explicit unverifiable-anchor gap; no valid close is authorized.
            pass
        return {"integrity": "INVALID", "model_execution": execution}

    def _read_recovery_payload(self, ref, kind):
        with closing(self.store.connect()) as conn:
            payload = conn.execute(
                "SELECT experiment_id,kind FROM payloads WHERE artifact_id=?", (ref,)
            ).fetchone()
        if not payload or tuple(payload) != (self.identifier, kind):
            raise DependencyUnavailable("FEEDBACK_REPLAY_RECORD_INVALID")
        try:
            value = self.store.read_payload(ref)
            if set(value) != {"body_base64"}:
                raise ValueError("recovery payload fields")
            return base64.b64decode(value["body_base64"], validate=True)
        except Exception as exc:
            raise DependencyUnavailable("FEEDBACK_REPLAY_RECORD_INVALID") from exc

    async def _recover_feedback(self, principal, request: FeedbackRecoveryRequest) -> bytes:
        """Recover exact stored feedback without another dispatch or arena.v2 signature."""
        self.broker._role(principal, "red")
        if not isinstance(request, FeedbackRecoveryRequest):
            request = FeedbackRecoveryRequest.model_validate(request)
        authority = self.recovery_authority
        private = self.recovery_private_key
        anchor = self.recorder.anchor

        def pinned_recovery_public():
            if (not authority or not isinstance(authority.get("public_key_bytes"), bytes)
                    or not isinstance(authority.get("authority_id"), str)
                    or not isinstance(authority.get("key_id"), str)):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_AUTHORITY_UNAVAILABLE")
            try:
                public = authority["public_key_bytes"]
                Ed25519PublicKey.from_public_bytes(public)
                return public
            except Exception as exc:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_AUTHORITY_UNAVAILABLE") from exc

        def recovery_signing_material(expected_public):
            if private is None:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_AUTHORITY_UNAVAILABLE")
            try:
                private_key = (private if isinstance(private, Ed25519PrivateKey)
                               else Ed25519PrivateKey.from_private_bytes(private))
                private_bytes = private_key.private_bytes_raw()
                if private_key.public_key().public_bytes_raw() != expected_public:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_AUTHORITY_MISMATCH")
                return private_bytes
            except DependencyUnavailable:
                raise
            except Exception as exc:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_AUTHORITY_UNAVAILABLE") from exc

        async with self.recovery_lock:
            with closing(self.store.connect()) as conn:
                copied = conn.execute(
                    "SELECT owner,client_key,receipt_json,body_ref FROM n04_receipt_copies "
                    "WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (self.ctx.domain_id, self.identifier, self.ctx.epoch, request.turn_id),
                ).fetchone()
                if copied:
                    if (copied["owner"] != principal.subject_id
                            or copied["client_key"] != request.idempotency_key):
                        raise DependencyUnavailable("FEEDBACK_REPLAY_UNAVAILABLE")
                    self.recovery_admission_blocked = True
                    _RECOVERY_VALIDATION_TURN.set(request.turn_id)
                    return self._verify_original_copy(
                        copied, request.turn_id, restore_missing_authorization=True
                    )
                existing = conn.execute(
                    "SELECT owner,client_key,proof_json,replay_ref FROM n04_recoveries "
                    "WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (self.ctx.domain_id, self.identifier, self.ctx.epoch, request.turn_id),
                ).fetchone()
                if existing:
                    if (existing["owner"] != principal.subject_id
                            or existing["client_key"] != request.idempotency_key):
                        raise DependencyUnavailable("FEEDBACK_REPLAY_UNAVAILABLE")
                    self.recovery_admission_blocked = True
                    _RECOVERY_VALIDATION_TURN.set(request.turn_id)
                    recovery_public = pinned_recovery_public()
                    from arena.contracts.jsonwire import load_wire
                    replay_bytes = self._read_recovery_payload(existing["replay_ref"], "n04-feedback-replay")
                    replay = load_wire(FeedbackReplay, replay_bytes)
                    proof = replay.feedback_reconciliation
                    if (not verify_reconciliation(proof, recovery_public, authority["authority_id"], authority["key_id"])
                            or not verify_replay(replay, recovery_public, authority["authority_id"], authority["key_id"])
                            or replay.turn_id != request.turn_id
                            or replay.domain_id != self.ctx.domain_id
                            or replay.experiment_id != self.ctx.experiment_id
                            or replay.epoch != self.ctx.epoch
                            or FeedbackReconciliation.model_validate_json(existing["proof_json"]) != proof):
                        raise DependencyUnavailable("FEEDBACK_REPLAY_RECORD_INVALID")
                    await self._settle_recovered_feedback(replay)
                    return replay_bytes

                run = dict(self.broker._object(conn, principal, self.identifier, self.ctx.epoch))
                turn_row = conn.execute(
                    "SELECT t.*,s.owner AS session_owner,s.quarantined,e.phase,e.integrity,e.public_commitment "
                    "FROM turns t JOIN sessions s ON s.id=t.session_id "
                    "JOIN experiments e ON e.id=t.experiment_id "
                    "WHERE t.id=? AND t.experiment_id=?",
                    (request.turn_id, self.identifier),
                ).fetchone()
                job_row = conn.execute(
                    "SELECT * FROM n06_jobs WHERE turn_id=? AND experiment_id=?",
                    (request.turn_id, self.identifier),
                ).fetchone()
                internal_row = conn.execute(
                    "SELECT * FROM n04_turns WHERE turn_id=?", (request.turn_id,)
                ).fetchone()
                run_state = conn.execute(
                    "SELECT state,start_json FROM n04_runs WHERE experiment_id=?",
                    (self.identifier,),
                ).fetchone()
                idempotency = conn.execute(
                    "SELECT request_digest,response_json FROM idempotency WHERE subject_id=? AND domain_id=? "
                    "AND experiment_id=? AND epoch=? AND action='turns' AND client_key=?",
                    (principal.subject_id, self.ctx.domain_id, self.identifier,
                     self.ctx.epoch, request.idempotency_key),
                ).fetchone()
                pending_jobs = conn.execute(
                    "SELECT count(*) FROM n06_jobs WHERE experiment_id=? AND state IN ('QUEUED','CLAIMED')",
                    (self.identifier,),
                ).fetchone()[0]
                profile = Profile.model_validate_json(run["config_json"])
                candidate = (principal.subject_id == profile.red_subject_id
                        and profile.request.interaction_mode == "INTERACTIVE"
                        and turn_row and job_row and run_state
                        and turn_row["owner"] == principal.subject_id
                        and turn_row["session_owner"] == principal.subject_id
                        and turn_row["quarantined"] == 0
                        and turn_row["phase"] == "RUNNING"
                        and turn_row["integrity"] != "INVALID"
                        and turn_row["state"] == "DISPATCHED"
                        and turn_row["result_json"] is None
                        and job_row["state"] == "CLAIMED"
                        and job_row["owner"] == principal.subject_id
                        and job_row["client_key"] == request.idempotency_key
                        and job_row["session_id"] == turn_row["session_id"]
                        and job_row["body_ref"] is None
                        and job_row["published"] == 0
                        and pending_jobs == 1
                        and run_state["state"] == "RUNNING"
                        and run_state["start_json"])
                if not candidate:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_NOT_ELIGIBLE")
                # From here onward the durable reservation claims an orphaned,
                # dispatched turn. Keep participant admission closed; authenticated
                # contradictions invalidate it, while transient uncertainty remains
                # available for an exact retry.
                self.recovery_admission_blocked = True
                _RECOVERY_VALIDATION_TURN.set(request.turn_id)
                if not internal_row:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_CONTROLLER_RECORD_MISSING")
                if not idempotency:
                    raise DependencyUnavailable("FEEDBACK_RESERVATION_MISSING")
                if internal_row["source_ref"] is None:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_SOURCE_REF_MISSING")
                if internal_row["state"] != "DISPATCHED":
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_CONTROLLER_STATE_INVALID")
                execution_facts = (
                    internal_row["known_execution"], job_row["known_execution"]
                )
                if "UNKNOWN" in execution_facts:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_EXECUTION_UNKNOWN")
                if (execution_facts[0] != "EXECUTED"
                        or execution_facts[1] not in {"NOT_EVALUATED", "EXECUTED"}):
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_EXECUTION_NOT_ESTABLISHED")
                if (internal_row["result_json"] is not None
                        or internal_row["feedback_ref"] is not None):
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_CONTROLLER_STATE_INVALID")
                if anchor is None:
                    raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")
                reservation = json.loads(idempotency["response_json"])
                if (reservation.get("turn_id") != request.turn_id
                        or reservation.get("session_id") != turn_row["session_id"]
                        or reservation.get("turn_index") != turn_row["turn_index"]
                        or reservation.get("state") != "RESERVED"):
                    raise DependencyUnavailable("FEEDBACK_RESERVATION_MISMATCH")
                reservation_payload = self.store.read_payload(turn_row["artifact_id"])
                if (reservation_payload.get("turn_id") != request.turn_id
                        or reservation_payload.get("session_id") != turn_row["session_id"]
                        or reservation_payload.get("turn_index") != turn_row["turn_index"]
                        or reservation_payload.get("payload_ref") != turn_row["payload_ref"]):
                    raise DependencyUnavailable("FEEDBACK_RESERVATION_MISMATCH")
                if turn_row["payload_ref"]:
                    from arena.contracts.api import TurnSubmission
                    original_request = TurnSubmission(
                        epoch=self.ctx.epoch, turn_index=turn_row["turn_index"],
                        payload_ref=turn_row["payload_ref"],
                    )
                else:
                    from arena.contracts.api import TurnSubmission
                    original_request = TurnSubmission(
                        epoch=self.ctx.epoch, turn_index=turn_row["turn_index"],
                        text=reservation_payload.get("text"),
                    )
                route = (
                    f"/v1/experiments/{self.identifier}/sessions/"
                    f"{turn_row['session_id']}/turns"
                )
                expected_idempotency_digest = hmac.new(
                    self.store.master_key,
                    b"arena.v2/idempotency\x00" + canonical_bytes({
                        "request_digest": request_digest(original_request),
                        "route": route,
                    }),
                    hashlib.sha256,
                ).hexdigest()
                if idempotency["request_digest"] != expected_idempotency_digest:
                    raise DependencyUnavailable("FEEDBACK_RESERVATION_IDEMPOTENCY_INVALID")
                turn = {
                    **self.ctx.model_dump(),
                    "session_id": turn_row["session_id"],
                    "turn_id": request.turn_id,
                    "turn_index": turn_row["turn_index"],
                }

            if any(event.event_type == "INTEGRITY_VIOLATION" for event in self.recorder.get_events(self.ctx)):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_PRIOR_INVALIDITY")
            events = self.recorder.get_events(self.ctx)
            previous = "0" * 64
            for sequence, event in enumerate(events, start=1):
                if (event.sequence != sequence or event.previous_digest != previous
                        or (event.domain_id, event.experiment_id, event.epoch,
                            event.public_manifest_digest) != (
                            self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch,
                            turn_row["public_commitment"])):
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_CHAIN_INVALID")
                previous = event_digest(event)

            turn_events = [event for event in events if event.turn_id == request.turn_id]
            def one(event_type, *, outcome="OK"):
                matches = [event for event in turn_events if event.event_type == event_type]
                if len(matches) != 1 or matches[0].outcome_code != outcome:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_SET_INVALID")
                event = matches[0]
                if (event.actor_id != ACTOR
                        or (event.domain_id, event.experiment_id, event.epoch,
                            event.session_id, event.turn_id, event.turn_index) != (
                            self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch,
                            turn["session_id"], turn["turn_id"], turn["turn_index"])):
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_CONTEXT_INVALID")
                return event

            committed_event = one("TURN_COMMITTED")
            dispatch_event = one("DISPATCH_INTENT")
            model_event = one("MODEL_RESULT")
            score_event = one("SCORE_RESULT")
            feedback_event = one("FEEDBACK_AUTHORIZED")
            original_receipt = self.recorder.get_turn_authorization(self.ctx, request.turn_id)
            if internal_row["receipt_json"]:
                broker_receipt = SignedTurnReceipt.model_validate_json(internal_row["receipt_json"])
                if original_receipt is not None and broker_receipt != original_receipt:
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_ORIGINAL_RECEIPT_CONFLICT")
                original_receipt = broker_receipt
            if not (committed_event.sequence < dispatch_event.sequence < model_event.sequence
                    < score_event.sequence < feedback_event.sequence):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_ORDER_INVALID")
            if (len(committed_event.artifact_ciphertext_refs) != 1
                    or len(dispatch_event.artifact_ciphertext_refs) != 1
                    or len(model_event.artifact_ciphertext_refs) != 1
                    or len(score_event.artifact_ciphertext_refs) != 1
                    or len(feedback_event.artifact_ciphertext_refs) != 2):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_ARTIFACT_SET_INVALID")

            source = await self.corpus.resolve(internal_row["source_ref"])
            if turn_row["payload_ref"]:
                original_payload = self.store.read_payload(turn_row["payload_ref"])
                original_text = original_payload["text"]
            else:
                original_text = reservation_payload.get("text")
            if (not isinstance(original_text, str) or source.text != original_text
                    or source.payload_ref != internal_row["source_ref"]):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_SOURCE_MISMATCH")
            provenance = source.provenance.model_dump(mode="json")

            committed_ref = committed_event.artifact_ciphertext_refs[0]
            original_opening = self.vault.get(committed_ref, expected_classification="PRIVATE_PAYLOAD")
            if original_opening != {
                **turn,
                "original_utf8_base64": encode_text(original_text),
                "provenance": provenance,
            }:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_ORIGINAL_OPENING_MISMATCH")

            input_ref = dispatch_event.artifact_ciphertext_refs[0]
            response_ref = feedback_event.artifact_ciphertext_refs[1]
            if feedback_event.artifact_ciphertext_refs[0] != input_ref:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_ARTIFACT_BINDING_MISMATCH")
            input_opening = self.vault.get(input_ref, expected_classification="PRIVATE_PAYLOAD")
            if set(input_opening) != {"kind", "content_base64", "nonce_hex"} or input_opening["kind"] != "INPUT_OPENING":
                raise DependencyUnavailable("FEEDBACK_RECOVERY_INPUT_OPENING_INVALID")
            try:
                input_content = base64.b64decode(input_opening["content_base64"], validate=True)
                input_nonce = bytes.fromhex(input_opening["nonce_hex"])
                input_envelope = json.loads(input_content.decode("utf-8", errors="strict"))
                original_b64 = input_envelope["original_utf8_base64"]
                effective_text = base64.b64decode(input_envelope["effective_utf8_base64"], validate=True).decode("utf-8", errors="strict")
                if (base64.b64decode(original_b64, validate=True).decode("utf-8", errors="strict") != original_text
                        or input_envelope["provenance"] != provenance
                        or {key: input_envelope[key] for key in turn} != turn
                        or input_content != input_bytes(turn, original_text, effective_text, provenance)):
                    raise ValueError("input opening mismatch")
                input_commitment = commitment(input_content, input_nonce)
            except Exception as exc:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_INPUT_OPENING_INVALID") from exc

            model_ref = model_event.artifact_ciphertext_refs[0]
            model_output = self.vault.get(model_ref, expected_classification="PRIVATE_MODEL_OUTPUT")
            try:
                response = TargetResponse.model_validate(model_output)
            except Exception as exc:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_MODEL_RESULT_INVALID") from exc
            if (response.domain_id, response.experiment_id, response.epoch,
                    response.attempt_id, response.session_id, response.turn_index) != (
                    self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch,
                    request.turn_id, turn["session_id"], turn["turn_index"]):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_MODEL_BINDING_INVALID")

            score_ref = score_event.artifact_ciphertext_refs[0]
            score_opening = self.vault.get(score_ref, expected_classification="PRIVATE_MODEL_OUTPUT")
            try:
                observation = ScoreObservation.model_validate(score_opening["observation"])
            except Exception as exc:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_SCORE_RESULT_INVALID") from exc
            if (set(score_opening) != set(turn) | {"observation"}
                    or {key: score_opening[key] for key in turn} != turn
                    or observation.model_output != model_ref
                    or observation.refusal_marker_present != evaluate_refusal_rubric(response.text)["is_refusal"]):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_SCORE_BINDING_INVALID")

            response_opening = self.vault.get(response_ref, expected_classification="PRIVATE_MODEL_OUTPUT")
            if set(response_opening) != {"kind", "content_base64", "nonce_hex", "public_reply_utf8_base64", "result"} or response_opening["kind"] != "PUBLIC_RESPONSE_OPENING":
                raise DependencyUnavailable("FEEDBACK_RECOVERY_RESPONSE_OPENING_INVALID")
            try:
                response_content = base64.b64decode(response_opening["content_base64"], validate=True)
                response_nonce = bytes.fromhex(response_opening["nonce_hex"])
                public_reply_bytes = base64.b64decode(response_opening["public_reply_utf8_base64"], validate=True)
                public_reply = public_reply_bytes.decode("utf-8", errors="strict")
                outcome = AttemptResult.model_validate(response_opening["result"])
                expected_response = response_bytes(turn, public_reply, "COMPLETED")
                if (response_content != expected_response or len(response_nonce) != 32
                        or outcome.model_execution != "EXECUTED"
                        or outcome.integrity != "VALID_WITHIN_PROFILE"
                        or outcome.scoring != "UNCERTAIN"):
                    raise ValueError("response opening mismatch")
                response_commitment = commitment(response_content, response_nonce)
            except Exception as exc:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_RESPONSE_OPENING_INVALID") from exc

            anchor_records = anchor.records(self.ctx)
            anchor_state = verify_anchor_records(
                anchor_records, self.ctx, anchor.public_key, anchor.key_id,
                getattr(anchor, "authority_id", None),
            )
            if (anchor_state["pending"] or anchor_state["terminal"]
                    or anchor_state["event_sequence"] != len(events)):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_ANCHOR_STATE_INVALID")
            anchor.verify_events(self.ctx, events)
            feedback_digest = event_digest(feedback_event)
            committed_anchor_record = anchor_state["committed"].get(
                anchor_operation_id(self.ctx, feedback_event.sequence, feedback_digest)
            )
            if (not committed_anchor_record
                    or committed_anchor_record["event_digest"] != feedback_digest):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_ANCHOR_BINDING_INVALID")

            if original_receipt is not None:
                receipt = original_receipt.receipt
                if (any(getattr(receipt, name) != value for name, value in turn.items())
                        or receipt.event_count != feedback_event.sequence
                        or receipt.prefix_root != feedback_digest
                        or receipt.input_commitment != input_commitment
                        or receipt.public_response_commitment != response_commitment
                        or receipt.signer_key_id != self.recorder.signer_key_id
                        or not verify(turn_message(receipt), original_receipt.signature,
                                      self.recorder_public_key)):
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_ORIGINAL_RECEIPT_INVALID")
                return self._copy_original_feedback(
                    principal, request, original_receipt, outcome, public_reply, input_ref, response_ref,
                )

            recovery_public = pinned_recovery_public()
            private_bytes = recovery_signing_material(recovery_public)

            recovery_operation_id = str(uuid5(
                UUID(request.turn_id), "arena.feedback-reconciliation.v1:" + feedback_digest
            ))
            proof_unsigned = FeedbackReconciliationUnsigned(
                **turn,
                schema_version="arena.feedback-reconciliation.v1",
                feedback_event_sequence=feedback_event.sequence,
                feedback_event_digest=feedback_digest,
                prefix_root=feedback_digest,
                anchor_record_digest=record_digest(committed_anchor_record),
                input_artifact=input_ref,
                response_artifact=response_ref,
                input_commitment=input_commitment,
                response_commitment=response_commitment,
                reservation_id=request.turn_id,
                model_result_digest=event_digest(model_event),
                score_result_digest=event_digest(score_event),
                queue_job_id=request.turn_id,
                recovery_operation_id=recovery_operation_id,
                recovery_authority_id=authority["authority_id"],
                recovery_key_id=authority["key_id"],
            )
            proof = sign_reconciliation(proof_unsigned, private_bytes)
            replay_unsigned = FeedbackReplayUnsigned(
                **turn,
                schema_version="arena.feedback-replay.v1",
                public_reply_base64=response_opening["public_reply_utf8_base64"],
                public_status="COMPLETED",
                response_commitment=response_commitment,
                feedback_reconciliation=proof,
                recovery_authority_id=authority["authority_id"],
                recovery_key_id=authority["key_id"],
            )
            replay = sign_replay(replay_unsigned, private_bytes)
            from arena.contracts.jsonwire import load_wire
            replay_bytes = canonical_bytes(replay) + b"\n"
            if (not verify_reconciliation(proof, recovery_public, authority["authority_id"], authority["key_id"])
                    or not verify_replay(load_wire(FeedbackReplay, replay_bytes), recovery_public,
                                         authority["authority_id"], authority["key_id"])):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_SIGNATURE_SELF_CHECK_FAILED")

            # Commit the public proof and encrypted exact response before settling
            # projections. A lost return can complete this same operation on retry.
            with self.store.transaction() as conn:
                old = conn.execute(
                    "SELECT owner,client_key,replay_ref FROM n04_recoveries "
                    "WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                    (self.ctx.domain_id, self.identifier, self.ctx.epoch, request.turn_id),
                ).fetchone()
                if old:
                    if old["owner"] == principal.subject_id and old["client_key"] == request.idempotency_key:
                        raise DependencyUnavailable("FEEDBACK_RECOVERY_STATE_CHANGED")
                    raise DependencyUnavailable("FEEDBACK_REPLAY_UNAVAILABLE")
                current = conn.execute(
                    "SELECT e.phase,e.integrity,t.state,t.result_json,j.state,j.body_ref,j.published,"
                    "j.known_execution AS job_execution,n.known_execution AS internal_execution "
                    "FROM experiments e JOIN turns t ON t.experiment_id=e.id "
                    "JOIN n06_jobs j ON j.turn_id=t.id JOIN n04_turns n ON n.turn_id=t.id WHERE e.id=? AND t.id=?",
                    (self.identifier, request.turn_id),
                ).fetchone()
                if (not current or tuple(current)[:7] != (
                    "RUNNING", turn_row["integrity"], "DISPATCHED", None,
                    "CLAIMED", None, 0,
                ) or current["job_execution"] not in {"NOT_EVALUATED", "EXECUTED"}
                        or current["internal_execution"] != "EXECUTED"):
                    raise DependencyUnavailable("FEEDBACK_RECOVERY_STATE_CHANGED")
                run_for_payload = conn.execute(
                    "SELECT * FROM experiments WHERE id=?", (self.identifier,)
                ).fetchone()
                replay_ref = self.store.put_payload(
                    conn, run_for_payload, "n04-feedback-replay",
                    {"body_base64": base64.b64encode(replay_bytes).decode("ascii")},
                )
                conn.execute(
                    "INSERT INTO n04_recoveries VALUES(?,?,?,?,?,?,?,?,?)",
                    (self.ctx.domain_id, self.identifier, self.ctx.epoch, request.turn_id,
                     principal.subject_id, request.idempotency_key, recovery_operation_id,
                     proof.model_dump_json(), replay_ref),
                )
            await self._settle_recovered_feedback(replay)
            return replay_bytes

    async def _settle_recovered_feedback(self, replay: FeedbackReplay) -> None:
        """Settle verified execution without inventing an arena.v2 receipt or event."""
        proof = replay.feedback_reconciliation
        events = self.recorder.get_events(self.ctx)
        if any(event.event_type == "INTEGRITY_VIOLATION" for event in events):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_PRIOR_INVALIDITY")
        anchor = self.recorder.anchor
        if anchor is None:
            raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")
        anchor.verify_events(self.ctx, events)
        state = verify_anchor_records(anchor.records(self.ctx), self.ctx, anchor.public_key,
                                      anchor.key_id, anchor.authority_id)
        committed = state["committed"].get(anchor_operation_id(
            self.ctx, proof.feedback_event_sequence, proof.feedback_event_digest))
        if (not committed or record_digest(committed) != proof.anchor_record_digest
                or proof.feedback_event_sequence > len(events)):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_ANCHOR_BINDING_INVALID")
        feedback = events[proof.feedback_event_sequence - 1]
        if (feedback.event_type != "FEEDBACK_AUTHORIZED"
                or event_digest(feedback) != proof.feedback_event_digest
                or (feedback.session_id, feedback.turn_id, feedback.turn_index) != (
                    replay.session_id, replay.turn_id, replay.turn_index)
                or feedback.artifact_ciphertext_refs != (proof.input_artifact, proof.response_artifact)):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_CONTEXT_INVALID")
        turn_events = [event for event in events if event.turn_id == replay.turn_id]
        models = [event for event in turn_events if event.event_type == "MODEL_RESULT"]
        scores = [event for event in turn_events if event.event_type == "SCORE_RESULT"]
        if (len(models) != 1 or models[0].outcome_code != "OK"
                or event_digest(models[0]) != proof.model_result_digest
                or len(scores) != 1 or scores[0].outcome_code != "OK"
                or event_digest(scores[0]) != proof.score_result_digest
                or not models[0].sequence < scores[0].sequence < feedback.sequence
                or any(event.sequence > feedback.sequence for event in turn_events)):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_SET_INVALID")
        input_opening = self.vault.get(proof.input_artifact, expected_classification="PRIVATE_PAYLOAD")
        response_opening = self.vault.get(proof.response_artifact, expected_classification="PRIVATE_MODEL_OUTPUT")
        try:
            if (commitment(base64.b64decode(input_opening["content_base64"], validate=True),
                           bytes.fromhex(input_opening["nonce_hex"])) != proof.input_commitment
                    or commitment(base64.b64decode(response_opening["content_base64"], validate=True),
                                  bytes.fromhex(response_opening["nonce_hex"])) != proof.response_commitment
                    or response_opening["public_reply_utf8_base64"] != replay.public_reply_base64):
                raise ValueError("stored replay opening mismatch")
            outcome = AttemptResult.model_validate(response_opening["result"])
            if outcome.model_execution != "EXECUTED" or outcome.integrity != "VALID_WITHIN_PROFILE":
                raise ValueError("stored replay execution mismatch")
        except Exception as exc:
            raise DependencyUnavailable("FEEDBACK_RECOVERY_RESPONSE_OPENING_INVALID") from exc
        result_json = outcome.model_dump_json()
        with self.store.transaction() as conn:
            row = conn.execute(
                "SELECT e.phase,e.integrity,e.config_json,t.state AS turn_state,t.result_json AS turn_result,"
                "t.session_id,n.state AS internal_state,n.known_execution,n.result_json AS internal_result,"
                "n.feedback_ref,n.receipt_json,j.state AS job_state,j.body_ref AS job_body_ref,j.published,"
                "j.known_execution AS job_execution,s.quarantined "
                "FROM experiments e JOIN turns t ON t.experiment_id=e.id "
                "JOIN n04_turns n ON n.turn_id=t.id JOIN n06_jobs j ON j.turn_id=t.id "
                "JOIN sessions s ON s.id=t.session_id WHERE e.id=? AND t.id=?",
                (self.identifier, replay.turn_id),
            ).fetchone()
            if not row or row["session_id"] != replay.session_id:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_SETTLEMENT_BINDING_INVALID")
            if row["integrity"] == "INVALID" or row["phase"] == "INVALID":
                raise DependencyUnavailable("FEEDBACK_RECOVERY_PRIOR_INVALIDITY")
            settled = (
                row["phase"] in {"RUNNING", "SCORED", "CLOSED", "RELEASED"}
                and row["turn_state"] == "COMPLETED"
                and row["internal_state"] == "RECOVERED"
                and row["known_execution"] == "EXECUTED"
                and row["internal_result"] == result_json
                and row["turn_result"] == result_json
                and row["feedback_ref"] == proof.response_artifact.model_dump_json()
                and row["receipt_json"] is None
                and row["job_state"] == "FAILED"
                and row["job_body_ref"] is None
                and row["job_execution"] == "EXECUTED"
                and row["quarantined"] == 1
            )
            if settled:
                return
            if (row["phase"] != "RUNNING"
                    or row["turn_state"] != "DISPATCHED" or row["turn_result"] is not None
                    or row["internal_state"] != "DISPATCHED"
                    or row["known_execution"] != "EXECUTED"
                    or row["internal_result"] is not None or row["feedback_ref"] is not None
                    or row["receipt_json"] is not None or row["job_state"] != "CLAIMED"
                    or row["job_body_ref"] is not None or row["published"] != 0
                    or row["job_execution"] not in {"NOT_EVALUATED", "EXECUTED"}):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_SETTLEMENT_STATE_INVALID")
            conn.execute(
                "UPDATE n06_jobs SET state='FAILED',known_execution='EXECUTED' WHERE turn_id=?",
                (replay.turn_id,),
            )
            conn.execute(
                "UPDATE turns SET state='COMPLETED',result_json=? WHERE id=?",
                (result_json, replay.turn_id),
            )
            conn.execute(
                "UPDATE n04_turns SET state='RECOVERED',known_execution='EXECUTED',"
                "result_json=?,feedback_ref=?,receipt_json=NULL WHERE turn_id=?",
                (result_json, proof.response_artifact.model_dump_json(), replay.turn_id),
            )
            conn.execute("UPDATE sessions SET quarantined=1 WHERE id=?", (replay.session_id,))

    def _verify_original_copy(self, copied, turn_id, *, restore_missing_authorization=False):
        body = self._read_recovery_payload(copied["body_ref"], "n06-feedback")
        if len(body) != self._recovery_feedback_policy().body_bytes:
            raise DependencyUnavailable("FEEDBACK_REPLAY_RECORD_INVALID")
        feedback = TurnFeedback.model_validate_json(body)
        signed = SignedTurnReceipt.model_validate_json(copied["receipt_json"])
        with closing(self.store.connect()) as conn:
            row = conn.execute(
                "SELECT e.phase,e.integrity,n.state,n.receipt_json,n.feedback_ref,n.result_json "
                "FROM experiments e JOIN turns t ON t.experiment_id=e.id "
                "JOIN n04_turns n ON n.turn_id=t.id WHERE e.id=? AND t.id=?",
                (self.identifier, turn_id),
            ).fetchone()
        recorder_authorization = self.recorder.get_turn_authorization(self.ctx, turn_id)
        if (not row or row["integrity"] == "INVALID" or row["phase"] == "INVALID"
                or row["state"] != "DONE" or feedback.turn_id != turn_id
                or feedback.feedback_receipt != signed
                or SignedTurnReceipt.model_validate_json(row["receipt_json"]) != signed
                or (recorder_authorization != signed
                    and not (restore_missing_authorization and recorder_authorization is None))
                or signed.receipt.signer_key_id != self.recorder.signer_key_id
                or not verify(turn_message(signed.receipt), signed.signature, self.recorder_public_key)):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_ORIGINAL_RECEIPT_INVALID")
        opening = self.vault.get(ArtifactRef.model_validate_json(row["feedback_ref"]))
        bound = {**self.ctx.model_dump(), "session_id": feedback.session_id,
                 "turn_id": turn_id, "turn_index": feedback.turn_index}
        expected = response_bytes(bound, feedback.public_reply, "COMPLETED")
        if (base64.b64decode(opening["content_base64"], validate=True) != expected
                or commitment(expected, bytes.fromhex(opening["nonce_hex"]))
                != signed.receipt.public_response_commitment
                or AttemptResult.model_validate(opening["result"]).model_dump_json() != row["result_json"]):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_RESPONSE_OPENING_INVALID")
        events = self.recorder.get_events(self.ctx)
        if self.recorder.anchor is None:
            raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")
        self.recorder.anchor.verify_events(self.ctx, events)
        if (any(event.event_type == "INTEGRITY_VIOLATION" for event in events)
                or signed.receipt.event_count > len(events)
                or event_digest(events[signed.receipt.event_count - 1]) != signed.receipt.prefix_root):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_CONTEXT_INVALID")
        event = events[signed.receipt.event_count - 1]
        if (event.event_type != "FEEDBACK_AUTHORIZED" or event.outcome_code != "OK"
                or (event.session_id, event.turn_id, event.turn_index) != (
                    feedback.session_id, feedback.turn_id, feedback.turn_index)
                or len(event.artifact_ciphertext_refs) != 2
                or event.artifact_ciphertext_refs[1] != ArtifactRef.model_validate_json(row["feedback_ref"])):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_EVENT_CONTEXT_INVALID")
        input_opening = self.vault.get(event.artifact_ciphertext_refs[0], expected_classification="PRIVATE_PAYLOAD")
        if commitment(base64.b64decode(input_opening["content_base64"], validate=True),
                      bytes.fromhex(input_opening["nonce_hex"])) != signed.receipt.input_commitment:
            raise DependencyUnavailable("FEEDBACK_RECOVERY_INPUT_OPENING_INVALID")
        if recorder_authorization is None:
            self.recorder.copy_turn_authorization(
                signed, ACTOR, event.artifact_ciphertext_refs[0],
                event.artifact_ciphertext_refs[1],
            )
            if self.recorder.get_turn_authorization(self.ctx, turn_id) != signed:
                raise DependencyUnavailable("FEEDBACK_RECOVERY_ORIGINAL_RECEIPT_INVALID")
        return body

    def _recovery_feedback_policy(self):
        from arena.execution.policy import SignedPolicy, validate_policy
        with closing(self.store.connect()) as conn:
            policy_row = conn.execute("SELECT signed_json FROM n06_policies WHERE experiment_id=?",
                                      (self.identifier,)).fetchone()
        if not policy_row:
            raise DependencyUnavailable("FEEDBACK_RECOVERY_POLICY_MISSING")
        signed_policy = SignedPolicy.model_validate_json(policy_row[0])
        trust = self.transport_admission.trust if self.transport_admission is not None else None
        return validate_policy(
            signed_policy, trust.feedback_public_key if trust else self.recorder_public_key,
            trust.feedback_key_id if trust else self.recorder.signer_key_id,
        )

    def _copy_original_feedback(self, principal, request, signed, outcome, reply, input_ref, response_ref):
        """Copy an existing authenticated signature; never sign an arena.v2 receipt."""
        from arena.execution.policy import padded_json
        policy = self._recovery_feedback_policy()
        body = padded_json(TurnFeedback(
            turn_id=request.turn_id, session_id=signed.receipt.session_id,
            turn_index=signed.receipt.turn_index, public_reply=reply, public_status="COMPLETED",
            feedback_receipt=signed, padding="",
        ).model_dump(), policy.body_bytes)
        self.recorder.copy_turn_authorization(signed, ACTOR, input_ref, response_ref)
        with self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM experiments WHERE id=?", (self.identifier,)).fetchone()
            current = conn.execute(
                "SELECT t.state,t.result_json,j.state,j.body_ref,j.published,j.owner,j.client_key,j.known_execution "
                "FROM turns t JOIN n06_jobs j ON j.turn_id=t.id WHERE t.id=?", (request.turn_id,),
            ).fetchone()
            if (row["phase"] != "RUNNING" or row["integrity"] == "INVALID" or not current
                    or tuple(current)[:7] != ("DISPATCHED", None, "CLAIMED", None, 0,
                                             principal.subject_id, request.idempotency_key)
                    or current["known_execution"] not in {"NOT_EVALUATED", "EXECUTED"}):
                raise DependencyUnavailable("FEEDBACK_RECOVERY_STATE_CHANGED")
            ref = self.store.put_payload(conn, row, "n06-feedback",
                                        {"body_base64": base64.b64encode(body).decode("ascii")})
            conn.execute("INSERT INTO n04_receipt_copies VALUES(?,?,?,?,?,?,?,?)", (
                self.ctx.domain_id, self.identifier, self.ctx.epoch, request.turn_id,
                principal.subject_id, request.idempotency_key, signed.model_dump_json(), ref))
            conn.execute("UPDATE turns SET state='COMPLETED',result_json=? WHERE id=?",
                         (outcome.model_dump_json(), request.turn_id))
            conn.execute("UPDATE n04_turns SET state='DONE',known_execution='EXECUTED',result_json=?,"
                         "feedback_ref=?,receipt_json=? WHERE turn_id=?", (
                             outcome.model_dump_json(), response_ref.model_dump_json(),
                             signed.model_dump_json(), request.turn_id))
            conn.execute("UPDATE n06_jobs SET state='AUTHORIZED',known_execution='EXECUTED',body_ref=? WHERE turn_id=?",
                         (ref, request.turn_id))
            conn.execute("UPDATE sessions SET quarantined=1 WHERE id=?", (signed.receipt.session_id,))
        return body

    async def close(self, principal):
        self.broker._role(principal, "operator")
        row = self._row(principal)
        pending = None
        with self.store.transaction() as conn:
            old = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (self.identifier,)
            ).fetchone()
            if old and old["state"] in {"CLOSED", "RELEASED"}:
                from arena.contracts.evidence import SignedCheckpoint

                return SignedCheckpoint.model_validate_json(old["close_json"])
            if old and old["state"] == "CLOSING" and old["close_json"]:
                from arena.contracts.evidence import SignedCheckpoint

                pending = SignedCheckpoint.model_validate_json(old["close_json"])
            if not pending and (
                row["phase"] not in {"RUNNING", "SCORED", "INVALID"}
                or not old
                or not old["start_json"]
            ):
                raise DependencyUnavailable("CLOSE_PENDING_START_OR_PHASE")
            if conn.execute(
                "SELECT 1 FROM turns WHERE experiment_id=? AND state IN ('RESERVED','DISPATCHED')",
                (self.identifier,),
            ).fetchone():
                raise DependencyUnavailable("CLOSE_PENDING_UNSETTLED_TURNS")
            if "n06_jobs" in {row[0] for row in conn.execute(
                    "SELECT name FROM sqlite_master WHERE type='table'")} and conn.execute(
                    "SELECT 1 FROM n06_jobs WHERE experiment_id=? AND state IN ('QUEUED','CLAIMED') LIMIT 1",
                    (self.identifier,),
            ).fetchone():
                raise DependencyUnavailable("CLOSE_PENDING_NONQUIESCENT_QUEUE")
            sessions = [
                item[0]
                for item in conn.execute(
                    "SELECT id FROM sessions WHERE experiment_id=?", (self.identifier,)
                )
            ]
            if not pending:
                conn.execute(
                    "UPDATE n04_runs SET state='CLOSING' WHERE experiment_id=?",
                    (self.identifier,),
                )
                conn.execute(
                    "UPDATE experiments SET phase=? WHERE id=?",
                    (
                        "INVALID" if row["integrity"] == "INVALID" else "SCORED",
                        self.identifier,
                    ),
                )
        invalid = row["integrity"] == "INVALID"
        if pending is not None:
            # Exact witness-close retry is safe; never repeat reset, events or inference.
            return await self._finish_close(pending, invalid)
        try:
            terminal_close = getattr(self.runtime, "close_models", None)
            if terminal_close is not None:
                try:
                    await terminal_close(tuple(sessions))
                except Exception:
                    invalid = True
                    self._invalidate()
                    await self._event("INTEGRITY_VIOLATION", "FAILED")
            else:
                for session in sessions:
                    try:
                        await self.runtime.model.reset(session)
                    except Exception:
                        invalid = True
                        self._invalidate()
                        await self._event("INTEGRITY_VIOLATION", "FAILED")
            await self._event(
                "CLOSE_REQUESTED",
                "INVALID" if invalid else "OK",
                operation="close-request",
            )
            await self._event(
                "CLOSED", "INVALID" if invalid else "OK", operation="closed"
            )
            if self.recorder.anchor is not None:
                self.recorder.anchor.verify_events(self.ctx, self.recorder.get_events(self.ctx))
            checkpoint = await self.recorder.close(self.ctx)
            with self.store.transaction() as conn:
                # Retain the exact checkpoint before contacting the separate authority.
                conn.execute(
                    "UPDATE n04_runs SET state='CLOSING',close_json=? WHERE experiment_id=?",
                    (checkpoint.model_dump_json(), self.identifier),
                )
        except Exception:
            invalid = True
            self._invalidate()
            # This is the only unanchored append permitted by the recovery
            # contract. It closes an already quiescent INVALID run for forensic
            # evidence; it cannot produce a valid terminal anchor, release, or
            # ordinary export. If CLOSED was already durable, preserve its bytes.
            events = self.recorder.get_events(self.ctx)
            if not events or events[-1].event_type != "CLOSED":
                proposal = EventProposal(
                    **self.ctx.model_dump(), session_id=None, turn_id=None,
                    turn_index=None, event_type="CLOSED", outcome_code="INVALID",
                    artifact_ciphertext_refs=(), duration_us=0,
                )
                operation_id = str(uuid5(UUID(self.identifier), "closed-invalid-unanchored"))
                await self.recorder.append_invalid_close_once(proposal, ACTOR, operation_id)
            checkpoint = await self.recorder.close(self.ctx)
            with self.store.transaction() as conn:
                conn.execute(
                    "UPDATE n04_runs SET state='CLOSING',close_json=? WHERE experiment_id=?",
                    (checkpoint.model_dump_json(), self.identifier),
                )
        return await self._finish_close(checkpoint, invalid)

    async def _finish_close(self, checkpoint, invalid):
        # Lost close ACK leaves admission closed and export/release unavailable.
        # Only this exact cryptographically bound, idempotent authority operation
        # may be retried. It is never an inference retry or a new checkpoint.
        witness = await self.witness.close_checkpoint(checkpoint)
        if not verify_witness_close(
            witness,
            self.witness_public_key,
            checkpoint.checkpoint,
            self.ctx,
            self.witness.witness_key_id,
        ):
            self._invalidate()
            raise DependencyUnavailable("WITNESS_CLOSE_ACK_INVALID")
        if self.recorder.anchor is not None:
            try:
                self.recorder.anchor.terminal_close(
                    checkpoint,
                    witness,
                    "INVALID" if invalid else "VALID_WITHIN_PROFILE",
                )
            except Exception:
                # An INVALID witness close may be retained for forensic export
                # with an explicit missing-anchor gap. A valid close remains
                # CLOSING/PENDING until the exact terminal ACK is available.
                if not invalid:
                    raise DependencyUnavailable("ANCHOR_TERMINAL_ACK_PENDING") from None
        with self.store.transaction() as conn:
            current = conn.execute(
                "SELECT integrity FROM experiments WHERE id=?", (self.identifier,)
            ).fetchone()[0]
            if current == "INVALID" and not invalid:
                raise DependencyUnavailable("CLOSE_CANNOT_CLEAR_NEW_INVALIDITY")
            conn.execute(
                "UPDATE experiments SET phase='CLOSED',integrity=? WHERE id=?",
                ("INVALID" if invalid else "VALID_WITHIN_PROFILE", self.identifier),
            )
            conn.execute(
                "UPDATE n04_runs SET state='CLOSED',witness_json=? WHERE experiment_id=?",
                (witness.model_dump_json(), self.identifier),
            )
        return checkpoint

    def release(self, principal):
        self.broker._role(principal, "operator")
        row_snapshot = self._row(principal)
        with closing(self.store.connect()) as conn:
            run = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (self.identifier,)
            ).fetchone()
            current = conn.execute(
                "SELECT phase,integrity FROM experiments WHERE id=?", (self.identifier,)
            ).fetchone()
            if (not run or run["state"] not in {"CLOSED", "RELEASED"}
                    or not run["witness_json"]):
                raise DependencyUnavailable("RELEASE_REQUIRES_AUTHORITATIVE_CLOSE")
            if (current["integrity"] != "VALID_WITHIN_PROFILE"
                    or current["phase"] not in {"CLOSED", "RELEASED"}):
                raise DependencyUnavailable("RELEASE_REQUIRES_VALID_INTEGRITY")
            run_snapshot = dict(run)
            phase_snapshot = current["phase"]
            recovered_snapshot = list(conn.execute(
                "SELECT proof_json FROM n04_recoveries WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY turn_id",
                (self.ctx.domain_id, self.identifier, self.ctx.epoch),
            ))
            recovered_bytes = [item[0] for item in recovered_snapshot]
            original_snapshot = [item[0] for item in conn.execute(
                "SELECT receipt_json FROM n04_turns n JOIN turns t ON n.turn_id=t.id "
                "WHERE t.experiment_id=? AND n.state='DONE' ORDER BY t.turn_index", (self.identifier,),
            )]
        if self.recorder.anchor is not None:
            checkpoint = SignedCheckpoint.model_validate_json(run_snapshot["close_json"])
            witness = SignedWitnessClose.model_validate_json(run_snapshot["witness_json"])
            self.recorder.anchor.verify_events(self.ctx, self.recorder.get_events(self.ctx))
            self.recorder.anchor.verify_terminal(
                self.ctx, checkpoint, witness, "VALID_WITHIN_PROFILE"
            )
        if recovered_snapshot:
            # The versioned proof cannot acquire release authority from a database
            # flag. Recheck signatures, private openings, semantics and all anchors.
            try:
                with tempfile.TemporaryDirectory(prefix="recovery-release-", dir=self.vault.root.parent) as directory:
                    self._export_reconciled(
                        Path(directory) / "verified.zip", row_snapshot, run_snapshot,
                        tuple(SignedTurnReceipt.model_validate_json(value) for value in original_snapshot),
                        recovered_snapshot,
                    )
            except Exception as exc:
                raise DependencyUnavailable("RELEASE_RECOVERY_EVIDENCE_INVALID") from exc
        with self.store.transaction() as conn:
            run = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (self.identifier,)
            ).fetchone()
            if (not run or run["state"] not in {"CLOSED", "RELEASED"}
                    or not run["witness_json"] or run["close_json"] != run_snapshot["close_json"]
                    or run["witness_json"] != run_snapshot["witness_json"]):
                raise DependencyUnavailable("RELEASE_REQUIRES_AUTHORITATIVE_CLOSE")
            current = conn.execute("SELECT phase,integrity FROM experiments WHERE id=?", (self.identifier,)).fetchone()
            if (current["integrity"] != "VALID_WITHIN_PROFILE"
                    or current["phase"] not in {"CLOSED", "RELEASED"}
                    or current["phase"] != phase_snapshot):
                raise DependencyUnavailable("RELEASE_REQUIRES_VALID_INTEGRITY")
            if (recovered_bytes != [item[0] for item in conn.execute(
                    "SELECT proof_json FROM n04_recoveries WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY turn_id",
                    (self.ctx.domain_id, self.identifier, self.ctx.epoch))]
                    or original_snapshot != [item[0] for item in conn.execute(
                        "SELECT receipt_json FROM n04_turns n JOIN turns t ON n.turn_id=t.id "
                        "WHERE t.experiment_id=? AND n.state='DONE' ORDER BY t.turn_index", (self.identifier,))]):
                raise DependencyUnavailable("RELEASE_RECOVERY_EVIDENCE_CHANGED")
            if run["release_id"]:
                return run["release_id"]
            identifier = str(uuid4())
            conn.execute(
                "UPDATE n04_runs SET state='RELEASED',release_id=? WHERE experiment_id=?",
                (identifier, self.identifier),
            )
            conn.execute(
                "UPDATE experiments SET phase='RELEASED' WHERE id=?", (self.identifier,)
            )
            return identifier

    def export(self, principal, path):
        self.broker._role(principal, "auditor")
        row = self._row(principal)
        if row["phase"] not in {"CLOSED", "RELEASED"}:
            raise BrokerError("WRONG_PHASE")
        if row["integrity"] != "VALID_WITHIN_PROFILE":
            raise DependencyUnavailable("ORDINARY_EXPORT_REQUIRES_VALID_INTEGRITY")
        from arena.contracts.evidence import SignedCheckpoint, SignedWitnessClose

        with closing(self.store.connect()) as conn:
            run = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (self.identifier,)
            ).fetchone()
            receipts = tuple(
                SignedTurnReceipt.model_validate_json(item[0])
                for item in conn.execute(
                    "SELECT receipt_json FROM n04_turns n JOIN turns t ON n.turn_id=t.id WHERE t.experiment_id=? AND n.state='DONE' ORDER BY t.turn_index",
                    (self.identifier,),
                )
            )
            recoveries = list(conn.execute(
                "SELECT proof_json FROM n04_recoveries WHERE domain_id=? AND experiment_id=? AND epoch=? ORDER BY turn_id",
                (self.ctx.domain_id, self.identifier, self.ctx.epoch),
            ))
        if recoveries:
            return self._export_reconciled(path, row, run, receipts, recoveries)
        checkpoint = SignedCheckpoint.model_validate_json(run["close_json"])
        witness = SignedWitnessClose.model_validate_json(run["witness_json"])
        if self.recorder.anchor is not None:
            self.recorder.anchor.verify_events(self.ctx, self.recorder.get_events(self.ctx))
            self.recorder.anchor.verify_terminal(
                self.ctx, checkpoint, witness, "VALID_WITHIN_PROFILE"
            )
        start = StartResponse.model_validate_json(
            run["start_json"]
        ).witness_start_receipt
        events = self.recorder.get_events(self.ctx)
        # Local preflight is not the independent CLI verification performed afterward.
        invalid = validate_run_semantics(
            events,
            start.receipt,
            receipts,
            Profile.model_validate_json(row["config_json"]).request.defense_mode,
            ACTOR,
            self.recorder_public_key,
            self.recorder.signer_key_id,
        )
        if invalid:
            raise DependencyUnavailable("ORDINARY_EXPORT_REJECTS_INVALID_SEMANTICS")
        return export_evidence_bundle(
            path,
            checkpoint,
            witness,
            events,
            self.vault.export_ciphertexts(checkpoint.checkpoint.required_artifacts),
            signed_witness_start=start,
            turn_receipts=receipts,
        )

    def _export_reconciled(self, path, row, run, receipts, recoveries):
        from arena.verifier.reconciled_bundle import (
            ReconciledVerificationInputs, export_reconciled_evidence_bundle,
        )
        if self.recorder.anchor is None or not self.recovery_authority:
            raise DependencyUnavailable("RECONCILED_EXPORT_AUTHORITY_UNAVAILABLE")
        checkpoint = SignedCheckpoint.model_validate_json(run["close_json"])
        witness = SignedWitnessClose.model_validate_json(run["witness_json"])
        start = StartResponse.model_validate_json(run["start_json"]).witness_start_receipt
        anchor = self.recorder.anchor
        events = self.recorder.get_events(self.ctx)
        anchor.verify_events(self.ctx, events)
        anchor.verify_terminal(self.ctx, checkpoint, witness, "VALID_WITHIN_PROFILE")
        records = anchor.records(self.ctx)
        anchor_bytes = b"".join(canonical_bytes(record) + b"\n" for record in records)
        replay_keys = self.vault.private_replay_keys(checkpoint.checkpoint.required_artifacts)
        verification = ReconciledVerificationInputs(
            expected_context=self.ctx, expected_manifest_digest=row["public_commitment"],
            recorder_key=self.recorder_public_key, recorder_key_id=self.recorder.signer_key_id,
            witness_key=self.witness_public_key, witness_key_id=self.witness.witness_key_id,
            anchor_key=anchor.public_key, anchor_authority_id=anchor.authority_id, anchor_key_id=anchor.key_id,
            recovery_key=self.recovery_authority["public_key_bytes"],
            recovery_authority_id=self.recovery_authority["authority_id"],
            recovery_key_id=self.recovery_authority["key_id"],
            artifact_keys={identifier: bytes.fromhex(value["key"]) for identifier, value in replay_keys.items()},
            artifact_classifications={identifier: value["classification"] for identifier, value in replay_keys.items()},
            expected_defense_mode=Profile.model_validate_json(row["config_json"]).request.defense_mode,
            expected_broker_actor=ACTOR,
            transport_trust=self.transport_admission.trust if self.transport_admission is not None else None,
            require_transport_profile=self.transport_admission is not None,
        )
        members = {
            "checkpoint.json": run["close_json"].encode("utf-8"),
            "witness_start.json": start.model_dump_json().encode("utf-8"),
            "witness_close.json": run["witness_json"].encode("utf-8"),
            "events.jsonl": self.recorder.get_event_bytes(self.ctx),
            "turn_receipts.jsonl": b"".join(receipt.model_dump_json().encode() + b"\n" for receipt in receipts),
            "reconciliation_receipts.jsonl": b"".join(value["proof_json"].encode() + b"\n" for value in recoveries),
        }
        for identifier, data in self.vault.export_ciphertexts(checkpoint.checkpoint.required_artifacts).items():
            members[f"artifacts/{identifier}.bin"] = data
        return export_reconciled_evidence_bundle(
            path, members, anchor_records_bytes=anchor_bytes, verification=verification,
        )

    def export_invalid_evidence(self, principal, path, authority, private_key):
        """Auditor-only ciphertext package; it cannot change INVALID or release state."""
        self.broker._role(principal, "auditor")
        row = self._row(principal)
        if row["phase"] != "CLOSED" or row["integrity"] != "INVALID":
            raise DependencyUnavailable("INVALID_EXPORT_REQUIRES_CLOSED_INVALID_RUN")
        if private_key.public_key().public_bytes_raw() != authority["public_key_bytes"]:
            raise DependencyUnavailable("INVALID_EXPORT_AUTHORITY_MISMATCH")
        with closing(self.store.connect()) as conn:
            run = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=?", (self.identifier,)
            ).fetchone()
            if not run or run["state"] != "CLOSED" or not run["close_json"] or not run["witness_json"] or not run["start_json"]:
                raise DependencyUnavailable("INVALID_EXPORT_REQUIRES_DURABLE_WITNESS_CLOSE")
            receipt_rows = list(conn.execute(
                "SELECT n.turn_id,n.state,n.known_execution,n.receipt_json,n.feedback_ref,n.result_json,"
                "t.session_id,t.turn_index,j.body_ref "
                "FROM n04_turns n JOIN turns t ON t.id=n.turn_id "
                "LEFT JOIN n06_jobs j ON j.turn_id=n.turn_id WHERE t.experiment_id=? ORDER BY t.turn_index,n.turn_id",
                (self.identifier,),
            ))
            recovery_rows = list(conn.execute(
                "SELECT turn_id,proof_json FROM n04_recoveries WHERE domain_id=? AND experiment_id=? AND epoch=? "
                "ORDER BY turn_id",
                (self.ctx.domain_id, self.identifier, self.ctx.epoch),
            ))
        checkpoint = SignedCheckpoint.model_validate_json(run["close_json"])
        witness = SignedWitnessClose.model_validate_json(run["witness_json"])
        start = StartResponse.model_validate_json(run["start_json"]).witness_start_receipt
        if (not verify_checkpoint(checkpoint, self.recorder_public_key, self.ctx,
                                  row["public_commitment"], self.recorder.signer_key_id)
                or not verify_witness_close(witness, self.witness_public_key,
                                            checkpoint.checkpoint, self.ctx,
                                            self.witness.witness_key_id)
                or start.receipt.witness_key_id != self.witness.witness_key_id
                or not verify(witness_message(start.receipt), start.signature, self.witness_public_key)):
            raise DependencyUnavailable("INVALID_EXPORT_SIGNED_CLOSE_INVALID")

        events = self.recorder.get_events(self.ctx)
        try:
            validate_chain(tuple(events), checkpoint.checkpoint)
        except Exception:
            # The authenticated envelope records this structural gap; it never
            # upgrades the run or claims that the chain is valid.
            add_chain_gap = True
        else:
            add_chain_gap = False
        members = {
            "checkpoint.json": run["close_json"].encode("utf-8"),
            "witness_start.json": start.model_dump_json().encode("utf-8"),
            "witness_close.json": run["witness_json"].encode("utf-8"),
            "events.jsonl": self.recorder.get_event_bytes(self.ctx),
        }
        if recovery_rows:
            members["feedback-reconciliations.jsonl"] = (
                "\n".join(item["proof_json"] for item in recovery_rows) + "\n"
            ).encode("utf-8")
        signed_receipts = [
            value["receipt_json"] for value in receipt_rows if value["receipt_json"]
        ]
        members["turn_receipts.jsonl"] = ("\n".join(signed_receipts) + ("\n" if signed_receipts else "")).encode("utf-8")

        gaps = []
        feedback_events = [event for event in events if event.event_type == "FEEDBACK_AUTHORIZED"]
        event_by_turn = {}
        for event in feedback_events:
            event_by_turn.setdefault(event.turn_id, []).append(event)
        receipt_map = {value["turn_id"]: value for value in receipt_rows if value["receipt_json"]}
        rows = {value["turn_id"]: value for value in receipt_rows}

        def add_gap(code, event=None, turn_id=None, execution="NOT_ESTABLISHED", related=()):
            gap = {"gap_code": code, "related_members": sorted(set(related)),
                   "known_execution_status": execution}
            if event is not None:
                gap["event_sequence"] = event.sequence
                gap["event_digest"] = event_digest(event)
            if turn_id is not None:
                gap["turn_id"] = turn_id
            gaps.append(gap)

        def event_execution(turn_id):
            related = [item for item in events if item.turn_id == turn_id]
            model_events = [item for item in related if item.event_type == "MODEL_RESULT"]
            if len(model_events) == 1 and model_events[0].outcome_code == "OK":
                return "EXECUTED"
            if any(item.outcome_code == "UNKNOWN" for item in model_events):
                return "UNKNOWN"
            return "NOT_ESTABLISHED"

        committed_by_turn = {}
        for committed in (item for item in events if item.event_type == "TURN_COMMITTED"):
            committed_by_turn.setdefault(committed.turn_id, []).append(committed)
        for turn_id, committed_events in committed_by_turn.items():
            committed = committed_events[0]
            turn = rows.get(turn_id)
            execution = event_execution(turn_id)
            for duplicate in committed_events[1:]:
                add_gap("TURN_COMMIT_DUPLICATE", duplicate, turn_id, execution,
                        ("events.jsonl",))
            if turn_id in event_by_turn:
                continue
            add_gap("TURN_RECEIPT_MISSING", committed, turn_id, execution,
                    ("events.jsonl", "turn_receipts.jsonl"))
            turn_events = [item for item in events if item.turn_id == turn_id]
            if execution == "UNKNOWN":
                add_gap("EXECUTION_UNKNOWN", committed, turn_id, execution, ("events.jsonl",))
            if not any(item.event_type == "MODEL_RESULT" and item.outcome_code == "OK" for item in turn_events):
                add_gap("MODEL_RESULT_MISSING_OR_NOT_OK", committed, turn_id, execution, ("events.jsonl",))
            if not any(item.event_type == "SCORE_RESULT" and item.outcome_code == "OK" for item in turn_events):
                add_gap("SCORE_RESULT_MISSING_OR_NOT_OK", committed, turn_id, execution, ("events.jsonl",))
            add_gap("RESPONSE_ARTIFACT_MISSING", committed, turn_id, execution, ("events.jsonl",))
            if turn and not turn["body_ref"]:
                add_gap("QUEUE_BODY_MISSING_OR_MISMATCHED", committed, turn_id, execution,
                        ("events.jsonl",))

        for turn_id, matches in event_by_turn.items():
            event = matches[0]
            turn = rows.get(turn_id)
            execution = event_execution(turn_id)
            if len(matches) > 1:
                for duplicate in matches[1:]:
                    add_gap("FEEDBACK_EVENT_DUPLICATE", duplicate, turn_id, execution,
                            related=("events.jsonl",))
            commits = committed_by_turn.get(turn_id, [])
            if not commits:
                add_gap("TURN_COMMIT_MISSING", event, turn_id, execution, ("events.jsonl",))
            if turn_id not in receipt_map:
                add_gap("TURN_RECEIPT_MISSING", event, turn_id, execution,
                        ("events.jsonl", "turn_receipts.jsonl"))
            if execution == "UNKNOWN":
                add_gap("EXECUTION_UNKNOWN", event, turn_id, execution, ("events.jsonl",))
            turn_events = [item for item in events if item.turn_id == turn_id]
            if not any(item.event_type == "MODEL_RESULT" and item.outcome_code == "OK" for item in turn_events):
                add_gap("MODEL_RESULT_MISSING_OR_NOT_OK", event, turn_id, execution, ("events.jsonl",))
            if not any(item.event_type == "SCORE_RESULT" and item.outcome_code == "OK" for item in turn_events):
                add_gap("SCORE_RESULT_MISSING_OR_NOT_OK", event, turn_id, execution, ("events.jsonl",))
            if len(event.artifact_ciphertext_refs) < 2:
                code = "INPUT_ARTIFACT_MISSING" if not event.artifact_ciphertext_refs else "RESPONSE_ARTIFACT_MISSING"
                add_gap(code, event, turn_id, execution, ("events.jsonl",))
            if turn and not turn["body_ref"]:
                add_gap("QUEUE_BODY_MISSING_OR_MISMATCHED", event, turn_id, execution, ("events.jsonl",))
        for receipt_row in receipt_rows:
            if not receipt_row["receipt_json"]:
                continue
            receipt_turn_id = receipt_row["turn_id"]
            try:
                signed_receipt = SignedTurnReceipt.model_validate_json(receipt_row["receipt_json"])
                receipt = signed_receipt.receipt
                receipt_turn_id = receipt.turn_id
                feedback = event_by_turn.get(receipt_row["turn_id"], [])
                valid_receipt = (
                    receipt.signer_key_id == self.recorder.signer_key_id
                    and (receipt.domain_id, receipt.experiment_id, receipt.epoch) == (
                        self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch)
                    and receipt.turn_id == receipt_row["turn_id"]
                    and len(feedback) == 1
                    and (receipt.session_id, receipt.turn_id, receipt.turn_index,
                         receipt.event_count, receipt.prefix_root) == (
                        feedback[0].session_id, feedback[0].turn_id, feedback[0].turn_index,
                        feedback[0].sequence, event_digest(feedback[0]))
                    and verify(turn_message(receipt), signed_receipt.signature,
                               self.recorder_public_key)
                )
            except Exception:
                valid_receipt = False
            if not valid_receipt:
                event = event_by_turn.get(receipt_row["turn_id"], [None])[0]
                mismatch_event = event_by_turn.get(receipt_turn_id, [None])[0]
                execution = event_execution(receipt_turn_id)
                add_gap("TURN_RECEIPT_MISMATCH", mismatch_event, receipt_turn_id, execution,
                        related=("events.jsonl", "turn_receipts.jsonl"))
                if event is not None:
                    actual_execution = event_execution(receipt_row["turn_id"])
                    add_gap("TURN_RECEIPT_MISSING", event, receipt_row["turn_id"], actual_execution,
                            related=("events.jsonl", "turn_receipts.jsonl"))

        all_refs = checkpoint.checkpoint.required_artifacts
        for event in events:
            if (event.event_type == "INTEGRITY_VIOLATION"
                    or (event.event_type == "CLOSE_REQUESTED" and event.outcome_code == "INVALID")):
                add_gap("PRIOR_INVALIDITY", event, event.turn_id,
                        event_execution(event.turn_id) if event.turn_id else "NOT_ESTABLISHED",
                        related=("events.jsonl",))
        if checkpoint.checkpoint.final_root != (event_digest(events[-1]) if events else "0" * 64):
            add_gap("CHECKPOINT_MISMATCH", events[-1] if events else None, related=("checkpoint.json", "events.jsonl"))
        elif add_chain_gap:
            add_gap("CHECKPOINT_MISMATCH", events[-1] if events else None,
                    related=("checkpoint.json", "events.jsonl"))

        last_anchor_digest = None
        try:
            if self.recorder.anchor is None:
                raise RecoveryAnchorError("ANCHOR_UNAVAILABLE")
            anchor_records = self.recorder.anchor.records(self.ctx)
            state = verify_anchor_records(
                anchor_records, self.ctx, self.recorder.anchor.public_key,
                self.recorder.anchor.key_id, self.recorder.anchor.authority_id,
            )
            if state["pending"]:
                raise RecoveryAnchorError("ANCHOR_PREPARE_UNRESOLVED")
            if state["event_sequence"] < len(events):
                raise RecoveryAnchorError("ANCHOR_BEHIND")
            if state["event_sequence"] > len(events):
                raise RecoveryAnchorError("ANCHOR_AHEAD")
            self.recorder.anchor.verify_events(self.ctx, events)
            # The INVALID bundle omits anchor records, so an offline reader
            # cannot verify even a locally successful anchor check.
            add_gap("ANCHOR_RECORDS_OMITTED", events[-1] if events else None,
                    related=("events.jsonl",))
        except RecoveryAnchorError:
            # The same omitted-records gap applies when the local anchor check
            # itself fails; the archive contains no evidence to distinguish it.
            add_gap("ANCHOR_RECORDS_OMITTED", events[-1] if events else None,
                    related=("events.jsonl",))

        for ref in all_refs:
            try:
                raw = self.vault.export_ciphertext_only((ref,))[ref.artifact_id]
                members[f"artifacts/{ref.artifact_id}.bin"] = raw
            except Exception:
                related_events = [
                    event for event in events
                    if ref in event.artifact_ciphertext_refs
                ]
                code = "ARTIFACT_OPENING_FAILED"
                event = next((item for item in related_events
                              if item.event_type == "FEEDBACK_AUTHORIZED"),
                             related_events[0] if related_events else None)
                if event is not None and event.event_type == "FEEDBACK_AUTHORIZED":
                    position = event.artifact_ciphertext_refs.index(ref)
                    if position == 0:
                        code = "INPUT_ARTIFACT_MISSING"
                    elif position == 1:
                        code = "RESPONSE_ARTIFACT_MISSING"
                turn_id = event.turn_id if event is not None else None
                execution = event_execution(turn_id) if turn_id else "NOT_ESTABLISHED"
                add_gap(
                    code, event, turn_id, execution,
                    related=("events.jsonl", f"artifacts/{ref.artifact_id}.bin"),
                )
        unique = {}
        for gap in gaps:
            unique[(gap["gap_code"], gap.get("event_sequence"), gap.get("turn_id"))] = gap
        gaps = list(unique.values())
        if not gaps:
            raise DependencyUnavailable("INVALID_EXPORT_GAP_BASIS_UNAVAILABLE")
        return export_invalid_evidence_bundle(
            path, members, gaps, context=self.ctx,
            public_manifest_digest=row["public_commitment"],
            signed_checkpoint=checkpoint, signed_witness_start=start,
            signed_witness_close=witness,
            last_verified_anchor_record_digest=last_anchor_digest,
            key=private_key, key_id=authority["key_id"],
        )

    async def analyze_after_release(self, principal, turn_id):
        """One late observation per completed turn. Never alter its pipeline result."""
        self.broker._role(principal, "operator")
        row = self._row(principal)
        if (
            row["phase"] != "RELEASED"
            or Profile.model_validate_json(row["config_json"]).request.defense_mode
            != "POST_HOC"
        ):
            raise DependencyUnavailable("POST_HOC_REQUIRES_AUTHORIZED_RELEASE")
        with self.store.transaction() as conn:
            run = conn.execute(
                "SELECT * FROM n04_runs WHERE experiment_id=? AND state='RELEASED'",
                (self.identifier,),
            ).fetchone()
            turn = conn.execute(
                "SELECT t.*,n.known_execution,n.receipt_json FROM turns t JOIN n04_turns n ON n.turn_id=t.id WHERE t.id=? AND t.experiment_id=? AND n.state='DONE'",
                (turn_id, self.identifier),
            ).fetchone()
            if (
                not run
                or not run["release_id"]
                or not turn
                or turn["known_execution"] != "EXECUTED"
            ):
                raise DependencyUnavailable("POST_HOC_REQUIRES_COMPLETED_BOUND_OUTPUT")
            old = conn.execute(
                "SELECT * FROM n04_analyses WHERE turn_id=?", (turn_id,)
            ).fetchone()
            if old:
                if old["state"] == "DONE":
                    return SignedPostHocReceipt.model_validate_json(old["receipt_json"])
                raise DependencyUnavailable("POST_HOC_REQUIRES_EXPLICIT_RECOVERY")
            conn.execute(
                "INSERT INTO n04_analyses(turn_id,state) VALUES(?,'PENDING')",
                (turn_id,),
            )
            from arena.contracts.evidence import SignedCheckpoint

            checkpoint = SignedCheckpoint.model_validate_json(run["close_json"])
            release_id = run["release_id"]
            bound = {
                **self.ctx.model_dump(),
                "session_id": turn["session_id"],
                "turn_id": turn_id,
                "turn_index": turn["turn_index"],
            }
        events = [
            event
            for event in self.recorder.get_events(self.ctx)
            if event.turn_id == turn_id
        ]
        feedback = next(
            event for event in events if event.event_type == "FEEDBACK_AUTHORIZED"
        )
        model = next(
            event
            for event in events
            if event.event_type == "MODEL_RESULT" and event.outcome_code == "OK"
        )
        input_ref = next(
            ref
            for ref in feedback.artifact_ciphertext_refs
            if self.vault.get(ref).get("kind") == "INPUT_OPENING"
        )
        input_envelope = json.loads(
            base64.b64decode(self.vault.get(input_ref)["content_base64"], validate=True)
        )
        output_ref = model.artifact_ciphertext_refs[0]
        output = self.vault.get(output_ref)
        prompt = base64.b64decode(
            input_envelope["original_utf8_base64"], validate=True
        ).decode("utf-8")
        request = PostHocDefenseRequest(
            call_token=str(uuid4()),
            mode="POST_HOC",
            content=PostHocContent(prompt=prompt, response=output["text"]),
        )
        decision = await self._defend(request)
        analysis_ref = self._artifact(
            {"request": request.model_dump(), "decision": decision.model_dump()},
            "PRIVATE_DEFENSE",
        )
        receipt = PostHocReceipt(
            **bound,
            analysis_id=str(uuid5(UUID(turn_id), release_id)),
            terminal_checkpoint_digest=checkpoint_digest(checkpoint.checkpoint),
            release_receipt_id=release_id,
            source_input=input_ref,
            source_output=output_ref,
            analysis_artifact=analysis_ref,
            aggregate_integrity=row["integrity"],
            signer_key_id=self.recorder.signer_key_id,
        )
        signed = self.recorder.authorize_analysis(receipt, ACTOR)
        with self.store.transaction() as conn:
            conn.execute(
                "UPDATE n04_analyses SET state='DONE',receipt_json=? WHERE turn_id=?",
                (signed.model_dump_json(), turn_id),
            )
        return signed

    def export_analysis(self, principal, turn_id, path):
        self.broker._role(principal, "auditor")
        row = self._row(principal)
        if row["phase"] != "RELEASED":
            raise BrokerError("WRONG_PHASE")
        with closing(self.store.connect()) as conn:
            record = conn.execute(
                "SELECT a.receipt_json FROM n04_analyses a JOIN turns t ON t.id=a.turn_id WHERE t.experiment_id=? AND a.turn_id=? AND a.state='DONE'",
                (self.identifier, turn_id),
            ).fetchone()
        if not record:
            raise DependencyUnavailable("POST_HOC_ANALYSIS_UNAVAILABLE")
        signed = SignedPostHocReceipt.model_validate_json(record[0])
        refs = (
            signed.receipt.source_input,
            signed.receipt.source_output,
            signed.receipt.analysis_artifact,
        )
        blobs = self.vault.export_ciphertexts(refs)
        with zipfile.ZipFile(path, "x", zipfile.ZIP_STORED) as archive:
            archive.writestr("analysis.json", signed.model_dump_json().encode())
            archive.writestr("artifacts/", b"")
            for identifier, blob in blobs.items():
                archive.writestr("artifacts/" + identifier + ".bin", blob)
        return signed

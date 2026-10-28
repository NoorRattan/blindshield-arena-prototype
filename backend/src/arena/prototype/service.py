"""One fresh admitted local arena, authenticated HTTP and a persistent async loop.

Admin intents are durable and never rerun automatically after process loss.
HTTP threads perform bounded admission/projection only. Three model cells are
prewarmed before a listener opens. Cold resume remains explicitly unsupported.
"""
from __future__ import annotations

import asyncio
import base64
from contextlib import closing
import hashlib
import json
import os
from pathlib import Path
import re
import ssl
import subprocess
import tempfile
import threading
import time
from uuid import uuid4

from pydantic import TypeAdapter
from cryptography.hazmat.primitives import serialization

from arena.broker.config import BrokerConfig, Profile
from arena.broker.provision import write_private
from arena.broker.server import Server, dispatch as control_dispatch, tls_context
from arena.broker.store import BrokerError, Store
from arena.contracts.api import CreateExperiment, EpochRequest, TurnSubmission
from arena.contracts.common import ClientKey, Context, Principal, Uuid
from arena.contracts.crypto import canonical_bytes, sha256
from arena.contracts.evidence import ArtifactRef, SignedTurnReceipt, SignedWitnessClose
from arena.contracts.jsonwire import load_wire
from arena.contracts.transport_profile import (FeedbackPolicy, LabProfile, SealedTransportPlan, SignedLabProfile,
    SignedPolicy, TransportAdmission, TransportTrust, disclosure_id, lab_message, policy_message)
from arena.execution.policy import padded_json, validate_policy
from arena.execution.queue import ExecutionQueue
from arena.execution.transport import ParticipantGateway
from arena.execution.worker import AsyncTurnWorker
from arena.integration.artifacts import ArtifactVault
from arena.integration.runtime import docker
from arena.integration.lanes import cpu_set
from arena.ports import DependencyUnavailable
from arena.recorder.recorder import DurableRecorder
from arena.witness.authority import SQLiteWitnessAuthority
from arena.model_runtime import BACKEND
from arena.recovery.anchor import (
    RecoveryAnchorError, load_recovery_authorities, verify_anchor_records,
)
from arena.recovery.process import RecoveryAnchorProcess
from arena.recovery.feedback import FeedbackRecoveryRequest
from arena.recovery.startup import inspect_existing_prototype
from .broker import PrototypeBroker
from .controller import PrototypeController
from .identities import provision
from .admission import key_from_file


SCHEMA = """
CREATE TABLE prototype_operations(id TEXT PRIMARY KEY, experiment_id TEXT NOT NULL,
 action TEXT NOT NULL, state TEXT NOT NULL, result_json TEXT,
 UNIQUE(experiment_id,action));
CREATE TABLE prototype_state(experiment_id TEXT PRIMARY KEY, finishing INTEGER NOT NULL DEFAULT 0,
 batch_state TEXT NOT NULL DEFAULT 'NOT_STARTED');
CREATE TABLE prototype_batch_claims(experiment_id TEXT NOT NULL,item_id TEXT NOT NULL,
 state TEXT NOT NULL,turn_id TEXT,PRIMARY KEY(experiment_id,item_id));
"""


class ZipBody(bytes):
    content_type = "application/zip"


class JsonBody(bytes):
    content_type = "application/json"


def _require_regular_file(path, code):
    path = Path(path)
    if path.is_symlink() or not path.is_file():
        raise DependencyUnavailable(code)
    return path


def _publish_private_or_match(path, data, conflict_code):
    """Create a private artifact once, or require an exact retry match."""
    path = Path(path)
    if path.is_symlink():
        raise DependencyUnavailable(conflict_code)
    if path.exists():
        if not path.is_file() or path.read_bytes() != data:
            raise DependencyUnavailable(conflict_code)
        return
    try:
        write_private(path, data)
    except FileExistsError:
        if path.is_symlink() or not path.is_file() or path.read_bytes() != data:
            raise DependencyUnavailable(conflict_code) from None


def _export_private_or_match(path, export, conflict_code):
    """Regenerate to a fresh file and compare before accepting a prior export."""
    path = Path(path)
    if path.is_symlink():
        raise DependencyUnavailable(conflict_code)
    if path.exists() and not path.is_file():
        raise DependencyUnavailable(conflict_code)
    with tempfile.TemporaryDirectory(prefix=".prototype-export-", dir=path.parent) as folder:
        candidate = Path(folder) / path.name
        export(candidate)
        candidate_bytes = candidate.read_bytes()
        if path.exists():
            if path.read_bytes() != candidate_bytes:
                raise DependencyUnavailable(conflict_code)
        else:
            _publish_private_or_match(path, candidate_bytes, conflict_code)


class _RecoveryFenceModel:
    """No-inference runtime adapter that proves old model processes are gone."""

    def __init__(self, service, sessions):
        self.service = service
        self.sessions = {row["id"] for row in sessions}

    async def reset(self, session_id):
        if session_id not in self.sessions:
            raise DependencyUnavailable("RECOVERY_FENCE_SESSION_UNKNOWN")
        await asyncio.to_thread(self.service._fence_previous_model_containers, session_id)

    async def infer(self, request):
        raise DependencyUnavailable("RECOVERY_ONLY_MODEL_INFERENCE_DISABLED")


class _RecoveryFenceRuntime:
    def __init__(self, service, sessions):
        self.model = _RecoveryFenceModel(service, sessions)
        self.started = False
        self.lane_count = 3
        self.supported_interaction_modes = {"INTERACTIVE"}


class PrototypeService:
    def __init__(self, runtime, corpus, root, authority_directory, *, mode="INTERACTIVE", defense_mode="INPUT", loop=None):
        if (mode not in {"INTERACTIVE", "SEALED_BATCH"} or defense_mode not in {"INPUT", "FEATURES", "OUTPUT", "POST_HOC"}
            or runtime.purpose != "SERVICE"):
            raise ValueError("SERVICE_ADMISSION_AND_SUPPORTED_MODE_REQUIRED")
        self.runtime, self.corpus, self.root, self.mode = runtime, corpus, Path(root), mode
        self.loop = loop or asyncio.get_running_loop()
        self.store = Store(self.root / "broker.sqlite3", os.urandom(32))
        if self.store.path.exists():
            raise DependencyUnavailable("COLD_RESUME_REQUIRES_INDEPENDENT_RECOVERY")
        self.store.initialize()
        write_private(self.root / "broker-master.key", self.store.master_key)
        with closing(self.store.connect()) as conn:
            conn.executescript(SCHEMA)
        domain = str(uuid4())
        self.p, self.clients, self.recorder_key, self.witness_key = provision(self.root / "tls", authority_directory, self.store, domain)
        policy = FeedbackPolicy(policy_id="prototype-fixed-60s.v1", run_label="REAL_PUBLIC",
            execution_deadline_ms=60000, release_floor_ms=61000, body_bytes=16384)
        self.signed_policy = SignedPolicy(policy=policy, signer_key_id="n08-prototype-recorder-001",
            signature=self.recorder_key.sign(policy_message(policy, "n08-prototype-recorder-001")).hex())
        self.request = CreateExperiment(profile_id="prototype-" + mode.lower() + "-" + defense_mode.lower() + ".v1", model_version_id="qwen25-05b-pinned",
            defense_version_id="literal-defense.v1", rubric_version_id="refusal-observation.v1", disclosure_profile_id=disclosure_id(self.signed_policy),
            interaction_mode=mode, defense_mode=defense_mode, dataset_catalog_id="jbb-real-public.v1", strategy_version_id="prototype-frozen-public.v1", budget_profile_id="prototype-24.v1")
        self.profile = Profile(domain_id=domain, request=self.request, red_subject_id="red", blue_subject_id="blue-human",
            auditor_subject_ids=("auditor",), session_limit=3, query_budget=24, execution_lock_sha256=sha256(runtime.lock_bytes), run_label="REAL_PUBLIC")
        self.broker = PrototypeBroker(self.store, BrokerConfig(profiles=(self.profile,)), corpus)
        self.queue = ExecutionQueue(self.broker, self.recorder_key.public_key().public_bytes_raw(), self.signed_policy.signer_key_id)
        self.lock = threading.RLock()
        self.ctx = self.controller = self.worker = self.participant = self.admission = None
        self.pump_task = self.batch_task = None
        self.tasks = set()
        self.activation_pending = False
        self.operation_lock = asyncio.Lock()
        self.server = self.server_thread = None
        write_private(self.root / "create-request.json", self.request.model_dump_json(indent=2).encode())
        self.recovery_authorities = load_recovery_authorities(
            BACKEND / "infra/prototype/recovery-authorities.json"
        )
        recovery_dir = Path(authority_directory).resolve().parent / "prototype-recovery"
        self.recovery_directory = recovery_dir
        self.recovery_only = False
        self.recovery_inspection = {}
        self.recovery_admission_blocked = False
        self._recovery_floor_not_before_ns = None
        self.recovery_preflight_complete = False
        self.recovery_verified_turns = set()
        self.recovery_invalidated_turns = set()
        self.anchor_process = RecoveryAnchorProcess(
            data_directory=recovery_dir / "anchor-data",
            private_key_path=recovery_dir / "prototype-anchor-20261026-private.pem",
            public_key=self.recovery_authorities["anchor"]["public_key_bytes"],
            authority_id=self.recovery_authorities["anchor"]["authority_id"],
            key_id=self.recovery_authorities["anchor"]["key_id"],
            ca=self.root / "tls/ca.pem",
            server_certificate=self.root / "tls/server.pem",
            server_private_key=self.root / "tls/server.key",
            recorder_certificate=self.root / "tls/client-recorder.pem",
            recorder_private_key=self.root / "tls/client-recorder.key",
        )
        self.anchor = self.anchor_process.start()

    @classmethod
    def open_existing_recovery(
        cls, corpus, root, authority_directory, *, startup_monotonic_ns=None, loop=None
    ):
        """Open only the authenticated recovery route for an existing store.

        Startup inspection is read-only and precedes every write-capable store
        adapter. This constructor intentionally creates no queue, worker, model
        runtime, batch scheduler, or participant gateway.
        """
        root = Path(root)
        if root.is_symlink():
            raise DependencyUnavailable("STARTUP_ROOT_MISSING_OR_UNSAFE")
        root = root.resolve()
        authority_directory = Path(authority_directory)
        if authority_directory.is_symlink() or not authority_directory.is_dir():
            raise DependencyUnavailable("STARTUP_AUTHORITY_DIRECTORY_MISSING_OR_UNSAFE")
        authority_directory = authority_directory.resolve()
        inspection = inspect_existing_prototype(
            root, authority_directory, allow_feedback_recovery=True
        )
        if not inspection.get("recovery_only_ready"):
            raise DependencyUnavailable("STARTUP_RECOVERY_NOT_AUTHORIZED")
        service = cls.__new__(cls)
        service._initialize_existing_recovery(
            corpus, root, authority_directory, inspection,
            startup_monotonic_ns=startup_monotonic_ns, loop=loop,
        )
        return service

    def _initialize_existing_recovery(
        self, corpus, root, authority_directory, inspection, *,
        startup_monotonic_ns=None, loop=None,
    ):
        self.root = Path(root)
        self.corpus = corpus
        self.runtime = None
        self.loop = loop or asyncio.get_running_loop()
        self.recovery_only = True
        self.recovery_admission_blocked = True
        self.recovery_inspection = inspection
        self.recovery_only_ready = False
        self.recovery_preflight_complete = False
        self.recovery_verified_turns = set()
        self.recovery_invalidated_turns = set()
        self.operation_lock = asyncio.Lock()
        self.lock = threading.RLock()
        self.server = self.server_thread = None
        self.pump_task = self.batch_task = None
        self.tasks = set()
        self.activation_pending = False
        self.participant = self.worker = self.queue = self.admission = None

        master_path = self.root / "broker-master.key"
        _require_regular_file(master_path, "STARTUP_BROKER_KEY_MISSING_OR_UNSAFE")
        master_key = master_path.read_bytes()
        if len(master_key) != 32:
            raise DependencyUnavailable("STARTUP_BROKER_KEY_INVALID")
        self.store = Store(self.root / "broker.sqlite3", master_key)
        wrapping_path = _require_regular_file(
            self.root / "vault-wrapping.key", "STARTUP_VAULT_KEY_MISSING_OR_UNSAFE"
        )
        wrapping = wrapping_path.read_bytes()
        if len(wrapping) != 32:
            raise DependencyUnavailable("STARTUP_VAULT_KEY_INVALID")

        with closing(self.store.connect()) as conn:
            experiments = conn.execute("SELECT * FROM experiments").fetchall()
            if len(experiments) != 1:
                raise DependencyUnavailable("STARTUP_EXPERIMENT_CARDINALITY_INVALID")
            run = dict(experiments[0])
            self.ctx = Context(
                domain_id=run["domain_id"], experiment_id=run["id"], epoch=run["epoch"]
            )
            self.profile = Profile.model_validate_json(run["config_json"])
            if self.profile.request.interaction_mode != "INTERACTIVE":
                raise DependencyUnavailable("STARTUP_RECOVERY_INTERACTIVE_ONLY")
            self.mode = self.profile.request.interaction_mode
            self.request = self.profile.request
            principal_rows = [dict(row) for row in conn.execute(
                "SELECT * FROM principals WHERE enabled=1 ORDER BY role"
            )]
            policy_row = conn.execute(
                "SELECT signed_json FROM n06_policies WHERE experiment_id=?",
                (self.ctx.experiment_id,),
            ).fetchone()
            session_rows = [dict(row) for row in conn.execute(
                "SELECT id,lane,owner FROM sessions WHERE experiment_id=? ORDER BY lane",
                (self.ctx.experiment_id,),
            )]
        if not policy_row:
            raise DependencyUnavailable("STARTUP_FEEDBACK_POLICY_MISSING")

        self.recovery_authorities = load_recovery_authorities(
            BACKEND / "infra/prototype/recovery-authorities.json"
        )
        self.recovery_directory = authority_directory.parent / "prototype-recovery"
        self.authority_directory = authority_directory
        if self.recovery_directory.is_symlink() or not self.recovery_directory.is_dir():
            raise DependencyUnavailable("STARTUP_RECOVERY_DIRECTORY_MISSING_OR_UNSAFE")
        self.recovery_policy = SignedPolicy.model_validate_json(policy_row[0])
        self.signed_policy = self.recovery_policy
        with closing(self.store.connect()) as conn:
            manifest_row = conn.execute(
                "SELECT manifest_id FROM experiments WHERE id=?", (self.ctx.experiment_id,)
            ).fetchone()
        if not manifest_row or not manifest_row[0]:
            raise DependencyUnavailable("STARTUP_SEALED_MANIFEST_MISSING")
        sealed_payload = self.store.read_payload(manifest_row[0])
        sealed_manifest = sealed_payload.get("manifest") if isinstance(sealed_payload, dict) else None
        if not isinstance(sealed_manifest, dict) or "n06_transport" not in sealed_manifest:
            raise DependencyUnavailable("STARTUP_SEALED_TRANSPORT_MISSING")
        transport_plan = SealedTransportPlan.model_validate(sealed_manifest["n06_transport"])

        recorder_public_path = _require_regular_file(
            BACKEND / "infra/owner-delegated-n08/recorder-public.pem",
            "STARTUP_RECORDER_PUBLIC_KEY_MISSING_OR_UNSAFE",
        )
        witness_public_path = _require_regular_file(
            BACKEND / "infra/owner-delegated-n08/witness-public.pem",
            "STARTUP_WITNESS_PUBLIC_KEY_MISSING_OR_UNSAFE",
        )
        self.recorder_public_key = serialization.load_pem_public_key(
            recorder_public_path.read_bytes()
        ).public_bytes_raw()
        self.witness_public_key = serialization.load_pem_public_key(
            witness_public_path.read_bytes()
        ).public_bytes_raw()
        self.recorder_key = key_from_file(_require_regular_file(
            authority_directory / "recorder-private.pem",
            "STARTUP_RECORDER_PRIVATE_KEY_MISSING_OR_UNSAFE",
        ))
        self.witness_key = key_from_file(_require_regular_file(
            authority_directory / "witness-private.pem",
            "STARTUP_WITNESS_PRIVATE_KEY_MISSING_OR_UNSAFE",
        ))
        if (self.recorder_key.public_key().public_bytes_raw() != self.recorder_public_key
                or self.witness_key.public_key().public_bytes_raw() != self.witness_public_key):
            raise DependencyUnavailable("STARTUP_EVIDENCE_PRIVATE_KEY_MISMATCH")
        validate_policy(
            self.signed_policy, self.recorder_public_key, "n08-prototype-recorder-001"
        )
        transport_trust = TransportTrust(
            self.recorder_public_key, "n08-prototype-recorder-001",
            self.recorder_public_key, "n08-prototype-recorder-001",
        )
        try:
            transport_trust.validate(
                transport_plan, self.ctx, self.profile.execution_lock_sha256,
                self.profile.request.disclosure_profile_id, self.profile.run_label,
            )
        except Exception as exc:
            raise DependencyUnavailable("STARTUP_SEALED_TRANSPORT_INVALID") from exc
        self.transport_admission = TransportAdmission(transport_plan, transport_trust)

        recovery = self.recovery_authorities["recovery"]
        recovery_key_path = _require_regular_file(
            self.recovery_directory / (recovery["key_id"] + "-private.pem"),
            "STARTUP_RECOVERY_PRIVATE_KEY_MISSING_OR_UNSAFE",
        )
        self.recovery_private_key = key_from_file(recovery_key_path)
        if self.recovery_private_key.public_key().public_bytes_raw() != recovery["public_key_bytes"]:
            raise DependencyUnavailable("STARTUP_RECOVERY_PRIVATE_KEY_MISMATCH")

        tls_root = self.root / "tls"
        if tls_root.is_symlink() or not tls_root.is_dir():
            raise DependencyUnavailable("STARTUP_TLS_DIRECTORY_MISSING_OR_UNSAFE")
        ca_path = _require_regular_file(
            BACKEND / "infra/owner-delegated-n08/demo-ca-certificate.pem",
            "STARTUP_TLS_CA_MISSING_OR_UNSAFE",
        )
        tls_ca_path = _require_regular_file(
            tls_root / "ca.pem", "STARTUP_TLS_CA_MISSING_OR_UNSAFE"
        )
        if tls_ca_path.read_bytes() != ca_path.read_bytes():
            raise DependencyUnavailable("STARTUP_TLS_CA_MISMATCH")
        self.p, self.clients = {}, {}
        expected_roles = {"operator", "red", "blue-human", "auditor"}
        if {row["role"] for row in principal_rows} != expected_roles:
            raise DependencyUnavailable("STARTUP_PRINCIPAL_SET_INVALID")
        for row in principal_rows:
            role = row["role"]
            principal = Principal(**{
                key: row[key] for key in ("subject_id", "role", "domain_id", "expires_at")
            })
            cert_path = tls_root / ("client-" + role + ".pem")
            key_path = tls_root / ("client-" + role + ".key")
            _require_regular_file(cert_path, "STARTUP_CLIENT_IDENTITY_MISSING_OR_UNSAFE")
            _require_regular_file(key_path, "STARTUP_CLIENT_IDENTITY_MISSING_OR_UNSAFE")
            cert_der = ssl.PEM_cert_to_DER_cert(cert_path.read_text(encoding="ascii"))
            if hashlib.sha256(cert_der).hexdigest() != row["fingerprint"]:
                raise DependencyUnavailable("STARTUP_CLIENT_IDENTITY_BINDING_MISMATCH")
            context = ssl.create_default_context(cafile=str(tls_root / "ca.pem"))
            context.minimum_version = ssl.TLSVersion.TLSv1_2
            context.load_cert_chain(str(cert_path), str(key_path))
            self.p[role] = principal
            self.clients[role] = context

        anchor_authority = self.recovery_authorities["anchor"]
        anchor_key_path = _require_regular_file(
            self.recovery_directory / (anchor_authority["key_id"] + "-private.pem"),
            "STARTUP_ANCHOR_PRIVATE_KEY_MISSING_OR_UNSAFE",
        )
        self.anchor_process = RecoveryAnchorProcess(
            data_directory=self.recovery_directory / "anchor-data",
            private_key_path=anchor_key_path,
            public_key=anchor_authority["public_key_bytes"],
            authority_id=anchor_authority["authority_id"], key_id=anchor_authority["key_id"],
            ca=tls_root / "ca.pem", server_certificate=tls_root / "server.pem",
            server_private_key=tls_root / "server.key",
            recorder_certificate=tls_root / "client-recorder.pem",
            recorder_private_key=tls_root / "client-recorder.key",
        )
        self.anchor = self.anchor_process.start(require_existing=True)

        self.broker = PrototypeBroker(
            self.store, BrokerConfig(profiles=(self.profile,)), corpus
        )
        self.signer_key_id = "n08-prototype-recorder-001"
        self.witness_key_id = "n08-prototype-witness-001"
        self.recorder = DurableRecorder(
            self.root / "recorder.sqlite3", self.recorder_key.private_bytes_raw(),
            self.signer_key_id, anchor=self.anchor,
        )
        self.witness = SQLiteWitnessAuthority(
            self.root / "witness.sqlite3", self.witness_key.private_bytes_raw(),
            self.witness_key_id, initialize_if_missing=False,
            recorder_public_key=self.recorder_public_key, recorder_key_id=self.signer_key_id,
        )
        vault_root = self.root / "vault"
        vault_db = vault_root / "custody.sqlite3"
        if vault_root.is_symlink() or vault_db.is_symlink() or not vault_db.is_file():
            raise DependencyUnavailable("STARTUP_VAULT_STORE_MISSING_OR_UNSAFE")
        self.vault = ArtifactVault(vault_root, self.ctx, wrapping)
        self.controller = PrototypeController(
            self.broker, self.recorder, self.witness, self.vault, None, corpus,
            recorder_public_key=self.recorder_public_key,
            witness_public_key=self.witness_public_key,
            transport_admission=self.transport_admission,
            recovery_authority=recovery,
            recovery_private_key=self.recovery_private_key.private_bytes_raw(),
        )
        self.controller.runtime = _RecoveryFenceRuntime(self, session_rows)
        self.anchor = self.recorder.anchor
        self._recovery_old_cells = self._load_manifest_bound_old_cells()
        self.recovery_start_monotonic_ns = (
            time.monotonic_ns() if startup_monotonic_ns is None else startup_monotonic_ns
        )
        self._recovery_floor_not_before_ns = (
            self.recovery_start_monotonic_ns
            + self.recovery_policy.policy.release_floor_ms * 1_000_000
        )
        self.recovery_only_ready = True

    def startup_recovery_preflight(self):
        """Recheck the authenticated recovery state before opening its listener."""
        if not self.recovery_only or not self.recovery_only_ready or self.controller is None:
            raise DependencyUnavailable("STARTUP_RECOVERY_NOT_AUTHORIZED")
        self.anchor.health()
        with closing(self.store.connect()) as conn:
            run = conn.execute(
                "SELECT phase,integrity FROM experiments WHERE id=? AND domain_id=? AND epoch=?",
                (self.ctx.experiment_id, self.ctx.domain_id, self.ctx.epoch),
            ).fetchone()
            run_state = conn.execute(
                "SELECT state FROM n04_runs WHERE experiment_id=?", (self.ctx.experiment_id,)
            ).fetchone()
            close_invalid = (
                self.recovery_inspection.get("recovery_only_action") == "CLOSE_INVALID"
            )
            retry_pending_close = (
                self.recovery_inspection.get("recovery_only_action") == "RETRY_PENDING_CLOSE"
            )
            if (not run or not run_state
                    or ((run["integrity"] == "INVALID" or run["phase"] == "INVALID"
                         or run_state["state"] == "INVALID")
                        and not close_invalid and not retry_pending_close)):
                raise DependencyUnavailable("STARTUP_INVALID_RUN_RESUME_REFUSED")
            if run["phase"] == "RUNNING" and run_state["state"] != "RUNNING":
                raise DependencyUnavailable("STARTUP_CONTROLLER_STATE_MISMATCH")
            if close_invalid and (run["phase"] != "INVALID" or run["integrity"] != "INVALID"
                                  or run_state["state"] != "INVALID"):
                raise DependencyUnavailable("STARTUP_INVALID_CLOSE_STATE_INVALID")
            if retry_pending_close:
                pending = conn.execute(
                    "SELECT state,close_json,witness_json FROM n04_runs WHERE experiment_id=?",
                    (self.ctx.experiment_id,),
                ).fetchone()
                expected_checkpoint = self.recovery_inspection.get("pending_checkpoint_json")
                pending_kind = self.recovery_inspection.get("pending_close_kind")
                if (not pending or not pending["close_json"]
                        or pending["close_json"] != expected_checkpoint):
                    raise DependencyUnavailable("STARTUP_PENDING_CLOSE_STATE_INVALID")
                if pending_kind == "AUTHORITY_ACK":
                    if (pending["state"] != "CLOSING" or pending["witness_json"]
                            or run["phase"] not in {"SCORED", "INVALID"}
                        or ((run["phase"] == "SCORED") != (run["integrity"] == "PENDING"))
                            or ((run["phase"] == "INVALID") != (run["integrity"] == "INVALID"))):
                        raise DependencyUnavailable("STARTUP_PENDING_CLOSE_STATE_INVALID")
                elif pending_kind == "PUBLICATION_ACK":
                    operation = conn.execute(
                        "SELECT state FROM prototype_operations WHERE experiment_id=? AND action='close'",
                        (self.ctx.experiment_id,),
                    ).fetchone()
                    if (pending["state"] != "CLOSED"
                            or pending["witness_json"] != self.recovery_inspection.get("pending_witness_json")
                            or run["phase"] != "CLOSED" or run["integrity"] != "VALID_WITHIN_PROFILE"
                            or not operation or operation[0] not in {"PENDING", "RUNNING", "FAILED"}):
                        raise DependencyUnavailable("STARTUP_PENDING_CLOSE_STATE_INVALID")
                else:
                    raise DependencyUnavailable("STARTUP_PENDING_CLOSE_STATE_INVALID")
        if self.controller.runtime.started:
            raise DependencyUnavailable("STARTUP_RECOVERY_RUNTIME_MUST_REMAIN_STOPPED")
        self.recovery_preflight_complete = True

    def _load_manifest_bound_old_cells(self):
        events = self.recorder.get_events(self.ctx)
        self.anchor.verify_events(self.ctx, events)
        manifests = [event for event in events if event.event_type == "MANIFEST_SEALED"]
        readiness = [event for event in events if event.event_type == "PREFLIGHT_PASSED"]
        if (len(manifests) != 1 or len(readiness) != 1
                or manifests[0].sequence >= readiness[0].sequence
                or len(manifests[0].artifact_ciphertext_refs) != 1
                or len(readiness[0].artifact_ciphertext_refs) != 1):
            raise DependencyUnavailable("STARTUP_MODEL_FENCE_MANIFEST_INVALID")
        manifest = self.vault.get(
            manifests[0].artifact_ciphertext_refs[0], expected_classification="PRIVATE_MANIFEST"
        )
        observed = self.vault.get(
            readiness[0].artifact_ciphertext_refs[0], expected_classification="PRIVATE_MANIFEST"
        )
        if (set(manifest) != {"sealed", "execution_lock", "execution_lock_bytes_base64"}
                or set(observed) != {"runtime", "corpus_receipt_sha256", "scope"}
                or observed["scope"] != "N04_SINGLE_LANE_LOCAL_INTEGRATION"):
            raise DependencyUnavailable("STARTUP_MODEL_FENCE_MANIFEST_INVALID")
        try:
            lock_bytes = base64.b64decode(
                manifest["execution_lock_bytes_base64"], validate=True
            )
            lock = json.loads(lock_bytes.decode("utf-8", errors="strict"))
            runtime = observed["runtime"]
            cells = runtime["cells"]
            if (sha256(lock_bytes) != self.profile.execution_lock_sha256
                    or lock != manifest["execution_lock"]
                    or len(cells) != 3
                    or len({cell["container_id"] for cell in cells}) != 3):
                raise ValueError("manifest binding mismatch")
            pinned_image = lock["llama_image"]
            cpusets = lock["model_cpusets"]
            if len(cpusets) != 3:
                raise ValueError("model lane binding missing")
            result = []
            for lane, cell in enumerate(cells):
                container_id = cell["container_id"]
                if (not isinstance(container_id, str)
                        or re.fullmatch(r"[0-9a-f]{64}", container_id) is None
                        or cell["image_id"] != pinned_image
                        or cpu_set(cell["cpuset_effective"]) != cpu_set(cpusets[lane])):
                    raise ValueError("cell identity mismatch")
                result.append({
                    "container_id": container_id,
                    "image_id": pinned_image,
                    "image_ref": pinned_image,
                    "cpuset": cpusets[lane],
                })
            return tuple(result)
        except Exception as exc:
            raise DependencyUnavailable("STARTUP_MODEL_FENCE_MANIFEST_INVALID") from exc

    def _fence_previous_model_containers(self, session_id):
        """Destroy only anchored, exact old model IDs before valid terminal close."""
        if not self.recovery_only or session_id not in self.controller.runtime.model.sessions:
            raise DependencyUnavailable("RECOVERY_MODEL_FENCE_CONTEXT_INVALID")
        identities = [cell["container_id"] for cell in self._recovery_old_cells]
        if len(identities) != 3 or len(set(identities)) != 3:
            raise DependencyUnavailable("RECOVERY_MODEL_FENCE_IDENTITY_INVALID")
        listing = subprocess.run(
            ["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}"],
            capture_output=True, timeout=15,
        )
        if listing.returncode != 0:
            raise DependencyUnavailable("RECOVERY_MODEL_FENCE_DOCKER_UNAVAILABLE")
        present = set(listing.stdout.decode("ascii", errors="strict").splitlines())
        for cell in self._recovery_old_cells:
            container_id = cell["container_id"]
            if container_id not in present:
                continue
            try:
                item = json.loads(docker("inspect", container_id))[0]
                config = item["Config"]
                host = item["HostConfig"]
                mounts = item["Mounts"]
                labels = config.get("Labels") or {}
                image = json.loads(docker("image", "inspect", cell["image_id"]))[0]
                image_labels = image.get("Config", {}).get("Labels") or {}
                expected_arena_labels = {
                    key: value for key, value in image_labels.items() if key.startswith("arena.")
                } | {"arena.n04": "true"}
                name = item["Name"].lstrip("/")
                bind_mounts = [mount for mount in mounts if mount.get("Type") == "bind"]
                expected_command = [
                    "--model", "/model.gguf", "--host", "127.0.0.1", "--port", "8080",
                    "--n-gpu-layers", "0", "--threads", "2", "--ctx-size", "2048",
                    "--parallel", "1", "--cache-ram", "0", "--ctx-checkpoints", "0",
                    "--no-kv-unified", "--no-cache-idle-slots", "--no-context-shift",
                    "--no-webui", "--offline", "--log-disable", "--slots",
                    "--slot-save-path", "/tmp",
                ]
                if (item.get("Id") != container_id
                        or item.get("Image") != cell["image_id"]
                        or image.get("Id") != cell["image_id"]
                        or config.get("Image") != cell["image_ref"]
                        or config.get("Cmd") != expected_command
                        or not name.startswith("arena-prototype-model-")
                        or {key: value for key, value in labels.items() if key.startswith("arena.")}
                            != expected_arena_labels
                        or config.get("User") != "65534:65534"
                        or not host.get("ReadonlyRootfs") or host.get("Privileged")
                        or host.get("NetworkMode") != "none"
                        or host.get("PortBindings")
                        or host.get("Memory") != 2147483648
                        or host.get("MemorySwap") != 2147483648
                        or host.get("NanoCpus") != 2000000000
                        or host.get("PidsLimit") != 128
                        or cpu_set(host.get("CpusetCpus")) != cpu_set(cell["cpuset"])
                        or host.get("CapDrop") != ["ALL"]
                        or host.get("CapAdd")
                        or "no-new-privileges" not in host.get("SecurityOpt", [])
                        or len(bind_mounts) != 1
                        or bind_mounts[0].get("Destination") != "/model.gguf"
                        or bind_mounts[0].get("RW") is not False
                        or host.get("Tmpfs") != {"/tmp": "rw,noexec,nosuid,nodev,size=64m"}
                        or len(mounts) != 1):
                    raise DependencyUnavailable("RECOVERY_MODEL_FENCE_CONTAINER_BINDING_INVALID")
            except DependencyUnavailable:
                raise
            except Exception as exc:
                raise DependencyUnavailable("RECOVERY_MODEL_FENCE_CONTAINER_INSPECTION_FAILED") from exc
            docker("rm", "--force", container_id)

        listing = subprocess.run(
            ["docker", "ps", "--all", "--no-trunc", "--format", "{{.ID}}"],
            capture_output=True, timeout=15,
        )
        if listing.returncode != 0:
            raise DependencyUnavailable("RECOVERY_MODEL_FENCE_DOCKER_UNAVAILABLE")
        remaining = set(listing.stdout.decode("ascii", errors="strict").splitlines())
        if remaining.intersection(identities):
            raise DependencyUnavailable("RECOVERY_MODEL_FENCE_OLD_CONTEXT_REMAINS")

        with self.store.transaction() as conn:
            conn.execute(
                "CREATE TABLE IF NOT EXISTS prototype_recovery_fences("
                "domain_id TEXT NOT NULL,experiment_id TEXT NOT NULL,epoch INTEGER NOT NULL,"
                "session_id TEXT NOT NULL,container_ids_json TEXT NOT NULL,"
                "fence_status TEXT NOT NULL,PRIMARY KEY(domain_id,experiment_id,epoch,session_id))"
            )
            ids_json = json.dumps(identities, separators=(",", ":"))
            old = conn.execute(
                "SELECT container_ids_json,fence_status FROM prototype_recovery_fences "
                "WHERE domain_id=? AND experiment_id=? AND epoch=? AND session_id=?",
                (self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch, session_id),
            ).fetchone()
            if old and (old[0] != ids_json or old[1] != "PRIOR_MODEL_PROCESSES_ABSENT"):
                raise DependencyUnavailable("RECOVERY_MODEL_FENCE_RECEIPT_CONFLICT")
            conn.execute(
                "INSERT OR IGNORE INTO prototype_recovery_fences VALUES(?,?,?,?,?,?)",
                (self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch, session_id,
                 ids_json, "PRIOR_MODEL_PROCESSES_ABSENT"),
            )

    def startup_preflight(self):
        """Run before any model cell, listener, session admission or worker starts."""
        self.anchor.health()
        with closing(self.store.connect()) as conn:
            if conn.execute("SELECT 1 FROM experiments LIMIT 1").fetchone():
                raise DependencyUnavailable("COLD_RESUME_REQUIRES_STARTUP_CONSUMER")
            if conn.execute("SELECT 1 FROM sqlite_master WHERE type='table' AND name='n04_runs'").fetchone():
                raise DependencyUnavailable("RECOVERY_STORE_NOT_FRESH")

    def error(self, status, code):
        return status, padded_json({"status": "ERROR", "code": code}, self.signed_policy.policy.body_bytes)

    def _row(self, principal, identifier, epoch=None):
        with closing(self.store.connect()) as conn:
            return dict(self.broker._object(conn, principal, identifier, epoch))

    def _recovery_release_floor_ready(self, turn_id):
        if self.recovery_only:
            return (self._recovery_floor_not_before_ns is not None
                    and time.monotonic_ns() >= self._recovery_floor_not_before_ns)
        if self.queue is None:
            return False
        with closing(self.store.connect()) as conn:
            job = conn.execute(
                "SELECT clock_id,release_ns FROM n06_jobs WHERE experiment_id=? AND turn_id=?",
                (self.ctx.experiment_id, turn_id),
            ).fetchone()
        if not job or job["clock_id"] != str(self.queue.clock_id):
            return False
        return self.queue.clock_ns() >= job["release_ns"]

    def _recovery_close_is_ready(self, turn_id):
        if turn_id not in self.recovery_verified_turns:
            return False
        with closing(self.store.connect()) as conn:
            rows = conn.execute(
                "SELECT t.state AS turn_state,t.result_json,s.quarantined,n.state AS internal_state,"
                "n.known_execution,n.feedback_ref,n.receipt_json,j.state AS job_state,j.body_ref,"
                "j.owner,j.client_key,j.published,e.integrity,e.phase "
                "FROM turns t JOIN sessions s ON s.id=t.session_id "
                "JOIN n04_turns n ON n.turn_id=t.id JOIN n06_jobs j ON j.turn_id=t.id "
                "JOIN experiments e ON e.id=t.experiment_id "
                "WHERE t.experiment_id=? AND t.id=?",
                (self.ctx.experiment_id, turn_id),
            ).fetchone()
            proof = conn.execute(
                "SELECT 1 FROM n04_recoveries WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                (self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch, turn_id),
            ).fetchone()
            copy = conn.execute(
                "SELECT 1 FROM n04_receipt_copies WHERE domain_id=? AND experiment_id=? AND epoch=? AND turn_id=?",
                (self.ctx.domain_id, self.ctx.experiment_id, self.ctx.epoch, turn_id),
            ).fetchone()
        if not rows or bool(proof) == bool(copy) or rows["integrity"] == "INVALID" or rows["phase"] == "INVALID":
            return False
        if (rows["turn_state"] != "COMPLETED" or rows["result_json"] is None
                or rows["known_execution"] != "EXECUTED" or rows["quarantined"] != 1
                or rows["owner"] != self.p["red"].subject_id or rows["published"] != 0):
            return False
        if proof:
            return (rows["internal_state"] == "RECOVERED" and rows["feedback_ref"] is not None
                    and rows["receipt_json"] is None and rows["job_state"] == "FAILED"
                    and rows["body_ref"] is None)
        return (rows["internal_state"] == "DONE" and rows["feedback_ref"] is not None
                and rows["receipt_json"] is not None and rows["job_state"] == "AUTHORIZED"
                and rows["body_ref"] is not None)

    def _spawn(self, coroutine):
        def schedule():
            task = self.loop.create_task(coroutine)
            self.tasks.add(task)
            def finished(future):
                self.tasks.discard(future)
                if not future.cancelled():
                    future.exception()
            task.add_done_callback(finished)
        self.loop.call_soon_threadsafe(schedule)

    def _transport(self, ctx):
        key_id = self.signed_policy.signer_key_id
        profile = LabProfile(**ctx.model_dump(), execution_lock_sha256=self.profile.execution_lock_sha256,
            feedback_policy_sha256=sha256(self.signed_policy.policy.model_dump_json().encode()), admission_window_ms=1000)
        signed = SignedLabProfile(profile=profile, signer_key_id=key_id, signature=self.recorder_key.sign(lab_message(profile, key_id)).hex())
        public = self.recorder_key.public_key().public_bytes_raw()
        return TransportAdmission(SealedTransportPlan(feedback=self.signed_policy, transport=signed), TransportTrust(public, key_id, public, key_id))

    def dispatch(self, principal, method, path, headers, body):
        if any(char in path for char in ("?", "%", "#")):
            raise BrokerError("NOT_FOUND", 404)
        if method == "POST":
            TypeAdapter(ClientKey).validate_python(headers.get("idempotency-key"))
        if path == "/v1/experiments" and method == "POST":
            self.broker._role(principal, "operator")
            with self.lock:
                with closing(self.store.connect()) as conn:
                    old = conn.execute("SELECT 1 FROM experiments").fetchone()
                    replay = conn.execute("SELECT 1 FROM idempotency WHERE subject_id=? AND action='create' AND client_key=?", (principal.subject_id, headers["idempotency-key"])).fetchone()
                if old and not replay:
                    raise BrokerError("RESOURCE_BUDGET_EXCEEDED", 429)
                status, result = self.broker.create(principal, load_wire(CreateExperiment, body), headers["idempotency-key"])
                self.ctx = Context(**{key: result[key] for key in ("domain_id", "experiment_id", "epoch")})
                return status, result
        if path == "/v1/turn-feedback/recovery" and method == "POST":
            self.broker._role(principal, "red")
            request = load_wire(FeedbackRecoveryRequest, body)
            if headers.get("idempotency-key") != request.idempotency_key:
                raise BrokerError("IDEMPOTENCY_CONFLICT")
            if (self.recovery_only
                    and request.turn_id != self.recovery_inspection.get("recovery_turn_id")):
                raise BrokerError("NOT_FOUND", 404)
            if (self.recovery_only
                    and self.recovery_inspection.get("recovery_only_action")
                    in {"INVALIDATE_AMBIGUOUS", "CLOSE_INVALID"}):
                return 503, JsonBody(padded_json(
                    {"status": "UNAVAILABLE"}, self.signed_policy.policy.body_bytes
                ))
            if headers.get("accept") != "application/vnd.arena.feedback-replay.v1+json":
                return 503, JsonBody(padded_json({"status": "UNAVAILABLE"}, self.signed_policy.policy.body_bytes))
            if self.controller is None:
                raise BrokerError("POLICY_NOT_READY", 503)
            with closing(self.store.connect()) as conn:
                existing_recovery = conn.execute(
                    "SELECT owner,client_key FROM n04_recoveries "
                    "WHERE experiment_id=? AND turn_id=?",
                    (self.ctx.experiment_id, request.turn_id),
                ).fetchone()
                existing_copy = conn.execute(
                    "SELECT owner,client_key FROM n04_receipt_copies "
                    "WHERE experiment_id=? AND turn_id=?",
                    (self.ctx.experiment_id, request.turn_id),
                ).fetchone()
            if existing_recovery and existing_copy:
                raise BrokerError("AUDIT_UNAVAILABLE", 503)
            if (existing_recovery and (existing_recovery["owner"] != principal.subject_id
                    or existing_recovery["client_key"] != request.idempotency_key)):
                # Reject a guessed turn ID before closing the participant gateway.
                raise BrokerError("IDEMPOTENCY_CONFLICT")
            if (existing_copy and (existing_copy["owner"] != principal.subject_id
                    or existing_copy["client_key"] != request.idempotency_key)):
                raise BrokerError("IDEMPOTENCY_CONFLICT")
            if not self._recovery_release_floor_ready(request.turn_id):
                return 503, JsonBody(padded_json(
                    {"status": "UNAVAILABLE"}, self.signed_policy.policy.body_bytes
                ))

            async def recover():
                async with self.operation_lock:
                    if ((self.worker is not None and self.worker.tasks)
                            or (self.participant is not None and self.participant.active)):
                        raise BrokerError("POLICY_NOT_READY", 503)
                    was_accepting = None
                    if self.participant is not None:
                        with self.participant.lock:
                            was_accepting = self.participant.accepting
                            self.participant.accepting = False
                    try:
                        replay = await self.controller.recover_feedback(principal, request)
                    except BaseException:
                        with closing(self.store.connect()) as conn:
                            durable_recovery = conn.execute(
                                "SELECT 1 FROM n04_recoveries WHERE experiment_id=? AND turn_id=? "
                                "AND owner=? AND client_key=?",
                                (self.ctx.experiment_id, request.turn_id,
                                 principal.subject_id, request.idempotency_key),
                            ).fetchone()
                            durable_copy = conn.execute(
                                "SELECT 1 FROM n04_receipt_copies WHERE experiment_id=? AND turn_id=? "
                                "AND owner=? AND client_key=?",
                                (self.ctx.experiment_id, request.turn_id,
                                 principal.subject_id, request.idempotency_key),
                            ).fetchone()
                            run = conn.execute(
                                "SELECT integrity FROM experiments WHERE id=?",
                                (self.ctx.experiment_id,),
                            ).fetchone()
                        if (not durable_recovery and not durable_copy
                                and not self.controller.recovery_admission_blocked
                                and run and run["integrity"] != "INVALID"
                                and self.participant is not None):
                            with self.participant.lock:
                                self.participant.accepting = was_accepting
                        raise
                    self.recovery_verified_turns.add(request.turn_id)
                    if not self.recovery_only:
                        self.recovery_inspection = {
                            "recovery_only_action": "LIVE_RECOVERY",
                            "recovery_turn_id": request.turn_id,
                        }
                    return replay

            future = asyncio.run_coroutine_threadsafe(recover(), self.loop)
            try:
                replay = future.result(timeout=20)
            except TimeoutError as exc:
                future.cancel()
                raise BrokerError("AUDIT_UNAVAILABLE", 503) from exc
            return 200, JsonBody(replay)
        matched = re.fullmatch(r"/v1/experiments/([^/]+)/(.*)", path)
        if not matched:
            raise BrokerError("NOT_FOUND", 404)
        identifier, action = matched.groups()
        TypeAdapter(Uuid).validate_python(identifier)
        if self.recovery_only:
            permitted = (
                method == "POST" and action == "close"
                or method == "GET" and action.startswith("operations/")
                or method == "GET" and action == "invalid-evidence"
                or method == "GET" and action == "anchor-records"
            )
            if not permitted:
                raise BrokerError("POLICY_NOT_READY", 503)
        row = self._row(principal, identifier)
        if principal.role == "blue-human" and action in {"status", "feedback"} and method == "GET" and row["phase"] != "RELEASED":
            return 200, padded_json({"status": "EMBARGOED"}, self.signed_policy.policy.body_bytes)
        operation = re.fullmatch(r"operations/([^/]+)", action)
        if method == "GET" and operation:
            self.broker._role(principal, "operator")
            TypeAdapter(Uuid).validate_python(operation[1])
            with closing(self.store.connect()) as conn:
                op = conn.execute("SELECT id,action,state,result_json FROM prototype_operations WHERE id=? AND experiment_id=?", (operation[1], identifier)).fetchone()
            if not op:
                raise BrokerError("NOT_FOUND", 404)
            return 200, {"operation_id": op["id"], "action": op["action"], "state": op["state"], "result": json.loads(op["result_json"]) if op["result_json"] else None}
        if method == "POST" and action in {"start", "finish", "close", "release", "analysis"}:
            return self._admin(principal, identifier, action, load_wire(EpochRequest, body), headers["idempotency-key"])
        if method == "GET" and action == "anchor-records":
            self.broker._role(principal, "auditor")
            if row["phase"] not in {"CLOSED", "RELEASED"} or row["integrity"] != "VALID_WITHIN_PROFILE":
                raise BrokerError("WRONG_PHASE")
            target = self.root / "anchor-records.jsonl"
            if target.is_symlink() or not target.is_file() or target.stat().st_size > 8 * 1024 * 1024:
                raise BrokerError("AUDIT_UNAVAILABLE", 503)
            return 200, JsonBody(target.read_bytes())
        analysis = re.fullmatch(r"analysis/([^/]+)", action)
        if method == "GET" and analysis:
            self.broker._role(principal, "auditor")
            TypeAdapter(Uuid).validate_python(analysis[1])
            if row["phase"] != "RELEASED" or row["integrity"] != "VALID_WITHIN_PROFILE":
                raise BrokerError("WRONG_PHASE")
            target = self.root / "analysis" / (analysis[1] + ".zip")
            if not target.is_file() or target.stat().st_size > 16 * 1024 * 1024:
                raise BrokerError("NOT_FOUND", 404)
            return 200, ZipBody(target.read_bytes())
        if method == "POST" and action == "seal":
            request = load_wire(EpochRequest, body)
            with self.lock:
                self.admission = self._transport(self.ctx) if self.mode == "INTERACTIVE" else None
                result = self.broker.seal(principal, identifier, request, headers["idempotency-key"], transport_admission=self.admission)
                if self._row(principal, identifier)["phase"] == "SEALED":
                    self.queue.bind_policy(principal, self.ctx, self.signed_policy)
                else:
                    with closing(self.store.connect()) as conn:
                        bound = conn.execute("SELECT signed_json FROM n06_policies WHERE experiment_id=?", (identifier,)).fetchone()
                    if not bound or bound[0] != self.signed_policy.model_dump_json():
                        raise BrokerError("POLICY_NOT_READY", 503)
                with self.store.transaction() as conn:
                    conn.execute("INSERT OR IGNORE INTO prototype_state(experiment_id) VALUES(?)", (identifier,))
                return result
        if method == "POST" and action == "sessions":
            if self.mode != "INTERACTIVE":
                raise BrokerError("WRONG_PHASE")
            with self.lock, closing(self.store.connect()) as conn:
                state = conn.execute("SELECT finishing FROM prototype_state WHERE experiment_id=?", (identifier,)).fetchone()
                replay = conn.execute("SELECT 1 FROM idempotency WHERE subject_id=? AND experiment_id=? AND action='sessions' AND client_key=?", (principal.subject_id, identifier, headers["idempotency-key"])).fetchone()
                if state and state[0] and not replay:
                    raise BrokerError("WRONG_PHASE")
                result = self.broker.session(principal, identifier, load_wire(EpochRequest, body), headers["idempotency-key"])
                count = conn.execute("SELECT count(*) FROM sessions WHERE experiment_id=?", (identifier,)).fetchone()[0]
                if count == 3 and self.participant is None and not self.activation_pending:
                    self.activation_pending = True
                    self._spawn(self._activate())
            return result
        if method == "GET" and action == "bundle":
            self.broker._role(principal, "auditor")
            if row["phase"] not in {"CLOSED", "RELEASED"} or row["integrity"] != "VALID_WITHIN_PROFILE":
                raise BrokerError("WRONG_PHASE")
            target = self.root / "evidence.zip"
            if not target.is_file() or target.stat().st_size > 16 * 1024 * 1024:
                raise BrokerError("AUDIT_UNAVAILABLE", 503)
            return 200, ZipBody(target.read_bytes())
        if method == "GET" and action == "invalid-evidence":
            self.broker._role(principal, "auditor")
            if row["phase"] != "CLOSED" or row["integrity"] != "INVALID":
                raise BrokerError("WRONG_PHASE")
            target = self.root / "invalid-evidence.zip"
            key_path = self.recovery_directory / (
                self.recovery_authorities["invalid_export"]["key_id"] + "-private.pem"
            )
            key = key_from_file(key_path)
            if target.exists():
                check_path = self.root / (".invalid-evidence-check-" + str(uuid4()) + ".zip")
                try:
                    self.controller.export_invalid_evidence(
                        principal, check_path, self.recovery_authorities["invalid_export"], key
                    )
                    if check_path.read_bytes() != target.read_bytes():
                        raise BrokerError("AUDIT_UNAVAILABLE", 503)
                finally:
                    check_path.unlink(missing_ok=True)
            else:
                self.controller.export_invalid_evidence(
                    principal, target, self.recovery_authorities["invalid_export"], key
                )
            if target.is_symlink() or not target.is_file() or target.stat().st_size > 16 * 1024 * 1024:
                raise BrokerError("AUDIT_UNAVAILABLE", 503)
            return 200, ZipBody(target.read_bytes())
        if method == "GET" and action == "feedback":
            self.broker._role(principal, "red", "blue-human")
            if row["phase"] != "RELEASED":
                return 200, padded_json({"status": "EMBARGOED"}, self.signed_policy.policy.body_bytes)
            if self.mode == "SEALED_BATCH":
                return 200, self._batch_feedback(identifier)
            with closing(self.store.connect()) as conn:
                turns = list(conn.execute("SELECT session_id,turn_id FROM n06_jobs WHERE experiment_id=? ORDER BY admitted_ns,turn_id", (identifier,)))
            values = []
            for turn in turns:
                projection = self.queue.project(self.p["red"], self.ctx, turn["session_id"], turn["turn_id"])
                if projection.status != 200:
                    raise BrokerError("AUDIT_UNAVAILABLE", 503)
                values.append(json.loads(projection.body))
            return 200, {"status": "RELEASED", "items": values}
        if action.startswith("sessions/"):
            if self.mode != "INTERACTIVE" or self.participant is None:
                raise BrokerError("POLICY_NOT_READY", 503)
            with self.lock, closing(self.store.connect()) as conn:
                finishing = conn.execute("SELECT finishing FROM prototype_state WHERE experiment_id=?", (identifier,)).fetchone()[0]
            if method == "POST" and action.endswith("/turns") and finishing:
                # Existing same-key turn retries still project the old reservation.
                with closing(self.store.connect()) as conn:
                    replay = conn.execute("SELECT 1 FROM idempotency WHERE subject_id=? AND experiment_id=? AND action='turns' AND client_key=?", (principal.subject_id, identifier, headers["idempotency-key"])).fetchone()
                if not replay:
                    raise BrokerError("WRONG_PHASE")
            return self.participant.dispatch(principal, method, path, headers, body)
        return control_dispatch(self.broker, principal, method, path, headers, body)

    def _admin(self, principal, identifier, action, request, key):
        self.broker._role(principal, "operator")
        def operation(conn, row):
            expected = {"start": {"SEALED"}, "finish": {"RUNNING", "INVALID"}, "close": {"SCORED", "INVALID"}, "release": {"CLOSED"}, "analysis": {"RELEASED"}}
            recovery_close = (action == "close" and self.controller is not None
                              and (self.recovery_only or self.controller.recovery_admission_blocked))
            if self.recovery_only and action != "close":
                raise BrokerError("POLICY_NOT_READY", 503)
            if recovery_close:
                expected["close"].add("RUNNING")
                recovery_turn = self.recovery_inspection.get("recovery_turn_id")
                if recovery_turn is None and len(self.recovery_verified_turns) == 1:
                    recovery_turn = next(iter(self.recovery_verified_turns))
                ambiguous_recovery_close = (
                    self.recovery_only
                    and self.recovery_inspection.get("recovery_only_action")
                    in {"INVALIDATE_AMBIGUOUS", "CLOSE_INVALID"}
                    and recovery_turn is not None
                )
                pending_close_retry = (
                    self.recovery_only
                    and self.recovery_inspection.get("recovery_only_action") == "RETRY_PENDING_CLOSE"
                )
                invalid_recovery_close = (
                    row["integrity"] == "INVALID" and row["phase"] == "INVALID"
                    and self.controller.recovery_admission_blocked
                )
                if (not ambiguous_recovery_close and not pending_close_retry
                        and not invalid_recovery_close
                        and (not recovery_turn or not self._recovery_close_is_ready(recovery_turn))):
                    raise BrokerError("POLICY_NOT_READY", 503)
                if (self.recovery_only
                        and self.recovery_inspection.get("recovery_only_action") == "RETRY_PENDING_CLOSE"
                        and self.recovery_inspection.get("pending_close_kind") == "PUBLICATION_ACK"):
                    expected["close"].add("CLOSED")
            if row["phase"] not in expected[action] or action == "release" and row["integrity"] != "VALID_WITHIN_PROFILE":
                raise BrokerError("WRONG_PHASE")
            if action == "analysis" and self.request.defense_mode != "POST_HOC":
                raise BrokerError("WRONG_PHASE")
            old_operation = conn.execute(
                "SELECT id,state FROM prototype_operations WHERE experiment_id=? AND action=?",
                (identifier, action),
            ).fetchone()
            if old_operation:
                if self.recovery_only and action == "close":
                    return 202, {"operation_id": old_operation["id"], "status": "ACCEPTED"}
                raise BrokerError("IDEMPOTENCY_CONFLICT")
            op = str(uuid4())
            conn.execute("INSERT INTO prototype_operations(id,experiment_id,action,state) VALUES(?,?,?,'PENDING')", (op, identifier, action))
            if action == "finish":
                conn.execute("UPDATE prototype_state SET finishing=1 WHERE experiment_id=?", (identifier,))
            return 202, {"operation_id": op, "status": "ACCEPTED"}
        with self.lock:
            result = self.broker._mutate(principal, identifier, request, "prototype-" + action, key, f"/v1/experiments/{identifier}/{action}", operation)
            op_id = result[1]["operation_id"]
            if self.recovery_only and action == "close" and not any(
                    task is not None and not task.done() for task in self.tasks):
                with self.store.transaction() as conn:
                    conn.execute(
                        "UPDATE prototype_operations SET state='PENDING',result_json=NULL "
                        "WHERE id=? AND state IN ('RUNNING','FAILED')", (op_id,)
                    )
            with self.store.transaction() as conn:
                claimed = conn.execute("UPDATE prototype_operations SET state='RUNNING' WHERE id=? AND state='PENDING'", (op_id,)).rowcount
            if claimed:
                self._spawn(self._perform(op_id, action, principal))
            return result

    async def _perform(self, op_id, action, principal):
        try:
            async with self.operation_lock:
                if action == "start":
                    await self._start(principal)
                    result = {"phase": "RUNNING"}
                elif action == "finish":
                    await self._finish()
                    result = {"phase": self._row(principal, self.ctx.experiment_id)["phase"]}
                elif action == "close":
                    if (self.recovery_only
                            and self.recovery_inspection.get("recovery_only_action") == "INVALIDATE_AMBIGUOUS"):
                        recovery_turn = self.recovery_inspection["recovery_turn_id"]
                        if recovery_turn not in self.recovery_invalidated_turns:
                            await self.controller.invalidate_unrecoverable_feedback(
                                principal, recovery_turn
                            )
                            self.recovery_invalidated_turns.add(recovery_turn)
                    checkpoint = await self.controller.close(principal)
                    result = {"phase": "CLOSED", "checkpoint": checkpoint.model_dump()}
                    if self._row(principal, self.ctx.experiment_id)["integrity"] == "VALID_WITHIN_PROFILE":
                        events = self.controller.recorder.get_events(self.ctx)
                        self.anchor.verify_events(self.ctx, events)
                        with closing(self.store.connect()) as conn:
                            run = conn.execute(
                                "SELECT witness_json FROM n04_runs WHERE experiment_id=?",
                                (self.ctx.experiment_id,),
                            ).fetchone()
                        if not run or not run[0]:
                            raise DependencyUnavailable("ANCHOR_TERMINAL_CLOSE_MISSING")
                        witness_close = load_wire(SignedWitnessClose, run[0].encode("utf-8"))
                        self.anchor.verify_terminal(
                            self.ctx, checkpoint, witness_close, "VALID_WITHIN_PROFILE"
                        )
                        records = self.anchor.records(self.ctx)
                        verify_anchor_records(
                            records, self.ctx,
                            self.recovery_authorities["anchor"]["public_key_bytes"],
                            self.recovery_authorities["anchor"]["key_id"],
                            self.recovery_authorities["anchor"]["authority_id"],
                        )
                        anchor_bytes = b"".join(canonical_bytes(record) + b"\n" for record in records)
                        anchor_path = self.root / "anchor-records.jsonl"
                        _publish_private_or_match(
                            anchor_path, anchor_bytes, "ANCHOR_RECORD_EXPORT_CONFLICT"
                        )
                        evidence_path = self.root / "evidence.zip"
                        await asyncio.to_thread(
                            _export_private_or_match,
                            evidence_path,
                            lambda target: self.controller.export(self.p["auditor"], target),
                            "EVIDENCE_EXPORT_CONFLICT",
                        )
                        replay_keys = self.controller.vault.private_replay_keys(
                            checkpoint.checkpoint.required_artifacts
                        )
                        replay_bytes = json.dumps(replay_keys).encode()
                        _publish_private_or_match(
                            self.root / "replay-keys.json", replay_bytes,
                            "REPLAY_KEYS_EXPORT_CONFLICT",
                        )
                elif action == "analysis":
                    folder = self.root / "analysis"
                    folder.mkdir(exist_ok=False)
                    with closing(self.store.connect()) as conn:
                        turns = [r[0] for r in conn.execute("SELECT t.id FROM turns t JOIN n04_turns n ON n.turn_id=t.id WHERE t.experiment_id=? AND n.known_execution='EXECUTED' AND n.state='DONE' ORDER BY t.id", (self.ctx.experiment_id,))]
                    receipts = []
                    for turn in turns:
                        receipt = await self.controller.analyze_after_release(principal, turn)
                        self.controller.export_analysis(self.p["auditor"], turn, folder / (turn + ".zip"))
                        receipts.append(receipt)
                    write_private(folder / "replay-keys.json", json.dumps(self.controller.vault.private_replay_keys(tuple(r.receipt.analysis_artifact for r in receipts))).encode())
                    result = {"status": "COMPLETE_POST_RELEASE_OBSERVATIONS", "analyses": [r.model_dump() for r in receipts], "prevention_claim": False}
                else:
                    if self.mode == "INTERACTIVE":
                        with closing(self.store.connect()) as conn:
                            release = conn.execute("SELECT max(release_ns) FROM n06_jobs WHERE experiment_id=?", (self.ctx.experiment_id,)).fetchone()[0]
                        if release is not None:
                            delay = (release - self.queue.clock_ns()) / 1_000_000_000
                            if delay > 0:
                                await asyncio.sleep(delay)
                    result = {"phase": "RELEASED", "release_receipt_id": self.controller.release(principal)}
            state = "DONE"
        except BaseException as exc:
            # Preserve durable execution states; no automatic operation replay.
            self.store.operator_alert("AUDIT_UNAVAILABLE", 503)
            if self.controller is not None and action in {"start", "finish"}:
                self.controller._invalidate()
            result, state = {"code": "AUDIT_UNAVAILABLE", "exception_type": type(exc).__name__}, "FAILED"
        with self.store.transaction() as conn:
            conn.execute("UPDATE prototype_operations SET state=?,result_json=? WHERE id=?", (state, json.dumps(result), op_id))

    async def _start(self, principal):
        recorder = DurableRecorder(self.root / "recorder.sqlite3", self.recorder_key.private_bytes_raw(), "n08-prototype-recorder-001", anchor=self.anchor)
        witness = SQLiteWitnessAuthority(self.root / "witness.sqlite3", self.witness_key.private_bytes_raw(), "n08-prototype-witness-001",
            initialize_if_missing=True, recorder_public_key=self.recorder_key.public_key().public_bytes_raw(), recorder_key_id=recorder.signer_key_id)
        wrapping = os.urandom(32)
        write_private(self.root / "vault-wrapping.key", wrapping)
        vault = ArtifactVault(self.root / "vault", self.ctx, wrapping)
        recovery_authority = self.recovery_authorities["recovery"]
        recovery_key_path = self.recovery_directory / (recovery_authority["key_id"] + "-private.pem")
        recovery_key = key_from_file(recovery_key_path) if recovery_key_path.is_file() else None
        if (recovery_key is not None and recovery_key.public_key().public_bytes_raw()
                != recovery_authority["public_key_bytes"]):
            raise DependencyUnavailable("FEEDBACK_RECOVERY_AUTHORITY_MISMATCH")
        self.controller = PrototypeController(self.broker, recorder, witness, vault, self.runtime, self.corpus,
            recorder_public_key=self.recorder_key.public_key().public_bytes_raw(), witness_public_key=self.witness_key.public_key().public_bytes_raw(), transport_admission=self.admission,
            recovery_authority=recovery_authority,
            recovery_private_key=recovery_key.private_bytes_raw() if recovery_key is not None else None)
        await self.controller.start(principal)
        self.worker = AsyncTurnWorker(self.queue, self.controller, self._resolve)
        if self.mode == "SEALED_BATCH":
            self.batch_task = asyncio.create_task(self._run_batch())

    async def _resolve(self, request, job):
        if request.payload_ref:
            value = self.store.read_payload(request.payload_ref)
            text = value["text"]
        else:
            text = request.text
        candidates = [p for p in self.corpus.records.values() if p.text == text]
        if len(candidates) != 1:
            raise DependencyUnavailable("ADMITTED_REAL_PUBLIC_PAYLOAD_REQUIRED")
        return await self.corpus.resolve(candidates[0].payload_ref)

    async def _activate(self):
        try:
            if self.worker is None or self.admission is None:
                raise DependencyUnavailable("AUTHORITATIVE_START_REQUIRED")
            self.participant = ParticipantGateway(self.p["operator"], self.worker, self.admission.plan.transport,
                self.admission.trust.transport_public_key, self.admission.trust.transport_key_id, admission=self.admission)
            self.pump_task = asyncio.create_task(self.participant.pump())
        finally:
            self.activation_pending = False

    async def _run_batch(self):
        try:
            with self.store.transaction() as conn:
                row = dict(conn.execute("SELECT * FROM experiments WHERE id=?", (self.ctx.experiment_id,)).fetchone())
                conn.execute("UPDATE prototype_state SET batch_state='RUNNING' WHERE experiment_id=?", (self.ctx.experiment_id,))
            plan = self.broker.frozen_batch(row)
            sessions = [self.broker.session(self.p["operator"], self.ctx.experiment_id, EpochRequest(epoch=self.ctx.epoch), "batch-session-" + str(i))[1]["session_id"] for i in range(3)]
            async def lane(index):
                for item in (i for i in plan["items"] if i["lane"] == index):
                    with self.store.transaction() as conn:
                        conn.execute("INSERT INTO prototype_batch_claims VALUES(?,?,'CLAIMED',NULL)", (self.ctx.experiment_id, item["item_id"]))
                    payload = await self.corpus.resolve(item["source_ref"])
                    result = await self.controller.turn(self.p["red"], sessions[index],
                        TurnSubmission(epoch=self.ctx.epoch, turn_index=item["turn_index"], payload_ref=item["artifact_id"]), "batch-" + item["item_id"], payload)
                    with self.store.transaction() as conn:
                        conn.execute("UPDATE prototype_batch_claims SET state='DONE',turn_id=? WHERE experiment_id=? AND item_id=?", (result.turn_id, self.ctx.experiment_id, item["item_id"]))
            results = await asyncio.gather(*(lane(i) for i in range(3)), return_exceptions=True)
            if any(isinstance(r, BaseException) for r in results):
                raise DependencyUnavailable("BATCH_REQUIRES_EXPLICIT_RECOVERY")
            state = "DONE"
        except BaseException:
            self.store.operator_alert("AUDIT_UNAVAILABLE", 503)
            self.controller._invalidate()
            state = "FAILED"
        with self.store.transaction() as conn:
            conn.execute("UPDATE prototype_state SET batch_state=? WHERE experiment_id=?", (state, self.ctx.experiment_id))

    async def _finish(self):
        if self.batch_task is not None:
            await self.batch_task
        if self.participant is not None:
            self.participant.accepting = False
            # Let the pump finish already-admitted work; drain() would cancel it.
            while True:
                with closing(self.store.connect()) as conn:
                    queued = conn.execute("SELECT 1 FROM n06_jobs WHERE experiment_id=? AND state IN ('QUEUED','CLAIMED')", (self.ctx.experiment_id,)).fetchone()
                if not queued and not self.participant.active and not self.worker.tasks:
                    break
                if self.participant.pump_error:
                    raise DependencyUnavailable("FINISH_WORKER_SETTLEMENT_UNPROVEN")
                await asyncio.sleep(.05)
            if not await self.participant.quiesce():
                raise DependencyUnavailable("FINISH_QUIESCENCE_UNPROVEN")
            if self.pump_task:
                await self.pump_task
        with self.store.transaction() as conn:
            unsettled = conn.execute("SELECT 1 FROM turns WHERE experiment_id=? AND state IN ('RESERVED','DISPATCHED')", (self.ctx.experiment_id,)).fetchone()
            if unsettled:
                raise DependencyUnavailable("FINISH_UNSETTLED_TURNS")
            conn.execute("UPDATE experiments SET phase=CASE WHEN integrity='INVALID' THEN 'INVALID' ELSE 'SCORED' END WHERE id=?", (self.ctx.experiment_id,))

    def _batch_feedback(self, identifier):
        with closing(self.store.connect()) as conn:
            rows = list(conn.execute("SELECT c.item_id,n.receipt_json,n.feedback_ref,n.result_json FROM prototype_batch_claims c JOIN n04_turns n ON n.turn_id=c.turn_id WHERE c.experiment_id=? AND c.state='DONE' ORDER BY c.item_id", (identifier,)))
        values = []
        for row in rows:
            opening = self.controller.vault.get(ArtifactRef.model_validate_json(row["feedback_ref"]))
            values.append({"item_id": row["item_id"], "result": json.loads(row["result_json"]),
                "public_reply": base64.b64decode(opening["public_reply_utf8_base64"]).decode(),
                "feedback_receipt": SignedTurnReceipt.model_validate_json(row["receipt_json"]).model_dump()})
        return {"status": "RELEASED", "items": values}

    def listen(self, port=0):
        if self.recovery_only:
            if not self.recovery_only_ready or not self.recovery_preflight_complete:
                raise DependencyUnavailable("STARTUP_RECOVERY_PREFLIGHT_REQUIRED")
        elif self.runtime is None or not self.runtime.started:
            raise DependencyUnavailable("STARTUP_PREFLIGHT_AND_RUNTIME_REQUIRED")
        self.server = Server(("127.0.0.1", port), self.broker, tls_context(self.root / "tls/server.pem", self.root / "tls/server.key", self.root / "tls/ca.pem"), participant_gateway=self)
        self.server_thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.server_thread.start()
        return self.server.server_address[1]

    async def shutdown(self):
        if self.server is not None:
            await asyncio.to_thread(self.server.shutdown)
            self.server.server_close()
            self.server_thread.join(timeout=2)
        if self.participant is not None:
            self.participant.accepting = False
            self.participant.stopped = True
        tasks = [task for task in (self.batch_task, self.pump_task, *tuple(self.tasks)) if task is not None]
        for task in tasks:
            if task is not None and not task.done():
                task.cancel()
        if tasks:
            await asyncio.gather(*tasks, return_exceptions=True)
        if self.worker is not None:
            await self.worker.drain()
        if self.runtime is not None:
            await asyncio.to_thread(self.runtime.stop)
        if self.anchor_process is not None:
            self.anchor_process.stop()

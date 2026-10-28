"""Synthetic-only timing experiment on the real mTLS/queue/evidence path.

The deliberately unsafe gateway is confined to this developer experiment. It
refuses real corpora/models. It is never selectable by the participant service.
Uses the repository's explicit synthetic integration fixtures, not a deploy SDK.
"""

import argparse
import asyncio
import base64
from contextlib import closing
from datetime import datetime, timezone
import json
from pathlib import Path
import random
import sys
import threading
import time
from uuid import uuid4

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT / "tests/integration"))
from test_n04 import SyntheticRuntime, payload
from test_n06_execution import environment

from arena.contracts.api import DefenseDecision, EpochRequest
from arena.contracts.crypto import sha256
from arena.broker.server import Server, tls_context
from arena.execution.lab import LocalMTLSPilot, lab_credentials
from arena.execution.transport import ParticipantGateway
from arena.measurement.statistics import analyze_timing


PROTOCOL = {"schema_version": "arena-n06-synthetic-timing-protocol.v1", "seed": 260622,
    "scope": "SYNTHETIC_LOOPBACK_TIMING_ONLY_NOT_REAL_MODEL_OR_CHANNEL_CAPACITY",
    "selection_campaigns_per_arm": 4, "validation_campaigns_per_arm": 10, "turns_per_campaign": 24,
    "lanes": 3, "labels_per_campaign": {"ALLOW": 12, "BLOCK": 12}, "allow_delay_ms": 200, "block_delay_ms": 10,
    "admission_window_ms": 100, "deadline_ms": 3000, "floor_ms": 3500, "body_bytes": 4096, "poll_ms": 25,
    "observer": "monotonic ns before TLS POST to first terminal TLS GET; rank uses elapsed only",
    "classification_direction": "chosen on selection per arm; unchanged for validation",
    "interval": "95 percentile bootstrap of whole held-out campaigns, 1000 resamples, seed 260622",
    "shaped_envelope": {"point": [.4, .6], "bootstrap_95": [.35, .65]},
    "negative_control_gate": "held-out AUC>=0.8; interval low>0.65; early publications>0; zero errors",
    "exclusions": "NONE; all socket/pipeline failures retained; no silent sample replacement",
    "campaign_independence_established": False, "real_model": False, "public_admission": False}


class UnsafeSyntheticGateway(ParticipantGateway):
    def __init__(self, *args, **kwargs):
        super().__init__(*args, **kwargs)
        if (type(self.controller.runtime) is not SyntheticRuntime or self._signed().policy.run_label != "SYNTHETIC_MOCK"
            or self.controller.runtime.inspect() != {"scope": "SYNTHETIC_UNIT_TEST_NOT_A_RUNTIME_RECEIPT"}):
            raise ValueError("UNSAFE_CONTROL_SYNTHETIC_FIXTURE_ONLY")

    def _signed(self):
        with closing(self.store.connect()) as conn: return self._signed_policy(conn)

    def dispatch(self, principal, method, path, headers, body):
        result = super().dispatch(principal, method, path, headers, body)
        if method != "GET" or result[0] != 202 or "/turns/" not in path: return result
        # The normal dispatcher has already validated identity, ownership and route.
        turn = path.rsplit("/", 1)[1]
        with self.lock, self.store.transaction() as conn:
            row = conn.execute("SELECT * FROM n06_jobs WHERE turn_id=?", (turn,)).fetchone()
            if row["state"] != "AUTHORIZED": return result
            raw = base64.b64decode(self.store.read_payload(row["body_ref"])["body_base64"], validate=True)
            conn.execute("UPDATE n06_jobs SET published=1 WHERE turn_id=?", (turn,))
            return 200, raw


class TimingClient(LocalMTLSPilot):
    """Experiment-only provisioner; production CLI cannot select unsafe gateway."""
    def __init__(self, env, directory, gateway_type):
        self.worker, self.queue, self.controller = env.worker, env.queue, env.controller
        self.contexts = lab_credentials(directory, env.broker, env.p)
        trust = env.admission.trust
        self.gateway = gateway_type(env.p["operator"], env.worker, env.admission.plan.transport,
            trust.transport_public_key, trust.transport_key_id, admission=env.admission)
        self.server = Server(("127.0.0.1", 0), env.broker,
            tls_context(directory / "server.pem", directory / "server.key", directory / "ca.pem"), participant_gateway=self.gateway)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True); self.thread.start()
        self.pump = asyncio.create_task(self.gateway.pump()); self.closed = False


def runtime_setup(runtime):
    runtime.lock["synthetic_timing_fixture"] = {"allow_delay_ms": 200, "block_delay_ms": 10}
    runtime.lock_bytes = json.dumps(runtime.lock).encode()
    async def evaluate(request):
        blocked = request.content.prompt.endswith(" B")
        await asyncio.sleep(.01 if blocked else .2)
        return DefenseDecision(call_token=request.call_token, verdict="BLOCK" if blocked else "ALLOW",
            reason_code="INJECTION_PATTERN" if blocked else "NONE", transform_id=None)
    runtime.evaluate = evaluate


async def campaign(root, arm, phase, number, labels):
    env = await environment(root, lanes=3, sealed_transport=True, runtime_setup=runtime_setup,
        execution_deadline_ms=3000, release_floor_ms=3500)
    env.queue.clock_ns = time.monotonic_ns
    sessions = [env.session]
    for lane in (1, 2):
        _, session = env.broker.session(env.p["operator"], env.ctx.experiment_id, EpochRequest(epoch=env.ctx.epoch), "session-"+str(lane))
        sessions.append(session["session_id"])
    sources = {label: payload("SYNTHETIC_CANARY_"+uuid4().hex + (" B" if label else " A")) for label in (0, 1)}
    async def resolve(request, job):
        item = next(p for p in sources.values() if p.text == request.text)
        return item
    env.worker.resolve_payload = resolve
    gateway_type = UnsafeSyntheticGateway if arm == "UNSHAPED_SYNTHETIC_CONTROL" else ParticipantGateway
    pilot = TimingClient(env, root / "tls", gateway_type)
    rows = []
    async def observe(index):
        lane, label = index%3, labels[index]
        path = f"/v1/experiments/{env.ctx.experiment_id}/sessions/{sessions[lane]}/turns"
        start = time.monotonic_ns(); status = 0; size = 0; release = None; admitted = None; polls = 0; error = None
        try:
            status, raw, _ = await asyncio.to_thread(pilot.request, "red", "POST", path,
                {"epoch": env.ctx.epoch, "turn_index": index//3, "text": sources[label].text}, "timing-"+str(index))
            if status == 202:
                turn = json.loads(raw)["turn_id"]
                with closing(env.store.connect()) as conn:
                    job = conn.execute("SELECT admitted_ns,release_ns FROM n06_jobs WHERE turn_id=?", (turn,)).fetchone()
                    admitted, release = job
                while True:
                    status, raw, _ = await asyncio.to_thread(pilot.request, "red", "GET", path+"/"+turn)
                    polls += 1
                    if status != 202: break
                    if time.monotonic_ns()-start > 8_000_000_000:
                        status = 0; error = "OBSERVER_TIMEOUT"; break
                    await asyncio.sleep(.025)
            size = len(raw)
        except Exception as exc:
            status = 0; error = type(exc).__name__
        end = time.monotonic_ns()
        return dict(arm=arm, phase=phase, campaign=number, index=index, lane=lane, label=label,
            latency_ns=end-start, status=status, body_bytes=size, polls=polls, error_type=error,
            admitted_ns=admitted, release_ns=release, observed_ns=end,
            early_publication=bool(status==200 and release is not None and end<release))
    try:
        for begin in range(0, 24, 3):
            rows.extend(await asyncio.gather(*(observe(i) for i in range(begin, begin+3))))
            with closing(env.store.connect()) as conn:
                until = conn.execute("SELECT unblocks_ns FROM n06_lab_runs").fetchone()[0]
            if until is not None: await asyncio.sleep(max(0, (until-time.monotonic_ns())/1e9)+.02)
        await pilot.close()
        await env.controller.close(env.p["operator"])
        env.controller.release(env.p["operator"])
    finally:
        if not pilot.closed: await pilot.close()
    return rows


async def main_async(output):
    output.mkdir(parents=True, exist_ok=False)
    protocol = dict(PROTOCOL, source_sha256={p.relative_to(ROOT).as_posix(): sha256(p.read_bytes())
        for p in (Path(__file__), ROOT / "src/arena/measurement/statistics.py", ROOT / "tests/integration/test_n06_execution.py")})
    (output / "protocol.json").write_text(json.dumps(protocol, indent=2)+"\n", encoding="ascii")
    rows = []; rng = random.Random(PROTOCOL["seed"])
    with (output / "observations.jsonl").open("x", encoding="ascii") as log:
        for phase, campaigns in (("selection", 4), ("validation", 10)):
            for number in range(campaigns):
                labels = [0, 1]*12; rng.shuffle(labels)
                arms = ["SHAPED", "UNSHAPED_SYNTHETIC_CONTROL"]
                if number%2: arms.reverse()
                for arm in arms:
                    values = await campaign(output / f"{phase}-{number}-{arm}", arm, phase, number, labels)
                    for row in values: log.write(json.dumps(row)+"\n")
                    log.flush(); rows.extend(values)
                    print(json.dumps({"phase": phase, "campaign": number, "arm": arm, "observations": len(values)}), flush=True)
    result = dict(analyze_timing(rows), observed_at_utc=datetime.now(timezone.utc).isoformat(),
        protocol_sha256=sha256((output / "protocol.json").read_bytes()), observations_sha256=sha256((output / "observations.jsonl").read_bytes()))
    (output / "analysis.json").write_text(json.dumps(result, indent=2)+"\n", encoding="ascii")
    print(json.dumps(result), flush=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description=__doc__); parser.add_argument("--output", type=Path, required=True)
    args = parser.parse_args()
    if not args.output.resolve().is_relative_to(ROOT / "artifacts"): raise ValueError("PRIVATE_ARTIFACT_DIRECTORY_REQUIRED")
    asyncio.run(main_async(args.output.resolve()))

"""Real-service acceptance client. Uses the same authenticated routes as clients."""
import asyncio
from contextlib import closing
import http.client
import json
import subprocess
import time
from uuid import uuid4

from arena.integration.controller import ACTOR
from arena.integration.isolation import observe_processing, processing_overlap
from arena.model_runtime import file_digest


def request(service, role, method, action, body=None, key=None):
    route = action if action.startswith("/v1/") else f"/v1/experiments/{service.ctx.experiment_id}/{action}"
    client = http.client.HTTPSConnection("127.0.0.1", service.server.server_address[1], context=service.clients[role], timeout=6)
    try:
        headers = {"Content-Type": "application/json"}
        if key is not None: headers["Idempotency-Key"] = key
        started = time.monotonic_ns()
        client.request(method, route, body=None if body is None else json.dumps(body), headers=headers)
        response = client.getresponse()
        raw = response.read()
        return {"status": response.status, "bytes": len(raw), "body": raw,
            "content_type": response.getheader("Content-Type"), "started_ns": started, "completed_ns": time.monotonic_ns()}
    finally:
        client.close()


async def admin(service, action):
    value = await asyncio.to_thread(request, service, "operator", "POST", action, {"epoch": service.ctx.epoch}, action)
    assert value["status"] == 202
    replay = await asyncio.to_thread(request, service, "operator", "POST", action, {"epoch": service.ctx.epoch}, action)
    assert value["body"] == replay["body"]
    op_id = json.loads(value["body"])["operation_id"]
    end = time.monotonic() + 180
    while time.monotonic() < end:
        result = await asyncio.to_thread(request, service, "operator", "GET", "operations/" + op_id)
        body = json.loads(result["body"])
        if body["state"] in {"DONE", "FAILED"}:
            if body["state"] != "DONE":
                raise AssertionError("ADMIN_OPERATION_FAILED:" + action + ":" + json.dumps(body["result"]))
            return body
        await asyncio.sleep(.1)
    raise AssertionError("ADMIN_OPERATION_SETTLEMENT_TIMEOUT")


async def exercise(service, offline_python):
    async def send(role, method, route, body=None, key=None):
        return await asyncio.to_thread(request, service, role, method, route, body, key)
    deny = await send("red", "POST", "/v1/experiments", service.request.model_dump(), "denied-create")
    assert deny["status"] == 403
    created = await send("operator", "POST", "/v1/experiments", service.request.model_dump(), "create")
    assert created["status"] == 201
    ctx = service.ctx
    order = lambda values: sorted(values, key=lambda p: (len(p.text.encode()), p.payload_ref))
    # Fixed long-form public cases make three-way generation observable without
    # changing sampling, minimum output length, token caps or admission checks.
    # The first shortest-case attempt ended too quickly for a conservative
    # three-way slot overlap and remains a failed acceptance attempt.
    benign_ids = ("benign:34", "benign:48", "benign:99")
    by_id = {p.provenance.record_id: p for p in service.corpus.records.values() if service.corpus.split[p.payload_ref] == "benign"}
    if not all(identifier in by_id for identifier in benign_ids):
        raise AssertionError("FROZEN_LONG_FORM_PUBLIC_CASES_MISSING")
    benign = [by_id[identifier] for identifier in benign_ids]
    harmful = order([p for p in service.corpus.records.values() if service.corpus.split[p.payload_ref] == "harmful"])
    # Main traffic is the actually admitted public JBB corpus, not canary text.
    payloads = benign[:3] + harmful[:3]
    assert len(payloads) == 6
    batch = {"epoch": ctx.epoch, "items": [{"item_id": f"item-{i:03}", "text": p.text} for i, p in enumerate(payloads)]}
    assert (await send("red", "POST", "attacks", batch, "upload"))["status"] == 201
    assert (await send("operator", "POST", "seal", {"epoch": ctx.epoch}, "seal"))["status"] == 200
    assert (await send("red", "POST", "attacks", batch, "post-seal-change"))["status"] == 409
    assert json.loads((await send("blue-human", "GET", "feedback"))["body"])["status"] == "EMBARGOED"
    done, ready, observations = asyncio.Event(), asyncio.Event(), []
    observer = asyncio.create_task(observe_processing(service.runtime, done, observations, ready, max_samples=4000))
    network = []
    try:
        await asyncio.wait_for(ready.wait(), 20)
        await admin(service, "start")
        if service.mode == "INTERACTIVE":
            sessions = []
            for lane in range(3):
                value = await send("operator", "POST", "sessions", {"epoch": ctx.epoch}, "session-" + str(lane))
                assert value["status"] == 201
                sessions.append(json.loads(value["body"])["session_id"])
            deadline = time.monotonic() + 10
            while service.participant is None:
                if time.monotonic() > deadline: raise AssertionError("PARTICIPANT_ACTIVATION_TIMEOUT")
                await asyncio.sleep(.05)
            for wave in range(2):
                async def turn(lane):
                    index = wave * 3 + lane
                    route = f"sessions/{sessions[lane]}/turns"
                    body = {"epoch": ctx.epoch, "turn_index": wave, "text": payloads[index].text}
                    key = "turn-" + str(index)
                    accepted = await send("red", "POST", route, body, key)
                    assert accepted["status"] == 202 and accepted["bytes"] == service.signed_policy.policy.body_bytes
                    replay = await send("red", "POST", route, body, key)
                    assert accepted["body"] == replay["body"]
                    changed = dict(body, text=payloads[(index + 1) % 6].text)
                    assert (await send("red", "POST", route, changed, key))["status"] == 409
                    assert (await send("blue-human", "POST", route, body, "denied-" + str(index)))["status"] == 403
                    poll = route + "/" + json.loads(accepted["body"])["turn_id"]
                    assert (await send("red", "GET", poll))["status"] == 202
                    deadline = time.monotonic() + 75
                    while time.monotonic() < deadline:
                        final = await send("red", "GET", poll)
                        if final["status"] != 202: break
                        await asyncio.sleep(.15)
                    else: raise AssertionError("INTERACTIVE_FEEDBACK_TIMEOUT")
                    assert final["status"] == 200 and final["bytes"] == accepted["bytes"]
                    value = json.loads(final["body"])
                    assert value["public_status"] == "COMPLETED"
                    assert final["completed_ns"] - accepted["started_ns"] >= service.signed_policy.policy.release_floor_ms * 1_000_000
                    assert (await send("red", "GET", poll))["body"] == final["body"]
                    network.append({"lane": lane, "turn_index": wave, "body_bytes": final["bytes"],
                        "admission_status": 202, "pending_status": 202, "final_status": final["status"],
                        "observed_floor_ns": final["completed_ns"] - accepted["started_ns"], "replay_identical": True})
                await asyncio.gather(*(turn(lane) for lane in range(3)))
        else:
            refused = await send("red", "POST", "sessions/" + str(uuid4()) + "/turns",
                {"epoch": ctx.epoch, "turn_index": 0, "text": payloads[0].text}, "no-batch-substitution")
            assert refused["status"] == 503
            assert json.loads((await send("red", "GET", "feedback"))["body"])["status"] == "EMBARGOED"
        await admin(service, "finish")
    finally:
        done.set()
        await observer
    overlap = processing_overlap(observations)
    (service.root / "slot-observations.json").write_bytes((json.dumps(observations) + "\n").encode())
    assert overlap["conservative_overlap_ns"] > 0, "THREE_REAL_PROCESSING_LANES_NOT_OBSERVED"
    assert json.loads((await send("red", "GET", "feedback"))["body"])["status"] == "EMBARGOED"
    await admin(service, "close")
    assert (await send("red", "GET", "bundle"))["status"] == 403
    downloaded = await send("auditor", "GET", "bundle")
    assert downloaded["status"] == 200 and downloaded["content_type"] == "application/zip"
    assert downloaded["body"] == (service.root / "evidence.zip").read_bytes()
    await admin(service, "release")
    analysis = await admin(service, "analysis") if service.request.defense_mode == "POST_HOC" else None
    if service.mode == "SEALED_BATCH":
        feedback = json.loads((await send("red", "GET", "feedback"))["body"])
        assert feedback["status"] == "RELEASED" and len(feedback["items"]) == 6
    with closing(service.store.connect()) as conn:
        run = conn.execute("SELECT * FROM experiments").fetchone()
        assert run["phase"] == "RELEASED" and run["integrity"] == "VALID_WITHIN_PROFILE"
        assert conn.execute("SELECT admitted FROM budgets").fetchone()[0] == 6
        outcomes = [json.loads(row[0]) for row in conn.execute("SELECT result_json FROM turns ORDER BY session_id,turn_index")]
        assert len(outcomes) == 6
    public = service.recorder_key.public_key().public_bytes_raw().hex()
    command = [str(offline_python), "-m", "arena.verifier.cli", "--bundle", str(service.root / "evidence.zip"),
        "--recorder-key", public, "--witness-key", service.witness_key.public_key().public_bytes_raw().hex(),
        "--recorder-key-id", "n08-prototype-recorder-001", "--witness-key-id", "n08-prototype-witness-001",
        "--domain-id", ctx.domain_id, "--experiment-id", ctx.experiment_id, "--epoch", str(ctx.epoch),
        "--manifest-digest", run["public_commitment"], "--defense-mode", service.request.defense_mode, "--broker-actor", ACTOR,
        "--keys-json", str(service.root / "replay-keys.json")]
    if service.mode == "INTERACTIVE":
        command += ["--require-transport-profile", "--transport-profile-key", public, "--transport-profile-key-id", "n08-prototype-recorder-001",
            "--feedback-policy-key", public, "--feedback-policy-key-id", "n08-prototype-recorder-001"]
    else:
        command += ["--require-prototype-batch"]
    if analysis is not None:
        with closing(service.store.connect()) as conn:
            release_id = conn.execute("SELECT release_id FROM n04_runs WHERE experiment_id=?", (ctx.experiment_id,)).fetchone()[0]
        command += ["--expected-release-id", release_id, "--analysis-keys-json", str(service.root / "analysis/replay-keys.json")]
        for value in analysis["result"]["analyses"]:
            command += ["--post-hoc-bundle", str(service.root / "analysis" / (value["receipt"]["turn_id"] + ".zip"))]
    checked = await asyncio.to_thread(subprocess.run, command, capture_output=True)
    (service.root / "offline-verifier.log").write_bytes(checked.stdout + checked.stderr)
    if checked.returncode:
        raise AssertionError("INDEPENDENT_OFFLINE_VERIFIER_REJECTED:" + checked.stdout.decode(errors="replace")[-2000:])
    trace = service.runtime.model.trace
    assert len(trace) == 6 and all(t["execution"] == "EXECUTED" for t in trace)
    return {"schema_version": "arena-prototype-e2e.v1", "result": "PASS_AUTHENTICATED_REAL_PUBLIC_PROTOTYPE",
        "interaction_mode": service.mode, "defense_mode": service.request.defense_mode, "context": ctx.model_dump(), "profile_sha256": file_digest(service.runtime.profile_path),
        "source_commit": subprocess.check_output(["git", "rev-parse", "HEAD"], text=True).strip(),
        "real_model_dispatches": len(trace), "outcomes": outcomes, "network_samples": network,
        "processing_overlap": overlap, "evidence_sha256": file_digest(service.root / "evidence.zip"),
        "offline_verifier_exit_code": checked.returncode, "offline_verifier_log_sha256": file_digest(service.root / "offline-verifier.log"),
        "denial_idempotency_and_embargo_checks_passed": True, "full_t_p_acceptance": False, "cold_resume_authorized": False}

"""Real SQLite/process retry tests. Public synthetic metadata, no inference claims."""

import asyncio
import json
import subprocess
import sys
from uuid import uuid4

from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey
from arena.contracts.common import Context
from arena.contracts.evidence import EventProposal
from arena.recorder.recorder import DurableRecorder


CHILD = """
import asyncio,json,pathlib,sys,os
from arena.contracts.evidence import EventProposal
from arena.recorder.recorder import DurableRecorder
root=pathlib.Path(sys.argv[1]); config=json.loads((root/'fixture.json').read_bytes())
recorder=DurableRecorder(root/'recorder.sqlite3',(root/'fixture.key').read_bytes(),'fixture-recorder')
result=asyncio.run(recorder.append_once(EventProposal.model_validate(config['proposal']),'fixture-broker',config['operation']))
if sys.argv[2]=='lose-ack':os._exit(0)
print(result.model_dump_json())
"""


def test_competing_process_retry_and_lost_ack_commits_once(tmp_path):
    private = Ed25519PrivateKey.generate().private_bytes_raw()
    recorder = DurableRecorder(
        tmp_path / "recorder.sqlite3", private, "fixture-recorder"
    )
    context = Context(domain_id=str(uuid4()), experiment_id=str(uuid4()), epoch=1)
    recorder.register_run(context, "a" * 64, actor_id="fixture-broker")
    proposal = EventProposal(
        **context.model_dump(),
        session_id=None,
        turn_id=None,
        turn_index=None,
        event_type="INTEGRITY_VIOLATION",
        outcome_code="INVALID",
        artifact_ciphertext_refs=(),
        duration_us=0,
    )
    operation = str(uuid4())
    (tmp_path / "fixture.key").write_bytes(private)
    (tmp_path / "fixture.json").write_text(
        json.dumps({"proposal": proposal.model_dump(), "operation": operation})
    )
    lost = subprocess.run(
        [sys.executable, "-c", CHILD, str(tmp_path), "lose-ack"],
        capture_output=True,
        timeout=15,
    )
    assert lost.returncode == 0 and lost.stdout == b""
    children = [
        subprocess.Popen(
            [sys.executable, "-c", CHILD, str(tmp_path), "reply"],
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        for _ in range(2)
    ]
    outputs = []
    for child in children:
        output, error = child.communicate(timeout=15)
        assert child.returncode == 0, error.decode()
        outputs.append(output)
    assert outputs[0] == outputs[1]
    assert len(recorder.get_events(context)) == 1
    assert (
        asyncio.run(
            recorder.append_once(proposal, "fixture-broker", operation)
        ).sequence
        == 1
    )

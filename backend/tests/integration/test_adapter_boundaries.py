"""Adversarial local HTTP responses; these are not real model or cache tests."""

import asyncio
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
from uuid import uuid4

import pytest
from arena.adapters.llama_adapter import LlamaModelAdapter
from arena.contracts.api import TargetRequest
from arena.ports import DependencyUnavailable, TargetNotDispatched


def request(session=None, index=0):
    return TargetRequest(
        domain_id=str(uuid4()),
        experiment_id=str(uuid4()),
        epoch=1,
        attempt_id=str(uuid4()),
        session_id=session or str(uuid4()),
        turn_index=index,
        text="first prompt",
        max_output_tokens=8,
    )


class Fixture:
    def __init__(self, response=None):
        self.requests = []
        self.response = (
            response
            or b'{"content":"prior answer","tokens_evaluated":2,"tokens_predicted":2}'
        )
        owner = self

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = json.loads(self.rfile.read(int(self.headers["Content-Length"])))
                owner.requests.append((self.path, body))
                result = (
                    b'{"tokens":[1,2]}' if self.path == "/tokenize" else owner.response
                )
                self.send_response(200)
                self.send_header("Content-Length", str(len(result)))
                self.end_headers()
                self.wfile.write(result)

            def log_message(self, *args):
                pass

        self.server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        self.adapter = LlamaModelAdapter(
            endpoint_url=f"http://127.0.0.1:{self.server.server_port}", timeout_sec=2
        )

    def close(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join(2)


def test_real_transport_carries_own_history_and_rejects_foreign_context():
    fixture = Fixture()

    async def exercise():
        first = request()
        await fixture.adapter.infer(first)
        second = first.model_copy(
            update={"turn_index": 1, "attempt_id": str(uuid4()), "text": "follow up"}
        )
        await fixture.adapter.infer(second)
        assert "prior answer" in fixture.requests[3][1]["prompt"]
        assert "first prompt" in fixture.requests[3][1]["prompt"]
        with pytest.raises(
            DependencyUnavailable, match="MODEL_SESSION_CONTEXT_MISMATCH"
        ):
            await fixture.adapter.infer(
                second.model_copy(update={"domain_id": str(uuid4()), "turn_index": 2})
            )
        assert len(fixture.requests) == 4

    try:
        asyncio.run(exercise())
    finally:
        fixture.close()


@pytest.mark.parametrize(
    "body",
    [
        b'{"content":"one","content":"two","tokens_evaluated":2,"tokens_predicted":2}',
        b'{"content":"bad budget","tokens_evaluated":2,"tokens_predicted":99}',
        b"x" * 70001,
    ],
    ids=["duplicate-key", "over-token-budget", "oversized-body"],
)
def test_invalid_or_oversized_reply_quarantines_lane(body):
    fixture = Fixture(body)

    async def exercise():
        first = request()
        with pytest.raises(Exception):
            await fixture.adapter.infer(first)
        before = len(fixture.requests)
        with pytest.raises(DependencyUnavailable, match="MODEL_LANE_QUARANTINED"):
            await fixture.adapter.infer(first)
        assert len(fixture.requests) == before

    try:
        asyncio.run(exercise())
    finally:
        fixture.close()


def test_token_cap_rejects_before_generation():
    fixture = Fixture()
    fixture.adapter.input_token_cap = 1

    async def exercise():
        with pytest.raises(TargetNotDispatched):
            await fixture.adapter.infer(request())
        assert [path for path, _ in fixture.requests] == ["/tokenize"]

    try:
        asyncio.run(exercise())
    finally:
        fixture.close()

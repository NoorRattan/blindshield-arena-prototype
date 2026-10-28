"""Tests for local CPU llama.cpp inference adapter and 3-lane session isolation (BAR-5, T-005)."""

from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import threading
import unittest
from uuid import uuid4

from arena.adapters.llama_adapter import LlamaModelAdapter, MODEL_CANDIDATE_CONFIG
from arena.contracts.api import TargetRequest
from arena.ports import DependencyUnavailable, validate_target_binding


class TestLlamaModelAdapter(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.adapter = LlamaModelAdapter(synthetic_mode=True)
        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.epoch = 1

    def test_candidate_metadata_does_not_claim_unverified_pins(self):
        self.assertEqual(MODEL_CANDIDATE_CONFIG["status"], "UNVERIFIED_CANDIDATE")
        self.assertEqual(MODEL_CANDIDATE_CONFIG["candidate"], "Qwen2.5-0.5B-Instruct")
        self.assertIsNone(MODEL_CANDIDATE_CONFIG["artifact_sha256"])
        self.assertIsNone(MODEL_CANDIDATE_CONFIG["tokenizer_sha256"])
        self.assertIsNone(MODEL_CANDIDATE_CONFIG["license"])
        self.assertEqual(MODEL_CANDIDATE_CONFIG["max_output_tokens_cap"], 256)

    def test_real_mode_requires_an_explicit_endpoint(self):
        with self.assertRaises(DependencyUnavailable):
            LlamaModelAdapter()

    async def test_loopback_server_request_uses_id_slot_and_confirms_reset(self):
        received = []

        class Handler(BaseHTTPRequestHandler):
            def do_POST(self):
                body = self.rfile.read(int(self.headers["Content-Length"]))
                received.append((self.path, json.loads(body)))
                if self.path == "/completion":
                    payload = {
                        "content": "local reply",
                        "tokens_evaluated": 2,
                        "tokens_predicted": 2,
                    }
                elif self.path == "/tokenize":
                    payload = {"tokens": [1, 2]}
                elif self.path == "/slots/0?action=erase":
                    payload = {"id_slot": 0, "n_erased": 2}
                else:
                    self.send_error(404)
                    return
                encoded = json.dumps(payload).encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "application/json")
                self.send_header("Content-Length", str(len(encoded)))
                self.end_headers()
                self.wfile.write(encoded)

            def log_message(self, fmt, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        try:
            adapter = LlamaModelAdapter(
                endpoint_url=f"http://127.0.0.1:{server.server_port}",
                timeout_sec=2.0,
            )
            session_id = str(uuid4())
            req = TargetRequest(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=1,
                attempt_id=str(uuid4()),
                session_id=session_id,
                turn_index=0,
                text="local only",
                max_output_tokens=8,
            )
            response = await adapter.infer(req)
            await adapter.reset(session_id)
            self.assertEqual(response.text, "local reply")
            self.assertEqual(received[0][0], "/tokenize")
            self.assertEqual(received[1][1]["id_slot"], 0)
            self.assertNotIn("slot_id", received[1][1])
            self.assertFalse(received[1][1]["cache_prompt"])
            self.assertEqual(received[2][0], "/slots/0?action=erase")
        finally:
            server.shutdown()
            server.server_close()
            thread.join(timeout=2.0)

    async def test_closed_schema_inference(self):
        req = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            attempt_id=str(uuid4()),
            session_id=str(uuid4()),
            turn_index=0,
            text="Hello Qwen, please summarize testing procedures.",
            max_output_tokens=64,
        )
        resp = await self.adapter.infer(req)

        self.assertEqual(resp.attempt_id, req.attempt_id)
        self.assertEqual(resp.session_id, req.session_id)
        self.assertEqual(resp.turn_index, req.turn_index)
        self.assertTrue(resp.output_tokens <= req.max_output_tokens)
        self.assertTrue(len(resp.text) > 0)
        self.assertTrue(resp.duration_us >= 25_000)

        # Confirm target binding holds
        validate_target_binding(req, resp)

    async def test_three_lane_session_isolation_and_continuity_t005(self):
        s1 = str(uuid4())
        s2 = str(uuid4())
        s3 = str(uuid4())

        # Turn 0 in Session 1
        req_s1_t0 = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            attempt_id=str(uuid4()),
            session_id=s1,
            turn_index=0,
            text="Session 1 canary prompt: ALPHA_SECRET",
            max_output_tokens=32,
        )
        await self.adapter.infer(req_s1_t0)
        lane1 = self.adapter.get_assigned_lane(s1)
        self.assertIsNotNone(lane1)
        self.assertEqual(self.adapter.get_lane_turn_count(lane1), 1)

        # Turn 0 in Session 2
        req_s2_t0 = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            attempt_id=str(uuid4()),
            session_id=s2,
            turn_index=0,
            text="Session 2 prompt: BETA_SECRET",
            max_output_tokens=32,
        )
        await self.adapter.infer(req_s2_t0)
        lane2 = self.adapter.get_assigned_lane(s2)
        self.assertIsNotNone(lane2)
        self.assertNotEqual(lane1, lane2)  # Different lanes!

        # Turn 0 in Session 3
        req_s3_t0 = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            attempt_id=str(uuid4()),
            session_id=s3,
            turn_index=0,
            text="Session 3 prompt: GAMMA_SECRET",
            max_output_tokens=32,
        )
        await self.adapter.infer(req_s3_t0)
        lane3 = self.adapter.get_assigned_lane(s3)
        self.assertIsNotNone(lane3)
        self.assertEqual(
            len({lane1, lane2, lane3}), 3
        )  # All 3 lanes assigned distinctly

        # Multi-turn continuity in Session 1
        req_s1_t1 = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
            attempt_id=str(uuid4()),
            session_id=s1,
            turn_index=1,
            text="Session 1 follow up",
            max_output_tokens=32,
        )
        await self.adapter.infer(req_s1_t1)
        self.assertEqual(self.adapter.get_lane_turn_count(lane1), 2)
        # Verify Session 2 lane is unaffected
        self.assertEqual(self.adapter.get_lane_turn_count(lane2), 1)

        # Reset Session 1 (clears Lane 1 context / KV cache)
        await self.adapter.reset(s1)
        self.assertEqual(self.adapter.get_lane_turn_count(lane1), 0)
        # Other lanes remain intact!
        self.assertEqual(self.adapter.get_lane_turn_count(lane2), 1)
        self.assertEqual(self.adapter.get_lane_turn_count(lane3), 1)

    async def test_input_cap_enforcement(self):
        # Text exceeding 65536 bytes
        huge_text = "a" * 65537
        # Note: pydantic Text field has max_length=65536, creating TargetRequest directly with huge_text fails
        from pydantic import ValidationError

        with self.assertRaises(ValidationError):
            TargetRequest(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                attempt_id=str(uuid4()),
                session_id=str(uuid4()),
                turn_index=0,
                text=huge_text,
                max_output_tokens=32,
            )

        # Output tokens > 256 fails validation
        with self.assertRaises(ValidationError):
            TargetRequest(
                domain_id=self.domain_id,
                experiment_id=self.experiment_id,
                epoch=self.epoch,
                attempt_id=str(uuid4()),
                session_id=str(uuid4()),
                turn_index=0,
                text="Normal text",
                max_output_tokens=257,
            )


if __name__ == "__main__":
    unittest.main()

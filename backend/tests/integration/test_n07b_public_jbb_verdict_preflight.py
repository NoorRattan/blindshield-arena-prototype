"""Synthetic unit checks for the public-JBB preflight's safe projection only.

These fixtures do not constitute JBB or defense-runtime evidence.
"""

from __future__ import annotations

import json
from types import SimpleNamespace
import unittest
from uuid import uuid4
import hashlib

from arena.contracts.api import DefenseDecision, PayloadProvenance, ResolvedPayload
from tools.run_n07b_public_jbb_verdict_preflight import (
    DockerEventRecorder,
    aggregate_rows,
    evaluate_public_records,
)
from tools.verify_n07b_public_jbb_verdict_preflight import require_exact_fields, reject_raw_fields


class PreflightProjectionTest(unittest.IsolatedAsyncioTestCase):
    async def test_helper_uses_only_evaluate_and_keeps_fixture_text_out_of_rows(self):
        raw_prompt = "UNIT_FIXTURE_RAW_PROMPT_NO_PUBLIC_EVIDENCE"
        payloads = {}
        split = {}
        for split_name, row_id in (("benign", "benign:unit-0"), ("harmful", "harmful:unit-1")):
            payload_ref = str(uuid4())
            payloads[payload_ref] = ResolvedPayload(
                payload_ref=payload_ref,
                text=raw_prompt + " " + split_name,
                provenance=PayloadProvenance(
                    source_id="UNIT_FIXTURE",
                    immutable_revision="unit-revision",
                    source_sha256="0" * 64,
                    record_id=row_id,
                    license_id="UNIT_ONLY",
                    run_label="SYNTHETIC_MOCK",
                ),
            )
            split[payload_ref] = split_name
        corpus = SimpleNamespace(records=payloads, split=split)

        class Evaluator:
            def __init__(self):
                self.evaluated = 0

            def start(self):
                raise AssertionError("model-start seam must not be called")

            async def evaluate(self, request):
                self.evaluated += 1
                self.assert_input_request(request)
                if "harmful" in request.content.prompt:
                    return DefenseDecision(
                        call_token=request.call_token,
                        verdict="BLOCK",
                        reason_code="INJECTION_PATTERN",
                        transform_id=None,
                    )
                return DefenseDecision(
                    call_token=request.call_token,
                    verdict="ALLOW",
                    reason_code="NONE",
                    transform_id=None,
                )

            @staticmethod
            def assert_input_request(request):
                if request.mode != "INPUT":
                    raise AssertionError("INPUT mode required")

        evaluator = Evaluator()

        class EventRecorderFixture:
            def __init__(self):
                self.index = 0

            async def wait_for_completed_container(self):
                self.index += 1
                suffix = str(self.index).encode("ascii")
                return {
                    "defense_container_id_sha256": hashlib.sha256(b"id" + suffix).hexdigest(),
                    "defense_container_name_sha256": hashlib.sha256(b"name" + suffix).hexdigest(),
                }

        event_fixture = EventRecorderFixture()
        rows = await evaluate_public_records(evaluator, corpus, event_fixture)  # type: ignore[arg-type]
        summary = aggregate_rows(rows)
        self.assertEqual(evaluator.evaluated, 2)
        self.assertEqual(event_fixture.index, 2)
        self.assertEqual(summary["record_count"], 2)
        self.assertTrue(summary["varied_verdicts_observed"])
        encoded = json.dumps(rows, sort_keys=True)
        self.assertNotIn(raw_prompt, encoded)
        self.assertNotIn("benign:unit-0", encoded)
        self.assertNotIn("harmful:unit-1", encoded)
        self.assertEqual(
            {row["verdict"] for row in rows},
            {"ALLOW", "BLOCK"},
        )

    def test_private_verifier_rejects_raw_prompt_fields(self):
        with self.assertRaisesRegex(ValueError, "PRIVATE_OBSERVATION_CONTAINS_RAW_OR_SECRET_FIELD"):
            reject_raw_fields({"records": [{"prompt": "UNIT_FIXTURE_RAW_PROMPT"}]})
        with self.assertRaisesRegex(ValueError, "PRIVATE_OBSERVATION_FIELD_SET_INVALID"):
            require_exact_fields(
                {"mode": "INPUT", "extra": "UNIT_FIXTURE_RAW_PROMPT"},
                {"mode"},
                "PRIVATE_OBSERVATION_FIELD_SET_INVALID",
            )

    async def test_daemon_event_projection_requires_complete_pinned_lifecycle(self):
        image = "sha256:" + "a" * 64
        container_id = "b" * 64
        container_name = "arena-n04-defense-unit-fixture"
        recorder = DockerEventRecorder(image, expected_count=1)
        recorder.listener_started = True
        recorder.process = SimpleNamespace(returncode=0)
        actions = ("create", "attach", "start", "die", "destroy")
        for action in actions:
            attributes = {"name": container_name, "image": image}
            if action == "die":
                attributes["exitCode"] = "0"
            recorder._accept_event({
                "Type": "container",
                "Action": action,
                "Actor": {"ID": container_id, "Attributes": attributes},
            })
        identity = await recorder.wait_for_completed_container()
        trace = await recorder.stop()
        self.assertEqual(trace["result"], "PASS")
        self.assertEqual(trace["observed_container_count"], 1)
        self.assertEqual(trace["action_counts"]["create"], 1)
        self.assertEqual(trace["action_counts"]["start"], 1)
        self.assertEqual(trace["action_counts"]["die"], 1)
        self.assertEqual(trace["action_counts"]["destroy"], 1)
        self.assertEqual(trace["containers"][0]["image_sha256"], hashlib.sha256(image.encode()).hexdigest())
        self.assertEqual(identity["defense_container_id_sha256"], hashlib.sha256(container_id.encode()).hexdigest())
        serialized = json.dumps(trace, sort_keys=True)
        self.assertNotIn(container_id, serialized)
        self.assertNotIn(container_name, serialized)

    async def test_daemon_event_projection_flags_other_container_activity(self):
        recorder = DockerEventRecorder("sha256:" + "a" * 64, expected_count=0)
        recorder.listener_started = True
        recorder.process = SimpleNamespace(returncode=0)
        recorder._accept_event({
            "Type": "container",
            "Action": "start",
            "Actor": {"ID": "c" * 64, "Attributes": {"name": "unrelated-fixture"}},
        })
        trace = await recorder.stop()
        self.assertEqual(trace["result"], "INCOMPLETE")
        self.assertEqual(trace["external_lifecycle_event_count"], 1)


if __name__ == "__main__":
    unittest.main()

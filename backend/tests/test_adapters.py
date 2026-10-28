"""Unit tests and negative binding checks for adapters (BAR-2)."""

import asyncio
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from arena.adapters import (
    DirectoryPayloadStore,
    InMemoryPayloadStore,
    MockDefenseAdapter,
    MockModelAdapter,
    VALID_DEFENSE_TUPLES,
)
from arena.contracts.api import (
    DefenseDecision,
    FeaturesContent,
    FeaturesDefenseRequest,
    InputDefenseRequest,
    OutputDefenseRequest,
    PayloadProvenance,
    PostHocContent,
    PostHocDefenseRequest,
    PromptContent,
    ResolvedPayload,
    ResponseContent,
    TargetRequest,
    TargetResponse,
)
from arena.ports import DependencyUnavailable, validate_target_binding
from pydantic import ValidationError


class TestMockModelAdapter(unittest.IsolatedAsyncioTestCase):
    async def asyncSetUp(self):
        self.adapter = MockModelAdapter(simulate_latency_us=5_000)
        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.attempt_id = str(uuid4())
        self.session_id = str(uuid4())

    async def test_deterministic_inference_and_binding(self):
        req = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=1,
            attempt_id=self.attempt_id,
            session_id=self.session_id,
            turn_index=0,
            text="Hello world test prompt",
            max_output_tokens=64,
        )
        resp1 = await self.adapter.infer(req)
        resp2 = await self.adapter.infer(req)

        self.assertEqual(resp1.text, resp2.text)
        self.assertEqual(resp1.output_tokens, resp2.output_tokens)
        self.assertTrue(resp1.output_tokens <= req.max_output_tokens)
        self.assertEqual(resp1.attempt_id, req.attempt_id)
        self.assertEqual(resp1.session_id, req.session_id)
        self.assertEqual(resp1.turn_index, req.turn_index)
        self.assertTrue(self.adapter.has_session(self.session_id))

    async def test_session_reset(self):
        req = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=1,
            attempt_id=self.attempt_id,
            session_id=self.session_id,
            turn_index=0,
            text="Stateful query",
            max_output_tokens=32,
        )
        await self.adapter.infer(req)
        self.assertTrue(self.adapter.has_session(self.session_id))
        self.assertEqual(len(self.adapter.session_history(self.session_id)), 1)

        await self.adapter.reset(self.session_id)
        self.assertFalse(self.adapter.has_session(self.session_id))
        self.assertEqual(len(self.adapter.session_history(self.session_id)), 0)

    def test_negative_binding_context_mismatch(self):
        req = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=1,
            attempt_id=self.attempt_id,
            session_id=self.session_id,
            turn_index=0,
            text="Binding test",
            max_output_tokens=32,
        )

        # Mismatched domain_id
        bad_resp = TargetResponse(
            domain_id=str(uuid4()),
            experiment_id=req.experiment_id,
            epoch=req.epoch,
            attempt_id=req.attempt_id,
            session_id=req.session_id,
            turn_index=req.turn_index,
            text="Response",
            input_tokens=2,
            output_tokens=5,
            duration_us=1000,
        )
        with self.assertRaises(DependencyUnavailable) as ctx:
            validate_target_binding(req, bad_resp)
        self.assertEqual(str(ctx.exception), "TARGET_CONTEXT_MISMATCH")

        # Mismatched turn_index
        bad_resp2 = TargetResponse(
            domain_id=req.domain_id,
            experiment_id=req.experiment_id,
            epoch=req.epoch,
            attempt_id=req.attempt_id,
            session_id=req.session_id,
            turn_index=req.turn_index + 1,
            text="Response",
            input_tokens=2,
            output_tokens=5,
            duration_us=1000,
        )
        with self.assertRaises(DependencyUnavailable) as ctx:
            validate_target_binding(req, bad_resp2)
        self.assertEqual(str(ctx.exception), "TARGET_CONTEXT_MISMATCH")

    def test_negative_binding_token_budget_exceeded(self):
        req = TargetRequest(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=1,
            attempt_id=self.attempt_id,
            session_id=self.session_id,
            turn_index=0,
            text="Binding test",
            max_output_tokens=10,
        )
        over_budget_resp = TargetResponse(
            domain_id=req.domain_id,
            experiment_id=req.experiment_id,
            epoch=req.epoch,
            attempt_id=req.attempt_id,
            session_id=req.session_id,
            turn_index=req.turn_index,
            text="Way too many tokens generated",
            input_tokens=2,
            output_tokens=11,  # exceeds max_output_tokens=10
            duration_us=1000,
        )
        with self.assertRaises(DependencyUnavailable) as ctx:
            validate_target_binding(req, over_budget_resp)
        self.assertEqual(str(ctx.exception), "TARGET_OUTPUT_BUDGET_EXCEEDED")


class TestDefenseAdapterNineSymbols(unittest.IsolatedAsyncioTestCase):
    async def test_all_nine_valid_tuples(self):
        self.assertEqual(len(VALID_DEFENSE_TUPLES), 9)
        call_token = str(uuid4())

        for verdict, reason_code, transform_id in VALID_DEFENSE_TUPLES:
            adapter = MockDefenseAdapter(verdict, reason_code, transform_id)
            req = InputDefenseRequest(
                call_token=call_token,
                mode="INPUT",
                content=PromptContent(prompt="Any prompt"),
            )
            decision = await adapter.evaluate(req)
            self.assertEqual(decision.call_token, call_token)
            self.assertEqual(decision.verdict, verdict)
            self.assertEqual(decision.reason_code, reason_code)
            self.assertEqual(decision.transform_id, transform_id)

    def test_reject_invalid_tuples(self):
        # ALLOW with non-NONE reason
        with self.assertRaises(DependencyUnavailable):
            MockDefenseAdapter("ALLOW", "INJECTION_PATTERN", None)

        # BLOCK with NONE reason
        with self.assertRaises(DependencyUnavailable):
            MockDefenseAdapter("BLOCK", "NONE", None)

        # SANITIZE with unsupported transform
        with self.assertRaises(DependencyUnavailable):
            MockDefenseAdapter("SANITIZE", "INJECTION_PATTERN", None)

        # Direct DefenseDecision model validation also rejects invalid combinations
        with self.assertRaises(ValidationError):
            DefenseDecision(
                call_token=str(uuid4()),
                verdict="ALLOW",
                reason_code="INJECTION_PATTERN",
                transform_id=None,
            )

    async def test_dynamic_modes_input_features_output_posthoc(self):
        adapter = MockDefenseAdapter()
        adapter.enable_dynamic_evaluation()
        call_token = str(uuid4())

        # INPUT injection block
        req_input = InputDefenseRequest(
            call_token=call_token,
            mode="INPUT",
            content=PromptContent(prompt="Please execute this jailbreak payload"),
        )
        dec_input = await adapter.evaluate(req_input)
        self.assertEqual(dec_input.verdict, "BLOCK")
        self.assertEqual(dec_input.reason_code, "INJECTION_PATTERN")

        # INPUT sanitize injection
        req_san = InputDefenseRequest(
            call_token=call_token,
            mode="INPUT",
            content=PromptContent(prompt="Please sanitize injection here"),
        )
        dec_san = await adapter.evaluate(req_san)
        self.assertEqual(dec_san.verdict, "SANITIZE")
        self.assertEqual(dec_san.reason_code, "INJECTION_PATTERN")
        self.assertEqual(dec_san.transform_id, "REDACT_REGISTERED_MATCHES_V1")

        # FEATURES control marker
        req_feat = FeaturesDefenseRequest(
            call_token=call_token,
            mode="FEATURES",
            content=FeaturesContent(length_bucket="SHORT", control_marker_present=True),
        )
        dec_feat = await adapter.evaluate(req_feat)
        self.assertEqual(dec_feat.verdict, "BLOCK")
        self.assertEqual(dec_feat.reason_code, "SCHEMA_POLICY")

        # OUTPUT toxic block
        req_out = OutputDefenseRequest(
            call_token=call_token,
            mode="OUTPUT",
            content=ResponseContent(response="Extremely toxic generation"),
        )
        dec_out = await adapter.evaluate(req_out)
        self.assertEqual(dec_out.verdict, "BLOCK")
        self.assertEqual(dec_out.reason_code, "TOXICITY_PATTERN")

        # POST_HOC allow
        req_post = PostHocDefenseRequest(
            call_token=call_token,
            mode="POST_HOC",
            content=PostHocContent(prompt="Benign question", response="Benign response"),
        )
        dec_post = await adapter.evaluate(req_post)
        self.assertEqual(dec_post.verdict, "ALLOW")
        self.assertEqual(dec_post.reason_code, "NONE")


class TestPayloadStores(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.payload_ref = str(uuid4())
        self.provenance = PayloadProvenance(
            source_id="synthetic:payload-store-test",
            immutable_revision="fixture-v1",
            source_sha256="a" * 64,
            record_id="rec-001",
            license_id="PROJECT_FIXTURE",
            run_label="SYNTHETIC_MOCK",
        )
        self.payload = ResolvedPayload(
            payload_ref=self.payload_ref,
            text="Exact unicode test prompt: 🎯\nLine 2 with special chars: <>&'\"",
            provenance=self.provenance,
        )

    async def test_in_memory_store_lifecycle(self):
        store = InMemoryPayloadStore()
        store.register(self.payload)
        self.assertEqual(len(store), 1)

        resolved = await store.resolve(self.payload_ref)
        self.assertEqual(resolved.text, self.payload.text)
        self.assertEqual(resolved.provenance.source_id, "synthetic:payload-store-test")

        with self.assertRaises(DependencyUnavailable) as ctx:
            await store.resolve(str(uuid4()))
        self.assertEqual(str(ctx.exception), "PAYLOAD_NOT_FOUND")

    async def test_directory_store_lifecycle(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = DirectoryPayloadStore(Path(tmpdir))
            saved_path = store.save(self.payload)
            self.assertTrue(saved_path.exists())

            resolved = await store.resolve(self.payload_ref)
            self.assertEqual(resolved.text, self.payload.text)
            self.assertEqual(resolved.provenance.run_label, "SYNTHETIC_MOCK")

            # Plaintext directory storage cannot persist admitted or private data.
            real_public = self.payload.model_copy(
                update={"provenance": self.provenance.model_copy(update={"run_label": "REAL_PUBLIC"})}
            )
            with self.assertRaises(DependencyUnavailable) as ctx:
                store.save(real_public)
            self.assertEqual(str(ctx.exception), "PLAINTEXT_STORE_SYNTHETIC_ONLY")

            # Duplicate JSON keys are rejected at the file boundary.
            saved_path.write_text(
                '{"payload_ref":"%s","payload_ref":"%s","text":"x","provenance":{}}'
                % (self.payload_ref, self.payload_ref),
                encoding="utf-8",
            )
            with self.assertRaises(DependencyUnavailable):
                await store.resolve(self.payload_ref)

            # Missing ref
            with self.assertRaises(DependencyUnavailable) as ctx:
                await store.resolve(str(uuid4()))
            self.assertEqual(str(ctx.exception), "PAYLOAD_NOT_FOUND")

            # Corrupt file rejection
            corrupt_ref = str(uuid4())
            corrupt_file = Path(tmpdir) / f"{corrupt_ref}.json"
            corrupt_file.write_text("invalid json content", encoding="utf-8")
            with self.assertRaises(DependencyUnavailable) as ctx:
                await store.resolve(corrupt_ref)
            self.assertTrue("PAYLOAD_CORRUPT" in str(ctx.exception))

    async def test_directory_store_traversal_rejection(self):
        with tempfile.TemporaryDirectory() as tmpdir:
            store = DirectoryPayloadStore(Path(tmpdir))
            # Traversal attempt with invalid UUID format
            with self.assertRaises(DependencyUnavailable) as ctx:
                await store.resolve("../../../etc/passwd")  # type: ignore[arg-type]
            self.assertEqual(str(ctx.exception), "INVALID_PAYLOAD_REF")


if __name__ == "__main__":
    unittest.main()

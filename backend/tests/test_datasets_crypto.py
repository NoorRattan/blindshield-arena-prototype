"""Tests for dataset catalog, AES-256-GCM storage, and hiding commitments (BAR-6, T-017)."""

import os
from pathlib import Path
import tempfile
import unittest
from uuid import uuid4

from arena.adapters.payload_store import DirectoryPayloadStore, InMemoryPayloadStore
from arena.contracts.common import Context
from arena.data import (
    SYNTHETIC_CATALOG,
    PrivateDataGate,
    create_hiding_commitment,
    decrypt_payload_artifact,
    encrypt_payload_artifact,
    generate_jbb_shaped_synthetic_fixture,
    verify_hiding_commitment,
)
from arena.ports import DependencyUnavailable


class TestDatasetAndCrypto(unittest.TestCase):
    def setUp(self):
        self.domain_id = str(uuid4())
        self.experiment_id = str(uuid4())
        self.epoch = 1
        self.context = Context(
            domain_id=self.domain_id,
            experiment_id=self.experiment_id,
            epoch=self.epoch,
        )

    def test_jbb_shaped_fixture_is_labeled_synthetic_and_resolves(self):
        records = generate_jbb_shaped_synthetic_fixture()
        self.assertEqual(len(records), 100)
        self.assertEqual(
            [record.payload_ref for record in records],
            [record.payload_ref for record in generate_jbb_shaped_synthetic_fixture()],
        )
        self.assertNotEqual(
            records[0].payload_ref,
            generate_jbb_shaped_synthetic_fixture(seed=43)[0].payload_ref,
        )

        # 50 harmful and 50 benign
        harmful_recs = [r for r in records if "harmful" in r.record_id]
        benign_recs = [r for r in records if "benign" in r.record_id]
        self.assertEqual(len(harmful_recs), 50)
        self.assertEqual(len(benign_recs), 50)

        # These generated prompts are synthetic fixtures, never acquired JBB data.
        for r in records:
            self.assertEqual(r.license_id, SYNTHETIC_CATALOG["license_id"])
            self.assertEqual(r.source_id, SYNTHETIC_CATALOG["source_id"])
            self.assertEqual(r.immutable_revision, SYNTHETIC_CATALOG["immutable_revision"])
            self.assertEqual(r.run_label, "SYNTHETIC_MOCK")
            self.assertEqual(r.to_resolved_payload().provenance.run_label, "SYNTHETIC_MOCK")

        # Ingest into InMemoryPayloadStore
        store = InMemoryPayloadStore()
        for r in records:
            store.register(r.to_resolved_payload())
        self.assertEqual(len(store), 100)

    def test_private_data_policy_gate(self):
        gate = PrivateDataGate()
        # Public data permitted
        gate.verify_admission("REAL_PUBLIC")
        gate.verify_admission("SYNTHETIC_MOCK")

        # Private data blocked by default
        with self.assertRaises(DependencyUnavailable) as ctx:
            gate.verify_admission("AUTHORIZED_PRIVATE")
        self.assertTrue("PRIVATE_DATA_GATE_CLOSED" in str(ctx.exception))

        # A string is not proof of owner authorization; a trusted verifier is required.
        with self.assertRaises(DependencyUnavailable):
            gate.authorize("owner_authorized_sign_off_token_123")
        authorized_gate = PrivateDataGate(
            authorization_verifier=lambda token: token == "verified-owner-proof"
        )
        with self.assertRaises(DependencyUnavailable):
            authorized_gate.authorize("made-up-token")
        authorized_gate.authorize("verified-owner-proof")
        authorized_gate.verify_admission("AUTHORIZED_PRIVATE")  # permitted only by the injected verifier

        # Revoke
        gate.revoke()
        with self.assertRaises(DependencyUnavailable):
            gate.verify_admission("AUTHORIZED_PRIVATE")

    def test_aes_256_gcm_artifact_encryption_and_aad_binding(self):
        plaintext = b"Classified attack corpus raw string"
        art_id = str(uuid4())

        key, blob, sha = encrypt_payload_artifact(
            plaintext=plaintext,
            context=self.context,
            artifact_id=art_id,
            classification="PRIVATE_PAYLOAD",
        )
        self.assertEqual(len(key), 32)
        self.assertTrue(len(blob) > len(plaintext))
        self.assertEqual(len(sha), 64)

        # Successful decryption
        decrypted = decrypt_payload_artifact(
            ciphertext_blob=blob,
            key=key,
            context=self.context,
            artifact_id=art_id,
            classification="PRIVATE_PAYLOAD",
        )
        self.assertEqual(decrypted, plaintext)

        # Negative test 1: Ciphertext tampering
        corrupted_blob = bytearray(blob)
        corrupted_blob[-1] ^= 0xFF
        with self.assertRaises(Exception):
            decrypt_payload_artifact(
                ciphertext_blob=bytes(corrupted_blob),
                key=key,
                context=self.context,
                artifact_id=art_id,
            )

        # Negative test 2: Context AAD mismatch (different experiment_id)
        other_context = Context(
            domain_id=self.domain_id,
            experiment_id=str(uuid4()),
            epoch=self.epoch,
        )
        with self.assertRaises(Exception):
            decrypt_payload_artifact(
                ciphertext_blob=blob,
                key=key,
                context=other_context,
                artifact_id=art_id,
            )

    def test_hiding_commitments_and_rainbow_table_protection(self):
        prompt = "How to bypass network safety filter"

        # Generate two commitments for the exact same prompt
        c1, nonce1 = create_hiding_commitment(prompt)
        c2, nonce2 = create_hiding_commitment(prompt)

        # Due to 256-bit random nonces, commitments are completely distinct!
        self.assertNotEqual(c1, c2)
        self.assertNotEqual(nonce1, nonce2)

        # Verify openings
        self.assertTrue(verify_hiding_commitment(c1, prompt, nonce1))
        self.assertTrue(verify_hiding_commitment(c2, prompt, nonce2))

        # Tampered content fails
        self.assertFalse(verify_hiding_commitment(c1, "Different prompt", nonce1))

        # Tampered nonce fails
        bad_nonce = bytearray(nonce1)
        bad_nonce[0] ^= 0xFF
        self.assertFalse(verify_hiding_commitment(c1, prompt, bytes(bad_nonce)))


if __name__ == "__main__":
    unittest.main()

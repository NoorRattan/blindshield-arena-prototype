"""Offline adapter for the actual arena-corpus-prep.v1 encrypted public preparation."""

import base64
import csv
import io
import json
import re
from pathlib import Path
from uuid import UUID, uuid5

from cryptography.hazmat.primitives.ciphers.aead import AESGCM
from arena.contracts.api import PayloadProvenance, ResolvedPayload
from arena.contracts.crypto import sha256
from arena.ports import DependencyUnavailable


class PreparedPublicCorpus:
    def __init__(
        self, root: Path, receipt: Path, key_file: Path, expected_receipt_sha256: str
    ):
        raw = receipt.read_bytes()
        if sha256(raw) != expected_receipt_sha256:
            raise DependencyUnavailable("CORPUS_RECEIPT_MISMATCH")
        metadata = json.loads(raw)
        if (
            metadata.get("schema") != "arena-corpus-prep.v1"
            or metadata.get("license_basis")
            != "pinned first-party MIT cards inspected; preserve attribution/cards"
        ):
            raise DependencyUnavailable("CORPUS_NOT_ADMITTED")
        keys = json.loads(key_file.read_bytes())
        refs = {item["artifact_id"]: item for item in metadata["artifacts"]}

        def open_artifact(identifier):
            # UUID construction prevents a receipt from selecting arbitrary files.
            if str(UUID(identifier)) != identifier:
                raise DependencyUnavailable("CORPUS_REFERENCE_INVALID")
            ref, secret = refs[identifier], keys[identifier]
            ciphertext = (Path(root) / f"{identifier}.aesgcm").read_bytes()
            if (
                sha256(ciphertext) != ref["ciphertext_sha256"]
                or len(ciphertext) != ref["bytes"]
            ):
                raise DependencyUnavailable("CORPUS_CIPHERTEXT_CHANGED")
            aad = base64.b64decode(secret["aad_b64"], validate=True)
            binding = json.loads(aad)
            if binding != {
                "schema": "arena-corpus-prep.v1",
                "artifact_id": identifier,
                "classification": "PUBLIC_BENCHMARK_PRIVATE_SELECTION",
                **ref["context"],
            }:
                raise DependencyUnavailable("CORPUS_AAD_MISMATCH")
            return AESGCM(base64.b64decode(secret["key_b64"], validate=True)).decrypt(
                base64.b64decode(secret["nonce_b64"], validate=True), ciphertext, aad
            )

        # Recheck preserved cards and exact source bytes; never infer rights from a code license.
        for item in metadata["artifacts"]:
            if item["context"].get("role") == "license_card":
                header = open_artifact(item["artifact_id"]).decode().split("---", 2)[1]
                if (
                    re.search(r"^license:\s*['\"]?mit['\"]?\s*$", header, re.M | re.I)
                    is None
                ):
                    raise DependencyUnavailable("CORPUS_LICENSE_CHANGED")
        sources = {}
        for source in metadata["sources"]:
            source_bytes = open_artifact(source["encrypted_source_artifact"])
            if sha256(source_bytes) != source["sha256"]:
                raise DependencyUnavailable("CORPUS_SOURCE_CHANGED")
            if source["dataset"] == "JailbreakBench/JBB-Behaviors":
                sources[source["file"]] = {
                    **source,
                    "rows": list(
                        csv.DictReader(io.StringIO(source_bytes.decode("utf-8-sig")))
                    ),
                }
        self.records = {}
        self.split = {}
        normalized = open_artifact(metadata["normalized_artifact_id"])
        for line in normalized.splitlines():
            record = json.loads(line)
            if record["source"] != "jbb":
                continue  # Other corpora need their own task/rights admission.
            source = sources[f"data/{record['split']}-behaviors.csv"]
            if (
                record["revision"] != source["revision"]
                or record["canary_instrumented"] is not False
            ):
                raise DependencyUnavailable("CORPUS_PROVENANCE_MISMATCH")
            index = record["source_row_index"]
            if (
                type(index) is not int
                or not 0 <= index < len(source["rows"])
                or source["rows"][index]["Goal"] != record["prompt"]
            ):
                raise DependencyUnavailable("CORPUS_RECORD_LINEAGE_MISMATCH")
            record_id = f"{record['split']}:{record['source_row_index']}"
            identifier = str(
                uuid5(
                    UUID("93f5bbd8-71bf-4f88-b6cc-cac8b07c429d"),
                    record["revision"] + ":" + record_id,
                )
            )
            payload = ResolvedPayload(
                payload_ref=identifier,
                text=record["prompt"],
                provenance=PayloadProvenance(
                    source_id="JBB-Behaviors",
                    immutable_revision=record["revision"],
                    source_sha256=source["sha256"],
                    record_id=record_id,
                    license_id="MIT",
                    run_label="REAL_PUBLIC",
                ),
            )
            if identifier in self.records:
                raise DependencyUnavailable("CORPUS_DUPLICATE_RECORD")
            self.records[identifier] = payload
            self.split[identifier] = record["split"]
        if len(self.records) != metadata["normalized_count"]:
            raise DependencyUnavailable("CORPUS_NORMALIZATION_INCOMPLETE")
        self.receipt_sha256 = expected_receipt_sha256

    async def resolve(self, payload_ref):
        if payload_ref not in self.records:
            raise DependencyUnavailable("PAYLOAD_NOT_FOUND")
        return self.records[payload_ref]

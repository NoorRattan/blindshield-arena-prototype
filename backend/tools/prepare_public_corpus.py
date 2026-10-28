"""Prepare pinned public benchmark files as encrypted local artifacts.

Requires an existing cryptography install; does not install packages. No prompts
or keys are printed. Gandalf Parquet normalization needs optional pyarrow; source
bytes can be prepared without claiming they have been normalized/evaluated.
"""

import argparse
from datetime import datetime, timedelta, timezone
import base64
import csv
import hashlib
import io
import json
import os
import random
import secrets
import urllib.parse
import urllib.request
import uuid
from pathlib import Path


SOURCES = {
    "jbb": ("JailbreakBench/JBB-Behaviors", "886acc352a31533ffbcf4ef22c744658688086fc"),
    "gandalf": (
        "Lakera/gandalf_ignore_instructions",
        "04737b65e90a6794ec227012e4a255a7def6344b",
    ),
}
GANDALF_TEST = "data/test-00000-of-00001-bc92128b9288a6d1.parquet"
LIMIT = 16 * 1024 * 1024


def sha(data):
    return hashlib.sha256(data).hexdigest()


def checked_origin(url):
    parsed = urllib.parse.urlparse(url)
    host = (parsed.hostname or "").lower()
    if parsed.scheme != "https" or not any(
        host == suffix or host.endswith("." + suffix)
        for suffix in ("huggingface.co", "hf.co", "xethub.hf.co")
    ):
        raise ValueError("Unapproved download origin")


class SafeRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        checked_origin(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def fetch(dataset, revision, filename):
    url = (
        "https://huggingface.co/datasets/"
        + dataset
        + "/resolve/"
        + revision
        + "/"
        + filename
    )
    checked_origin(url)
    opener = urllib.request.build_opener(SafeRedirect)
    with opener.open(url, timeout=30) as reply:
        data = reply.read(LIMIT + 1)
        if len(data) > LIMIT:
            raise ValueError("Source exceeds byte cap")
    return data


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--key-file", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--per-split", type=int, default=50)
    args = parser.parse_args()
    if not 1 <= args.per_split <= 1000:
        raise ValueError("Subset cap must be 1..1000")
    if args.output.exists() or args.key_file.exists() or args.receipt.exists():
        raise ValueError("Refusing to overwrite an existing preparation")
    from cryptography.hazmat.primitives.ciphers.aead import AESGCM

    # Acquire and inspect pinned cards before any dataset bytes are admitted.
    cards = {k: fetch(*source, "README.md") for k, source in SOURCES.items()}
    for card in cards.values():
        header = card.decode("utf-8").split("---", 2)[1].lower()
        if (
            "license:" not in header
            or "mit" not in header.split("license:", 1)[1].splitlines()[0]
        ):
            raise ValueError("Pinned license metadata differs from reviewed MIT card")
    args.output.mkdir(parents=True, mode=0o700)
    args.key_file.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    args.receipt.parent.mkdir(parents=True, exist_ok=True)
    secret_records, artifact_records, sources, records = {}, [], [], []
    selection_seed = secrets.randbits(128)
    rng = random.Random(selection_seed)

    def store(data, context):
        artifact_id = str(uuid.uuid4())
        key, nonce = secrets.token_bytes(32), secrets.token_bytes(12)
        aad = json.dumps(
            {
                "schema": "arena-corpus-prep.v1",
                "artifact_id": artifact_id,
                "classification": "PUBLIC_BENCHMARK_PRIVATE_SELECTION",
                **context,
            },
            sort_keys=True,
            separators=(",", ":"),
        ).encode()
        encrypted = AESGCM(key).encrypt(nonce, data, aad)
        (args.output / (artifact_id + ".aesgcm")).write_bytes(encrypted)
        secret_records[artifact_id] = {
            "key_b64": base64.b64encode(key).decode(),
            "nonce_b64": base64.b64encode(nonce).decode(),
            "aad_b64": base64.b64encode(aad).decode(),
        }
        artifact_records.append(
            {
                "artifact_id": artifact_id,
                "ciphertext_sha256": sha(encrypted),
                "bytes": len(encrypted),
                "context": context,
            }
        )
        return artifact_id

    for label, (dataset, revision) in SOURCES.items():
        store(
            cards[label],
            {"dataset": dataset, "revision": revision, "role": "license_card"},
        )
    for split, filename in (
        ("harmful", "data/harmful-behaviors.csv"),
        ("benign", "data/benign-behaviors.csv"),
    ):
        dataset, revision = SOURCES["jbb"]
        data = fetch(dataset, revision, filename)
        source_id = store(
            data, {"dataset": dataset, "revision": revision, "file": filename}
        )
        rows = list(csv.DictReader(io.StringIO(data.decode("utf-8-sig"))))
        if not rows or "Goal" not in rows[0]:
            raise ValueError("Unexpected JBB schema")
        selected = rng.sample(list(enumerate(rows)), min(args.per_split, len(rows)))
        for index, row in selected:
            records.append(
                {
                    "source": "jbb",
                    "revision": revision,
                    "split": split,
                    "source_row_index": index,
                    "prompt": row["Goal"],
                    "category": row.get("Category"),
                    "canary_instrumented": False,
                }
            )
        sources.append(
            {
                "dataset": dataset,
                "revision": revision,
                "file": filename,
                "sha256": sha(data),
                "rows_parsed": len(rows),
                "selected_count": len(selected),
                "encrypted_source_artifact": source_id,
            }
        )
    dataset, revision = SOURCES["gandalf"]
    data = fetch(dataset, revision, GANDALF_TEST)
    source_id = store(
        data, {"dataset": dataset, "revision": revision, "file": GANDALF_TEST}
    )
    gandalf_status = "ENCRYPTED_SOURCE_ONLY_PYARROW_UNAVAILABLE"
    try:
        import pyarrow.parquet as pq

        rows = pq.read_table(io.BytesIO(data)).to_pylist()
        for index, row in rng.sample(
            list(enumerate(rows)), min(args.per_split, len(rows))
        ):
            records.append(
                {
                    "source": "gandalf",
                    "revision": revision,
                    "split": "test",
                    "source_row_index": index,
                    "prompt": row["text"],
                    "category": "prompt_injection",
                    "canary_instrumented": False,
                }
            )
        gandalf_status = "NORMALIZED"
    except ImportError:
        pass
    sources.append(
        {
            "dataset": dataset,
            "revision": revision,
            "file": GANDALF_TEST,
            "sha256": sha(data),
            "encrypted_source_artifact": source_id,
            "normalization_status": gandalf_status,
        }
    )
    normalized = "\n".join(
        json.dumps(row, ensure_ascii=False) for row in records
    ).encode("utf-8")
    normalized_id = store(normalized, {"role": "normalized_selected_records"})
    store(
        json.dumps(
            {
                "selection_seed": selection_seed,
                "normalized_plaintext_sha256": sha(normalized),
            }
        ).encode(),
        {"role": "private_selection_manifest"},
    )
    # Preparation custody only: Windows ACL/runtime mounts still need preflight.
    fd = os.open(args.key_file, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(fd, "w", encoding="utf-8") as stream:
        json.dump(secret_records, stream)
    receipt = {
        "schema": "arena-corpus-prep.v1",
        "as_of": datetime.now(timezone(timedelta(hours=5, minutes=30)))
        .date()
        .isoformat(),
        "scope": "public dataset preparation only; no model/evaluation/arena security test",
        "sources": sources,
        "normalized_count": len(records),
        "normalized_artifact_id": normalized_id,
        "artifacts": artifact_records,
        "plaintext_written_to_disk": False,
        "signed_run_manifest": False,
        "license_basis": "pinned first-party MIT cards inspected; preserve attribution/cards",
        "key_custody_status": "LOCAL_PREPARATION_ONLY_RUNTIME_ACLS_UNVERIFIED",
        "gandalf_status": gandalf_status,
    }
    args.receipt.write_text(json.dumps(receipt, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "normalized_count": len(records),
                "gandalf_status": gandalf_status,
                "receipt": str(args.receipt),
                "keys_printed": False,
                "prompts_printed": False,
            }
        )
    )


if __name__ == "__main__":
    main()

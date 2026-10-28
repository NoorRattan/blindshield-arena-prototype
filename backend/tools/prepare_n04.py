"""Prepare pinned CPU model/images; runtime has no downloads or automatic pulls.

Run from backend/ with its isolated Python. Existing files are reused only after
checksum verification. No cloud account, global ML change, corpus upload or training.
"""

import argparse
import hashlib
import json
from pathlib import Path
import subprocess
from urllib.parse import urlsplit
from urllib.request import HTTPRedirectHandler, ProxyHandler, build_opener

from arena.contracts.crypto import sha256
from arena.integration.types import AdmissionLock
from arena.integration.runtime import runtime_source_hashes


ROOT = Path(__file__).resolve().parents[1]


def allowed_origin(url):
    parsed = urlsplit(url)
    host = parsed.hostname or ""
    if (
        parsed.scheme != "https"
        or parsed.username
        or parsed.password
        or not (
            host == "huggingface.co"
            or host.endswith(".hf.co")
            or host.endswith(".xethub.hf.co")
        )
    ):
        raise ValueError("UNAPPROVED_PREPARATION_ORIGIN")


class Redirects(HTTPRedirectHandler):
    def redirect_request(self, req, fp, code, msg, headers, newurl):
        allowed_origin(newurl)
        return super().redirect_request(req, fp, code, msg, headers, newurl)


def file_digest(path):
    result = hashlib.sha256()
    with path.open("rb") as stream:
        while chunk := stream.read(1048576):
            result.update(chunk)
    return result.hexdigest()


def acquire(path, url, expected, limit, enabled):
    if path.exists():
        if file_digest(path) != expected:
            raise ValueError("EXISTING_PREPARATION_BYTES_MISMATCH")
        return
    if not enabled:
        raise ValueError("MISSING_LOCAL_ARTIFACT_USE_EXPLICIT_DOWNLOAD_PREPARATION")
    allowed_origin(url)
    partial = path.with_suffix(path.suffix + ".partial")
    opener = build_opener(ProxyHandler({}), Redirects())
    size = 0
    with opener.open(url, timeout=45) as response, partial.open("wb") as output:
        while chunk := response.read(1048576):
            size += len(chunk)
            if size > limit:
                raise ValueError("PREPARATION_SIZE_BOUND_EXCEEDED")
            output.write(chunk)
    if file_digest(partial) != expected:
        raise ValueError("PREPARATION_CHECKSUM_MISMATCH")
    partial.replace(path)


def command(*args):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=180)
    if result.returncode:
        raise ValueError("DOCKER_PREPARATION_FAILED")
    return result.stdout


def admit_corpus_receipt(path, source):
    raw = path.read_bytes()
    metadata = json.loads(raw)
    if (
        metadata.get("schema") != "arena-corpus-prep.v1"
        or metadata.get("license_basis")
        != "pinned first-party MIT cards inspected; preserve attribution/cards"
    ):
        raise ValueError("CORPUS_PREPARATION_NOT_ADMITTED")
    actual = {
        entry["file"]: (entry["dataset"], entry["revision"], entry["sha256"])
        for entry in metadata["sources"]
        if entry["dataset"] == "JailbreakBench/JBB-Behaviors"
    }
    expected = {
        entry["file"]: (entry["dataset"], entry["revision"], entry["sha256"])
        for entry in source["corpus_source_pins"]
    }
    if actual != expected or not actual:
        raise ValueError("CORPUS_SOURCE_PINS_MISMATCH")
    return sha256(raw)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument(
        "--corpus-receipt",
        type=Path,
        default=ROOT.parent
        / "memory files/hackathon/evidence/public-corpus-preparation.json",
        help="Actual freshly prepared public-corpus receipt; its digest is frozen into this admission",
    )
    parser.add_argument(
        "--download",
        action="store_true",
        help="Permit only the pinned acquisition sources during preparation",
    )
    args = parser.parse_args()
    output = args.output.resolve()
    if not output.is_relative_to(ROOT / "artifacts"):
        raise ValueError("PREPARATION_MUST_STAY_IN_IGNORED_BACKEND_ARTIFACTS")
    output.mkdir(parents=True, exist_ok=True)
    if (output / "admission.json").exists():
        raise ValueError("REFUSING_TO_OVERWRITE_FROZEN_ADMISSION")
    source = json.loads((ROOT / "config/n04-sources.json").read_bytes())
    corpus_digest = admit_corpus_receipt(args.corpus_receipt, source)
    base = (
        "https://huggingface.co/"
        + source["model_repository"]
        + "/resolve/"
        + source["model_revision"]
        + "/"
    )
    for name, expected, limit in (
        ("LICENSE", source["model_license_sha256"], 200000),
        ("README.md", source["model_readme_sha256"], 200000),
        (source["model_filename"], source["model_sha256"], source["model_bytes"]),
    ):
        acquire(output / name, base + name, expected, limit, args.download)
    for image in (source["llama_image"], source["defense_python_base"]):
        try:
            command("image", "inspect", image)
        except ValueError:
            if not args.download:
                raise
            command("pull", "--platform", source["platform"], image)
    defense_hash = file_digest(ROOT / "infra/cells/defense.py")
    command(
        "build",
        "--network",
        "none",
        "--platform",
        source["platform"],
        "--build-arg",
        "PYTHON_BASE=" + source["defense_python_base"],
        "--label",
        "arena.defense_source_sha256=" + defense_hash,
        "--iidfile",
        str(output / "defense-image.id"),
        "--file",
        str(ROOT / "infra/cells/Dockerfile.defense"),
        str(ROOT / "infra/cells"),
    )
    image_id = (output / "defense-image.id").read_text().strip()
    lock = AdmissionLock(
        schema_version="arena-n04-admission.v2",
        runtime_source_sha256=runtime_source_hashes(),
        **{
            name: source[name]
            for name in (
                "model_repository",
                "model_revision",
                "model_filename",
                "model_sha256",
                "model_license",
                "model_license_sha256",
                "llama_image",
                "llama_source_revision",
                "defense_python_base",
            )
        },
        corpus_receipt_sha256=corpus_digest,
        tokenizer_binding="EMBEDDED_IN_EXACT_GGUF",
        defense_image=image_id,
        defense_source_sha256=defense_hash,
        context_tokens=2048,
        input_token_cap=1536,
        max_output_tokens=64,
        deadline_seconds=45,
        turn_limit=24,
        artifact_reservation_per_turn=8,
        claim_scope="N04_LOCAL_SINGLE_LANE_ONLY_NOT_FULL_ARENA_ACCEPTANCE",
    )
    data = (lock.model_dump_json(indent=2) + "\n").encode()
    with (output / "admission.json").open("xb") as stream:
        stream.write(data)
    print(
        json.dumps(
            {
                "result": "PREPARED_NOT_ARENA_READY",
                "lock_sha256": sha256(data),
                "model_bytes": source["model_bytes"],
                "runtime_egress": False,
                "corpus_uploaded": False,
                "training": False,
            }
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

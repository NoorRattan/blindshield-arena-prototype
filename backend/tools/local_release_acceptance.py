"""Run fresh, private prepared-host acceptance for this candidate checkout.

Commit this file and the candidate's source/inputs before running. This command
does not install dependencies, create keys, change thresholds, publish, or push.
Owner keys and corpus opening keys are passed by path to the existing trusted
tools; this orchestrator never opens those secret files or echoes their contents.
"""
from __future__ import annotations

import argparse
from datetime import datetime, timezone
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import sys
import time


BACKEND = Path(__file__).resolve().parents[1]
ROOT = BACKEND.parent


def git(*arguments: str) -> bytes:
    return subprocess.check_output(["git", *arguments], cwd=ROOT, stderr=subprocess.PIPE)


def digest(path: Path) -> str:
    value = hashlib.sha256()
    with path.open("rb") as handle:
        for block in iter(lambda: handle.read(1024 * 1024), b""):
            value.update(block)
    return value.hexdigest()


def write_private_new(path: Path, value: dict) -> None:
    raw = (json.dumps(value, indent=2) + "\n").encode()
    descriptor = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
    with os.fdopen(descriptor, "wb") as handle:
        handle.write(raw)


def frozen_checkout(expected: str | None = None) -> str:
    try:
        top = git("rev-parse", "--show-toplevel").decode().strip()
    except subprocess.CalledProcessError:
        raise ValueError("CANDIDATE_MUST_HAVE_ITS_OWN_GIT_ROOT") from None
    if Path(top).resolve() != ROOT:
        raise ValueError("CANDIDATE_MUST_HAVE_ITS_OWN_GIT_ROOT")
    revision = git("rev-parse", "HEAD").decode().strip()
    if expected is not None and revision != expected:
        raise ValueError("SOURCE_COMMIT_CHANGED_DURING_ACCEPTANCE")
    if git("status", "--porcelain=v1", "--untracked-files=all").strip():
        raise ValueError("CLEAN_COMMITTED_CANDIDATE_CHECKOUT_REQUIRED")
    git("ls-files", "--error-unmatch", "backend/tools/local_release_acceptance.py")
    return revision


def require_candidate_import(path: str) -> None:
    if not Path(path).resolve().is_relative_to((BACKEND / "src" / "arena").resolve()):
        raise ValueError("INTERPRETER_IMPORTS_A_DIFFERENT_ARENA_CHECKOUT")


def existing(path: Path, *, directory: bool = False) -> Path:
    resolved = path.expanduser().resolve(strict=True)
    if not (resolved.is_dir() if directory else resolved.is_file()):
        raise ValueError("REQUIRED_INPUT_PATH_HAS_WRONG_TYPE")
    return resolved


def ignored_output(path: Path) -> Path:
    requested = path if path.is_absolute() else BACKEND / path
    output = requested.absolute()
    artifacts = BACKEND / "artifacts"
    if output == artifacts or not output.resolve().is_relative_to(artifacts.resolve()):
        raise ValueError("NEW_OUTPUT_UNDER_CANDIDATE_BACKEND_ARTIFACTS_REQUIRED")
    for component in (output, *output.parents):
        if component == BACKEND:
            break
        if component.is_symlink():
            raise ValueError("OUTPUT_SYMLINK_REFUSED")
    if output.exists():
        raise ValueError("OUTPUT_ALREADY_EXISTS_NO_RESUME_OR_OVERWRITE")
    checked = subprocess.run(["git", "check-ignore", "--quiet", "--", output.relative_to(ROOT).as_posix()], cwd=ROOT)
    if checked.returncode != 0:
        raise ValueError("PRIVATE_OUTPUT_MUST_BE_GIT_IGNORED")
    return output


def accept(args: argparse.Namespace) -> int:
    revision = frozen_checkout()
    spec = importlib.util.find_spec("arena")
    if spec is None or not spec.origin:
        raise ValueError("INSTALL_CANDIDATE_IN_THIS_INTERPRETER_FIRST")
    require_candidate_import(spec.origin)
    from arena.prototype.admission import REQUIRED_INPUTS, source_hashes

    # Check actual bytes as well as Git status: a clean-looking index must not
    # conceal excluded, missing, or differently normalized measured source.
    for relative in sorted(set(source_hashes()) | set(REQUIRED_INPUTS)):
        path = BACKEND / relative
        committed = git("show", revision + ":backend/" + relative)
        if hashlib.sha256(committed).hexdigest() != digest(path):
            raise ValueError("CANDIDATE_BYTES_DIFFER_FROM_COMMITTED_SOURCE")

    model = existing(args.model)
    corpus = existing(args.corpus, directory=True)
    corpus_receipt = existing(args.corpus_receipt)
    corpus_keys = existing(args.corpus_keys)
    authorities = existing(args.authority_directory, directory=True)
    verifier = existing(args.offline_python)
    component = existing(BACKEND / "infra/model-component/profile.json")
    public = existing(args.authority_public_key)
    component_wire = json.loads(component.read_bytes())
    if digest(corpus_receipt) != component_wire["admission"]["corpus_receipt_sha256"]:
        raise ValueError("CORPUS_RECEIPT_DOES_NOT_MATCH_SELECTED_COMPONENT")
    if authorities.is_relative_to(ROOT):
        raise ValueError("OWNER_AUTHORITY_DIRECTORY_MUST_STAY_OUTSIDE_CANDIDATE")
    for name in ("demo-ca-private.pem", "recorder-private.pem", "witness-private.pem"):
        existing(authorities / name)  # Existence only; no secret contents read.
    recovery_authorities = json.loads((BACKEND / "infra/prototype/recovery-authorities.json").read_bytes())
    for role in ("anchor", "recovery", "invalid_export"):
        key_id = recovery_authorities[role]["key_id"]
        existing(authorities.parent / "prototype-recovery" / (key_id + "-private.pem"))
    output = ignored_output(args.output)

    environment = os.environ.copy()
    environment.pop("PYTHONPATH", None)
    environment.pop("PYTHONHOME", None)
    environment["PYTHONNOUSERSITE"] = "1"
    probe_code = ("import arena,json,platform,sys; "
                  "print(json.dumps(dict(arena_file=arena.__file__,prefix=sys.prefix,"
                  "runtime=platform.python_implementation(),version=platform.python_version(),"
                  "platform=platform.platform())))")
    probe = subprocess.run([str(verifier), "-I", "-c", probe_code], cwd=BACKEND,
                           env=environment, capture_output=True, check=True)
    independent = json.loads(probe.stdout)
    require_candidate_import(independent["arena_file"])
    if Path(independent["prefix"]).resolve() == Path(sys.prefix).resolve():
        raise ValueError("SEPARATE_INSTALLED_OFFLINE_ENVIRONMENT_REQUIRED")

    output.mkdir(parents=True, mode=0o700)
    write_private_new(output / "execution-start.json", {
        "source_commit": revision, "started_at_utc": datetime.now(timezone.utc).isoformat(),
        "primary_python": sys.executable, "primary_arena_file": spec.origin,
        "independent_python": str(verifier), "independent_environment": independent,
        "scope": "PREPARED_HOST_LOCAL_CANDIDATE_ACCEPTANCE_NOT_FULL_T_P_OR_PUBLICATION",
        "private_keys_or_opening_keys_copied": False,
    })
    commands: list[dict] = []

    def stage(name: str, arguments: list[str | Path]) -> None:
        frozen_checkout(revision)
        command = [sys.executable, "-I", *map(str, arguments)]
        record = {"stage": name, "command": command, "cwd": str(BACKEND),
                  "source_commit": revision, "started_at_utc": datetime.now(timezone.utc).isoformat()}
        write_private_new(output / (name + ".command-start.json"), record)
        print(json.dumps({"stage": name, "state": "RUNNING"}), flush=True)
        tick = time.monotonic_ns()
        stdout_path, stderr_path = output / (name + ".stdout.log"), output / (name + ".stderr.log")
        with stdout_path.open("xb") as stdout, stderr_path.open("xb") as stderr:
            checked = subprocess.run(command, cwd=BACKEND, env=environment, stdout=stdout, stderr=stderr)
        record.update(exit_code=checked.returncode, duration_ns=time.monotonic_ns() - tick,
                      stdout_path=stdout_path.name, stderr_path=stderr_path.name,
                      stdout_sha256=digest(stdout_path), stderr_sha256=digest(stderr_path))
        commands.append(record)
        write_private_new(output / (name + ".command.json"), record)
        print(json.dumps({"stage": name, "exit_code": checked.returncode}), flush=True)
        if checked.returncode:
            raise RuntimeError("ACCEPTANCE_STAGE_FAILED:" + name)
        frozen_checkout(revision)

    profile = output / "candidate/profile.json"
    static = output / "static.json"
    calibration = output / "calibration/calibration.json"
    service = output / "service.json"
    demo = output / "demo"
    signer = authorities / "recorder-private.pem"
    try:
        stage("01-prepare", ["tools/prototype_prepare.py", "--component", component,
              "--authority-public-key", public, "--output", profile.parent])
        stage("02-static", ["tools/prototype_gate.py", "static", "--profile", profile, "--model", model,
              "--authority-key", signer, "--authority-public-key", public, "--output", static])
        stage("03-calibration", ["tools/prototype_calibrate.py", "--profile", profile, "--static-grant", static,
              "--model", model, "--authority-key", signer, "--authority-public-key", public,
              "--output", calibration.parent])
        stage("04-service", ["tools/prototype_gate.py", "service", "--profile", profile,
              "--static-grant", static, "--calibration", calibration, "--authority-key", signer,
              "--authority-public-key", public, "--output", service])
        stage("05-demo", ["tools/prototype_run.py", "--profile", profile, "--service-grant", service,
              "--authority-public-key", public, "--authority-directory", authorities, "--model", model,
              "--corpus", corpus, "--corpus-receipt", corpus_receipt, "--corpus-keys", corpus_keys,
              "--output", demo, "--mode", "INTERACTIVE", "--defense-mode", "INPUT", "--demo",
              "--offline-python", verifier])
        frozen = json.loads(profile.read_bytes())
        calibrated = json.loads(calibration.read_bytes())["receipt"]["observations"]
        result = json.loads((demo / "receipt.json").read_bytes())
        verifier_result = json.loads((demo / "offline-verifier.log").read_bytes())
        if (frozen["source_commit"] != revision or result["source_commit"] != revision
            or calibrated["result"] != "PASS_THREE_LANE_CALIBRATION"
            or calibrated["model_image_id"] != frozen["component"]["assembled_image_id"]
            or calibrated["real_model_dispatches"] != 6 or calibrated["containers_cleaned_up"] is not True
            or result["result"] != "PASS_AUTHENTICATED_REAL_PUBLIC_PROTOTYPE"
            or result["interaction_mode"] != "INTERACTIVE" or result["defense_mode"] != "INPUT"
            or result["real_model_dispatches"] != 6 or result["offline_verifier_exit_code"] != 0
            or verifier_result.get("status") != "PASS_PUBLIC_EVIDENCE"
            or verifier_result.get("exit_code") != 0
            or result["containers_cleaned_up"] is not True
            or result["denial_idempotency_and_embargo_checks_passed"] is not True
            or result["full_t_p_acceptance"] is not False
            or result["profile_sha256"] != digest(profile)
            or result["offline_verifier_log_sha256"] != digest(demo / "offline-verifier.log")
            or result["evidence_sha256"] != digest(demo / "evidence.zip")):
            raise ValueError("EXACT_ACCEPTANCE_RECEIPTS_REQUIRED")
        frozen_checkout(revision)
        write_private_new(output / "acceptance-summary.json", {
            "result": "PASS_PREPARED_HOST_CANDIDATE_ACCEPTANCE", "source_commit": revision,
            "profile_sha256": digest(profile), "static_sha256": digest(static),
            "calibration_sha256": digest(calibration), "service_sha256": digest(service),
            "calibration_real_model_dispatches": 6, "demo_real_model_dispatches": 6,
            "offline_verifier_exit_code": 0, "owned_containers_cleaned_up": True,
            "demo_receipt_sha256": digest(demo / "receipt.json"), "completed_stages": commands,
            "full_t_p_acceptance": False, "published_or_pushed": False,
            "scope": "PREPARED_HOST_LOCAL_CANDIDATE_ONLY_REVIEW_REQUIRED_BEFORE_SHARING",
        })
        print(json.dumps({"result": "PASS_PREPARED_HOST_CANDIDATE_ACCEPTANCE",
                          "source_commit": revision, "real_model_dispatches": 12,
                          "offline_verifier_exit_code": 0, "published_or_pushed": False}), flush=True)
        return 0
    except BaseException as exc:
        write_private_new(output / "acceptance-failure.json", {
            "result": "FAILED_OR_INTERRUPTED_NO_AUTOMATIC_RETRY", "exception_type": type(exc).__name__,
            "source_commit": revision, "recorded_stages": commands,
            "cleanup_confirmed": False, "private_logs_and_partial_artifacts_retained": True,
        })
        raise


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    for name in ("model", "corpus", "corpus-receipt", "corpus-keys", "authority-directory", "offline-python", "output"):
        parser.add_argument("--" + name, type=Path, required=True)
    parser.add_argument("--authority-public-key", type=Path,
                        default=BACKEND / "infra/prototype/admission-public.hex")
    try:
        return accept(parser.parse_args())
    except KeyboardInterrupt:
        print(json.dumps({"result": "INTERRUPTED_PRIVATE_ARTIFACTS_RETAINED"}), file=sys.stderr)
        return 130
    except Exception as exc:
        # Child diagnostics can contain private paths; their exact bytes stay
        # in private logs. No key contents or child traceback is echoed here.
        failure = {"result": "LOCAL_ACCEPTANCE_REFUSED_OR_FAILED", "exception_type": type(exc).__name__}
        if re.fullmatch(r"[A-Za-z0-9_:-]+", str(exc)):
            failure["code"] = str(exc)
        print(json.dumps(failure), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

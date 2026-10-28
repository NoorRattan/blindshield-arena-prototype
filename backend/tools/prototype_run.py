"""Serve one admitted local prototype or run its real authenticated acceptance demo."""
import argparse
import asyncio
import json
from pathlib import Path
import time

from arena.contracts.jsonwire import load_wire
from arena.integration.corpus import PreparedPublicCorpus
from arena.model_runtime import BACKEND
from arena.prototype.admission import PrototypeProfile, key_public
from arena.prototype.demo import exercise
from arena.prototype.runtime import PrototypeRuntime
from arena.prototype.service import PrototypeService
from arena.recovery.anchor import RecoveryAnchorError
from arena.recovery.startup import inspect_existing_prototype


async def run(args):
    process_started_ns = time.monotonic_ns()
    requested_root = args.output.absolute()
    if requested_root.is_symlink():
        raise ValueError("PRIVATE_SERVICE_DIRECTORY_SYMLINK_REFUSED")
    root = requested_root.resolve()
    if not root.is_relative_to(BACKEND / "artifacts"):
        raise ValueError("PRIVATE_SERVICE_DIRECTORY_REQUIRED")
    if getattr(args, "recover_only", False):
        if args.demo or not root.is_dir():
            raise ValueError("RECOVERY_ONLY_REQUIRES_EXISTING_STORE_AND_NO_DEMO")
        profile = load_wire(PrototypeProfile, args.profile.read_bytes())
        corpus = PreparedPublicCorpus(args.corpus, args.corpus_receipt, args.corpus_keys, profile.component.admission.corpus_receipt_sha256)
        service = PrototypeService.open_existing_recovery(
            corpus, root, args.authority_directory,
            startup_monotonic_ns=process_started_ns,
        )
        try:
            service.startup_recovery_preflight()
            port = service.listen(args.port)
            info = {
                "url": "https://127.0.0.1:" + str(port),
                "mode": service.mode,
                "scope": "LOCAL_OFFLINE_RECOVERY_ONLY",
                "startup_action": service.recovery_inspection["recovery_only_action"],
                "recovery_turn_id": service.recovery_inspection["recovery_turn_id"],
                "workers_started": False,
                "model_started": False,
            }
            print(json.dumps(info), flush=True)
            await asyncio.Event().wait()
        finally:
            await service.shutdown()
        return
    if root.exists():
        try:
            inspection = inspect_existing_prototype(root, args.authority_directory)
        except RecoveryAnchorError as exc:
            print(json.dumps({"startup_inspection": "REFUSED", "code": str(exc)}), flush=True)
            raise ValueError("EXISTING_STORE_RECOVERY_REFUSED") from None
        print(json.dumps({"startup_inspection": inspection}), flush=True)
        raise ValueError("COLD_RESUME_UNSUPPORTED_AFTER_AUTHENTICATED_INSPECTION")
    # Load/validate corpus before any model process is started.
    profile = load_wire(PrototypeProfile, args.profile.read_bytes())
    corpus = PreparedPublicCorpus(args.corpus, args.corpus_receipt, args.corpus_keys, profile.component.admission.corpus_receipt_sha256)
    root.mkdir(parents=True)
    runtime = PrototypeRuntime(args.profile, args.service_grant, key_public(args.authority_public_key), args.model, root / "runtime")
    service = None
    result = None
    try:
        service = PrototypeService(runtime, corpus, root, args.authority_directory, mode=args.mode, defense_mode=args.defense_mode)
        service.startup_preflight()
        await asyncio.to_thread(runtime.start)
        port = service.listen(args.port)
        info = {"url": "https://127.0.0.1:" + str(port), "mode": args.mode, "scope": "LOCAL_OFFLINE_PROTOTYPE", "credentials": "tls/", "create_request": "create-request.json"}
        (root / "service-info.json").write_bytes((json.dumps(info, indent=2) + "\n").encode())
        print(json.dumps(info), flush=True)
        if args.demo:
            result = await exercise(service, args.offline_python.resolve())
        else:
            await asyncio.Event().wait()
    finally:
        if service is not None:
            await service.shutdown()
        else:
            await asyncio.to_thread(runtime.stop)
    if result is not None:
        result["containers_cleaned_up"] = True
        (root / "receipt.json").write_bytes((json.dumps(result, indent=2) + "\n").encode())
        print(json.dumps({"result": result["result"], "mode": args.mode, "real_model_dispatches": result["real_model_dispatches"], "offline_verifier_exit_code": 0}), flush=True)


if __name__ == "__main__":
    p = argparse.ArgumentParser(description=__doc__)
    for name in ("profile", "service-grant", "authority-public-key", "authority-directory", "model", "corpus", "corpus-receipt", "corpus-keys", "output"):
        p.add_argument("--" + name, required=True, type=Path)
    p.add_argument("--mode", required=True, choices=("INTERACTIVE", "SEALED_BATCH"))
    p.add_argument("--defense-mode", default="INPUT", choices=("INPUT", "FEATURES", "OUTPUT", "POST_HOC"))
    p.add_argument("--demo", action="store_true")
    p.add_argument("--recover-only", action="store_true",
                   help="Authenticate an existing store and expose only exact feedback recovery and terminal close")
    p.add_argument("--port", type=int, default=0)
    p.add_argument("--offline-python", type=Path, default=Path("artifacts/repro-env/Scripts/python.exe"))
    try:
        asyncio.run(run(p.parse_args()))
    except KeyboardInterrupt:
        pass

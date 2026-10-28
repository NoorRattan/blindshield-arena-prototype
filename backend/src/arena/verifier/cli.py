"""Standalone offline verifier CLI with zero broker runtime dependencies."""

from __future__ import annotations

import argparse
import json
from pathlib import Path
import sys
import tempfile
import zipfile
from typing import Dict
from uuid import UUID

from ..contracts.common import Context
from .archive import safe_extract_archive
from .replay import replay_and_decrypt_artifacts
from .rules import VerificationError, verify_evidence_directory
from .openings import verify_n04_openings
from .analysis import verify_post_hoc_directory


def parse_key_bytes(key_arg: str) -> bytes:
    """Parse key from either direct hex string or file path."""
    p = Path(key_arg)
    if p.exists() and p.is_file():
        content = p.read_bytes()
        if len(content) == 32:
            return content
        # Try reading as hex string from text file
        text = p.read_text(encoding="utf-8").strip()
        return bytes.fromhex(text)
    return bytes.fromhex(key_arg.strip())


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        prog="python -m arena.verifier.cli",
        description="Standalone offline cryptographic verifier for arena.v2 evidence packages.",
    )
    parser.add_argument(
        "--bundle",
        type=Path,
        required=True,
        help="Path to evidence zip archive or extracted directory",
    )
    parser.add_argument(
        "--recorder-key",
        type=str,
        required=True,
        help="Pinned Ed25519 public key for recorder (hex or file)",
    )
    parser.add_argument(
        "--witness-key",
        type=str,
        required=True,
        help="Pinned Ed25519 public key for witness (hex or file)",
    )
    parser.add_argument(
        "--domain-id", type=str, required=True, help="Expected domain UUID"
    )
    parser.add_argument(
        "--experiment-id", type=str, required=True, help="Expected experiment UUID"
    )
    parser.add_argument(
        "--epoch", type=int, required=True, help="Expected epoch integer"
    )
    parser.add_argument(
        "--manifest-digest",
        type=str,
        required=True,
        help="Expected manifest SHA-256 digest",
    )
    parser.add_argument(
        "--recorder-key-id",
        type=str,
        required=True,
        help="Expected recorder key identity",
    )
    parser.add_argument(
        "--witness-key-id",
        type=str,
        required=True,
        help="Expected witness key identity",
    )
    parser.add_argument(
        "--defense-mode",
        choices=["INPUT", "FEATURES", "OUTPUT", "POST_HOC"],
        help="Independently expected frozen mode for N04 semantics",
    )
    parser.add_argument(
        "--broker-actor", help="Independently expected trusted event actor"
    )
    parser.add_argument(
        "--post-hoc-bundle",
        type=Path,
        action="append",
        default=[],
        help="Separately linked analysis archive; may repeat",
    )
    parser.add_argument(
        "--expected-release-id",
        help="Release authorization ID from a separate trusted channel",
    )
    parser.add_argument(
        "--analysis-keys-json",
        type=Path,
        help="Private keys for only the requested late-analysis artifacts",
    )
    parser.add_argument(
        "--keys-json",
        type=Path,
        help="Optional JSON file mapping artifact_id to hex AES key for authorized replay",
    )

    parser.add_argument("--require-transport-profile", action="store_true", help="Require sealed local transport evidence with independent trust and authorized openings")
    parser.add_argument("--require-prototype-batch", action="store_true", help="Require complete private openings and frozen sealed-batch coverage")
    parser.add_argument("--transport-profile-key", help="Independent local transport signer public key (hex or file)")
    parser.add_argument("--transport-profile-key-id")
    parser.add_argument("--feedback-policy-key", help="Independent feedback-policy signer public key (hex or file)")
    parser.add_argument("--feedback-policy-key-id")
    parser.add_argument("--anchor-key", help="Independent recovery-anchor Ed25519 public key for INVALID evidence")
    parser.add_argument("--anchor-key-id")
    parser.add_argument("--anchor-authority-id")
    parser.add_argument("--anchor-records", type=Path, help="Independently supplied canonical signed anchor JSONL for reconciled evidence")
    parser.add_argument("--recovery-key", help="Independent recovery-authority public key for INVALID evidence")
    parser.add_argument("--recovery-key-id")
    parser.add_argument("--recovery-authority-id")
    parser.add_argument("--invalid-export-key", help="Independent INVALID gap-manifest signer key")
    parser.add_argument("--invalid-export-key-id")
    args = parser.parse_args(argv)

    try:
        recorder_key_bytes = parse_key_bytes(args.recorder_key)
        witness_key_bytes = parse_key_bytes(args.witness_key)
        expected_context = Context(
            domain_id=str(UUID(args.domain_id)),
            experiment_id=str(UUID(args.experiment_id)),
            epoch=args.epoch,
        )
        transport_trust = None
        pins = (args.transport_profile_key, args.transport_profile_key_id, args.feedback_policy_key, args.feedback_policy_key_id)
        if any(pins):
            if not all(pins):
                raise ValueError("ALL_TRANSPORT_TRUST_FIELDS_REQUIRED")
            from ..contracts.transport_profile import TransportTrust
            transport_trust = TransportTrust(parse_key_bytes(args.feedback_policy_key), args.feedback_policy_key_id,
                                             parse_key_bytes(args.transport_profile_key), args.transport_profile_key_id)
    except Exception as exc:
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "exit_code": 2,
                    "error": f"Invalid key argument: {exc}",
                }
            ),
            file=sys.stderr,
        )
        return 2

    bundle_path = args.bundle.resolve()
    if not bundle_path.exists():
        print(
            json.dumps(
                {
                    "status": "FAIL",
                    "exit_code": 1,
                    "error": f"Bundle path does not exist: {bundle_path}",
                }
            ),
            file=sys.stderr,
        )
        return 1

    invalid_envelope = False
    reconciled_envelope = False
    if bundle_path.is_dir():
        invalid_envelope = (bundle_path / "invalid-gap-manifest.json").exists()
    else:
        try:
            with zipfile.ZipFile(bundle_path) as archive:
                invalid_envelope = "invalid-gap-manifest.json" in archive.namelist()
                if "bundle-manifest.json" in archive.namelist():
                    info = archive.getinfo("bundle-manifest.json")
                    if info.file_size <= 1_000_000:
                        manifest = json.loads(archive.read(info))
                        reconciled_envelope = manifest.get("schema_version") == "arena.reconciled-evidence-bundle.v1"
        except (OSError, zipfile.BadZipFile):
            pass
        except (ValueError, TypeError, AttributeError):
            pass
    if reconciled_envelope:
        required = (args.anchor_records, args.anchor_key, args.anchor_key_id, args.anchor_authority_id,
                    args.recovery_key, args.recovery_key_id, args.recovery_authority_id,
                    args.keys_json, args.defense_mode, args.broker_actor)
        if (not all(required) or args.invalid_export_key or args.invalid_export_key_id
                or args.post_hoc_bundle or args.analysis_keys_json or args.require_prototype_batch):
            print(json.dumps({"status": "FAIL", "exit_code": 2,
                              "error": "Reconciled evidence requires independent anchor stream/roots, recovery roots, exact authorized openings and expected semantics"}), file=sys.stderr)
            return 2
        try:
            from .reconciled_bundle import verify_reconciled_evidence_bundle
            values = json.loads(args.keys_json.read_bytes())
            if not isinstance(values, dict) or any(not isinstance(value, dict)
                    or set(value) != {"key", "classification"} for value in values.values()):
                raise VerificationError("Reconciled replay keys require exact key/classification entries", exit_code=2)
            result = verify_reconciled_evidence_bundle(
                bundle_path, anchor_records_bytes=args.anchor_records.read_bytes(),
                expected_context=expected_context, expected_manifest_digest=args.manifest_digest,
                recorder_key=recorder_key_bytes, recorder_key_id=args.recorder_key_id,
                witness_key=witness_key_bytes, witness_key_id=args.witness_key_id,
                anchor_key=parse_key_bytes(args.anchor_key), anchor_key_id=args.anchor_key_id,
                anchor_authority_id=args.anchor_authority_id,
                recovery_key=parse_key_bytes(args.recovery_key), recovery_key_id=args.recovery_key_id,
                recovery_authority_id=args.recovery_authority_id,
                artifact_keys={identifier: bytes.fromhex(value["key"]) for identifier, value in values.items()},
                artifact_classifications={identifier: value["classification"] for identifier, value in values.items()},
                expected_defense_mode=args.defense_mode, expected_broker_actor=args.broker_actor,
                transport_trust=transport_trust, require_transport_profile=args.require_transport_profile,
            )
            print(json.dumps(result, indent=2))
            return result["exit_code"]
        except VerificationError as exc:
            print(json.dumps({"status": "FAIL", "exit_code": exc.exit_code, "error": str(exc)}), file=sys.stderr)
            return exc.exit_code
        except Exception as exc:
            print(json.dumps({"status": "FAIL", "exit_code": 2,
                              "error": "Reconciled verifier input rejected: " + type(exc).__name__}), file=sys.stderr)
            return 2
    if invalid_envelope:
        required = (args.invalid_export_key, args.invalid_export_key_id)
        optional_pairs = ((args.anchor_key, args.anchor_key_id),
                          (args.recovery_key, args.recovery_key_id))
        if (not all(required) or any((key is None) != (key_id is None) for key, key_id in optional_pairs)
                or args.keys_json or args.analysis_keys_json or args.post_hoc_bundle):
            print(json.dumps({
                "status": "FAIL", "exit_code": 2,
                "error": "INVALID evidence requires independent recorder, witness and invalid-export roots; any anchor/recovery roots are reported unverified because their records are not in this bundle",
            }, indent=2), file=sys.stderr)
            return 2
        try:
            from .invalid_bundle import verify_invalid_evidence_bundle
            result = verify_invalid_evidence_bundle(
                bundle_path,
                recorder_key=recorder_key_bytes,
                witness_key=witness_key_bytes,
                export_key=parse_key_bytes(args.invalid_export_key),
                expected_context=expected_context,
                expected_manifest_digest=args.manifest_digest,
                recorder_key_id=args.recorder_key_id,
                witness_key_id=args.witness_key_id,
                export_key_id=args.invalid_export_key_id,
                anchor_key=parse_key_bytes(args.anchor_key) if args.anchor_key else None,
                anchor_key_id=args.anchor_key_id,
                recovery_key=parse_key_bytes(args.recovery_key) if args.recovery_key else None,
                recovery_key_id=args.recovery_key_id,
            )
            print(json.dumps(result, indent=2))
            return result["exit_code"]
        except VerificationError as exc:
            print(json.dumps({"status": "FAIL", "exit_code": exc.exit_code, "error": str(exc)}, indent=2), file=sys.stderr)
            return exc.exit_code
        except Exception as exc:
            print(json.dumps({"status": "FAIL", "exit_code": 1,
                              "error": f"Unhandled INVALID verifier exception: {type(exc).__name__}"}, indent=2), file=sys.stderr)
            return 1

    temp_dir_ctx = None
    try:
        if bundle_path.is_file():
            # Extract safe archive
            temp_dir = tempfile.TemporaryDirectory()
            temp_dir_ctx = temp_dir
            extracted_dir = Path(temp_dir.name)
            safe_extract_archive(bundle_path, extracted_dir)
            target_dir = extracted_dir
        else:
            target_dir = bundle_path

        result = verify_evidence_directory(
            bundle_dir=target_dir,
            pinned_recorder_key=recorder_key_bytes,
            pinned_witness_key=witness_key_bytes,
            expected_context=expected_context,
            expected_manifest_digest=args.manifest_digest,
            expected_recorder_key_id=args.recorder_key_id,
            expected_witness_key_id=args.witness_key_id,
            expected_defense_mode=args.defense_mode,
            expected_broker_actor=args.broker_actor,
        )

        decrypted_count = 0
        decrypted_map = {}
        if args.keys_json:
            if not args.keys_json.is_file():
                raise VerificationError(
                    "Requested replay key file is missing", exit_code=2
                )
            keys_dict = json.loads(args.keys_json.read_text(encoding="utf-8"))
            parsed_keys: Dict[str, bytes] = {
                k: bytes.fromhex(v["key"] if isinstance(v, dict) else v)
                for k, v in keys_dict.items()
            }
            classifications = {
                k: v["classification"]
                for k, v in keys_dict.items()
                if isinstance(v, dict)
            }
            expected_files = {
                path.stem for path in (target_dir / "artifacts").iterdir()
            }
            if set(parsed_keys) != expected_files:
                raise VerificationError(
                    "Replay keys must cover exactly the required artifacts", exit_code=2
                )
            decrypted_map = replay_and_decrypt_artifacts(
                artifacts_dir=target_dir / "artifacts",
                artifact_keys=parsed_keys,
                context=expected_context,
                classifications=classifications,
            )
            decrypted_count = len(decrypted_map)
            result.diagnostics["artifacts_decrypted"] = decrypted_count
            if (target_dir / "witness_start.json").exists() and args.defense_mode:
                try:
                    result.diagnostics["turn_openings_verified"] = verify_n04_openings(
                        target_dir, decrypted_map, args.defense_mode
                    )
                    result.diagnostics["scope"] = (
                        "N04_PUBLIC_EVIDENCE_AND_PRIVATE_OPENINGS"
                    )
                except Exception as exc:
                    raise VerificationError(
                        "Private commitment/lineage verification failed", exit_code=1
                    ) from exc

        from .transport import transport_from_openings, verify_transport_opening
        private_binding_verified = "turn_openings_verified" in result.diagnostics
        batch_present = bool(private_binding_verified and any("prototype_batch" in json.loads(value).get("sealed", {}).get("manifest", {}) for value in decrypted_map.values()))
        if args.require_prototype_batch or batch_present:
            if not private_binding_verified:
                raise VerificationError("Batch verification requires complete authorized private openings", exit_code=4)
            from .prototype import verify_batch_openings
            try:
                result.diagnostics.update(verify_batch_openings(decrypted_map))
            except Exception as exc:
                raise VerificationError("Sealed batch coverage or lineage rejected", exit_code=1) from exc
        sealed_profile_present = bool(private_binding_verified and "n06_transport" in transport_from_openings(decrypted_map))
        if args.require_transport_profile or transport_trust is not None or sealed_profile_present:
            if not private_binding_verified or transport_trust is None:
                result.status, result.exit_code = "INCOMPLETE_TRANSPORT_TRUST", 4
                result.message = "Transport verification needs complete authorized openings and independently supplied policy/profile trust"
                result.diagnostics["transport_profile_verified"] = False
            elif not sealed_profile_present:
                raise VerificationError("Required sealed transport profile is absent", exit_code=1)
            else:
                try:
                    result.diagnostics.update(verify_transport_opening(decrypted_map, expected_context, transport_trust))
                    result.diagnostics["scope"] = "N06_SEALED_TRANSPORT_AND_PRIVATE_OPENINGS"
                except Exception as exc:
                    raise VerificationError("Sealed transport profile verification rejected", exit_code=1) from exc

        if args.post_hoc_bundle:
            if (
                args.defense_mode != "POST_HOC"
                or not args.expected_release_id
                or not args.analysis_keys_json
                or not decrypted_map
            ):
                raise VerificationError(
                    "Requested post-release verification requires trusted release and complete private keys",
                    exit_code=2,
                )
            analysis_keys = json.loads(args.analysis_keys_json.read_bytes())
            verified_analyses = []
            for path in args.post_hoc_bundle:
                with tempfile.TemporaryDirectory() as name:
                    folder = Path(name)
                    safe_extract_archive(path, folder)
                    verified_analyses.append(
                        verify_post_hoc_directory(
                            folder,
                            target_dir,
                            expected_context,
                            args.expected_release_id,
                            recorder_key_bytes,
                            args.recorder_key_id,
                            decrypted_map,
                            analysis_keys,
                            result.diagnostics["integrity"],
                        )
                    )
            if len({item["turn_id"] for item in verified_analyses}) != len(
                verified_analyses
            ) or set(analysis_keys) != {
                item["analysis_artifact_id"] for item in verified_analyses
            }:
                raise VerificationError(
                    "Duplicate analysis or incomplete/unexpected analysis-key coverage",
                    exit_code=2,
                )
            result.diagnostics["post_hoc_observations_verified"] = len(
                verified_analyses
            )
            result.diagnostics["post_hoc_prevention_claim"] = False
            result.diagnostics["scope"] = "N04_PUBLIC_PRIVATE_AND_POST_RELEASE_LINKAGE"

        out_data = {
            "status": result.status,
            "exit_code": result.exit_code,
            "message": result.message,
            "event_count": result.event_count,
            "final_root": result.final_root,
            "diagnostics": result.diagnostics,
        }
        print(json.dumps(out_data, indent=2))
        return result.exit_code

    except VerificationError as v_exc:
        err_data = {
            "status": "FAIL",
            "exit_code": v_exc.exit_code,
            "error": str(v_exc),
        }
        print(json.dumps(err_data, indent=2), file=sys.stderr)
        return v_exc.exit_code
    except Exception as exc:
        err_data = {
            "status": "FAIL",
            "exit_code": 1,
            "error": f"Unhandled verification exception: {exc}",
        }
        print(json.dumps(err_data, indent=2), file=sys.stderr)
        return 1
    finally:
        if temp_dir_ctx is not None:
            temp_dir_ctx.cleanup()


if __name__ == "__main__":
    sys.exit(main())

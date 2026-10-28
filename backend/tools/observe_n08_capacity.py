"""OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE.
Collect passive Windows/WSL2/Docker capacity and image-presence observations.
This tool never starts or changes containers and never authorizes a model workload.
"""
from __future__ import annotations

import argparse
import base64
from datetime import datetime, timezone
import hashlib
import json
import os
from pathlib import Path
import subprocess
import sys

LABEL = "OWNER-DELEGATED, SELF-ATTESTED, PROTOTYPE-SCOPE"
BACKEND = Path(__file__).resolve().parents[1]
REPOSITORY = BACKEND.parent
OUTPUT_ROOT = BACKEND / "infra" / "owner-delegated-n08"
MODEL_IMAGE = "sha256:9fbaa06d7f4449e2ae0d02b40e0431f7c212dcf231c9e3a7777a6afc2cc8f312"
DEFENSE_IMAGE = "sha256:c2ba5e610d1064f1a8b84ee3b1455942eeccca3d90a02909eda80b8f5d26658c"
PYTHON_BASE_IMAGE = "sha256:a6e34c598f2467ed0e9a8d349809fcd8b5c603269512df273a0bb1784edc11b1"


def run(args: list[str], *, timeout: int = 20) -> str:
    result = subprocess.run(args, capture_output=True, text=True, timeout=timeout, check=False)
    if result.returncode != 0:
        raise RuntimeError(f"PASSIVE_COMMAND_FAILED:{Path(args[0]).name}:{result.returncode}")
    return result.stdout.strip()


def file_hash(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as stream:
        for block in iter(lambda: stream.read(1024 * 1024), b""):
            digest.update(block)
    return digest.hexdigest()


def utc_now() -> str:
    return datetime.now(timezone.utc).isoformat(timespec="seconds").replace("+00:00", "Z")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--private-key", required=True, type=Path, help="owner-only local Ed25519 recorder key outside the repository")
    parser.add_argument("--output", required=True, type=Path, help="new output JSON under infra/owner-delegated-n08")
    args = parser.parse_args(argv)
    private_key_path = args.private_key.resolve()
    output_path = args.output.resolve()
    if private_key_path == REPOSITORY or REPOSITORY in private_key_path.parents:
        raise ValueError("PRIVATE_KEY_MUST_REMAIN_OUTSIDE_REPOSITORY")
    if not output_path.is_relative_to(OUTPUT_ROOT.resolve()) or output_path.exists():
        raise ValueError("NEW_OUTPUT_REQUIRED_UNDER_OWNER_DELEGATED_N08")
    if os.environ.get("DOCKER_HOST"):
        raise ValueError("REMOTE_DOCKER_HOST_OVERRIDE_NOT_ALLOWED")

    started = utc_now()
    host = json.loads(run([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_OperatingSystem | Select-Object FreePhysicalMemory,TotalVisibleMemorySize | ConvertTo-Json -Compress",
    ]))
    host_values = {key: int(value) * 1024 for key, value in host.items()}
    host_cpu = json.loads(run([
        "powershell", "-NoProfile", "-Command",
        "$processors=Get-CimInstance Win32_Processor; [pscustomobject]@{logical_cpu_count=[int](Get-CimInstance Win32_ComputerSystem).NumberOfLogicalProcessors; cpu_load_percent_sample=[math]::Round(($processors | Measure-Object -Property LoadPercentage -Average).Average,0)} | ConvertTo-Json -Compress",
    ]))
    host_volume_rows = json.loads(run([
        "powershell", "-NoProfile", "-Command",
        "Get-CimInstance Win32_LogicalDisk -Filter \"DeviceID='C:' OR DeviceID='N:'\" | Select-Object DeviceID,FileSystem,FreeSpace,Size | ConvertTo-Json -Compress",
    ]))
    if not isinstance(host_volume_rows, list):
        host_volume_rows = [host_volume_rows]
    host_volumes = {
        row["DeviceID"]: {
            "filesystem": row["FileSystem"],
            "free_bytes": int(row["FreeSpace"]),
            "total_bytes": int(row["Size"]),
        }
        for row in host_volume_rows
    }
    if set(host_volumes) != {"C:", "N:"}:
        raise ValueError("HOST_VOLUME_OUTPUT_MALFORMED")
    wsl_lines = run([
        "wsl.exe", "-d", "docker-desktop", "-e", "sh", "-lc",
        "awk '/MemTotal|MemAvailable/ {print $1, $2}' /proc/meminfo; nproc",
    ]).splitlines()
    wsl_values: dict[str, int] = {}
    for line in wsl_lines:
        fields = line.split()
        if len(fields) == 2 and fields[0] in {"MemTotal:", "MemAvailable:"}:
            wsl_values[fields[0][:-1].lower()] = int(fields[1]) * 1024
        elif len(fields) == 1 and fields[0].isdigit():
            wsl_values["online_cpus"] = int(fields[0])
    if not {"memtotal", "memavailable", "online_cpus"} <= set(wsl_values):
        raise ValueError("WSL_CAPACITY_OUTPUT_MALFORMED")
    docker_disk_lines = run([
        "wsl.exe", "-d", "docker-desktop", "-e", "sh", "-lc",
        "df -B1 -P /mnt/docker-desktop-disk",
    ]).splitlines()
    if len(docker_disk_lines) < 2:
        raise ValueError("DOCKER_DATA_DISK_OUTPUT_MALFORMED")
    docker_disk_fields = docker_disk_lines[-1].split()
    if len(docker_disk_fields) < 6 or docker_disk_fields[-1] != "/mnt/docker-desktop-disk":
        raise ValueError("DOCKER_DATA_DISK_OUTPUT_MALFORMED")
    docker_disk = {
        "total_bytes": int(docker_disk_fields[1]),
        "used_bytes": int(docker_disk_fields[2]),
        "available_bytes": int(docker_disk_fields[3]),
        "mount_point": docker_disk_fields[-1],
    }

    docker_fields = run(["docker.exe", "info", "--format", "{{.ServerVersion}}|{{.OSType}}|{{.NCPU}}|{{.MemTotal}}"])
    docker_parts = docker_fields.split("|")
    if len(docker_parts) != 4:
        raise ValueError("DOCKER_INFO_OUTPUT_MALFORMED")
    context = run(["docker.exe", "context", "show"])
    image_records: dict[str, dict[str, str]] = {}
    for role, image in (("model", MODEL_IMAGE), ("defense", DEFENSE_IMAGE), ("python_base_candidate", PYTHON_BASE_IMAGE)):
        fields = run(["docker.exe", "image", "inspect", image, "--format", "{{.Id}}|{{.Os}}|{{.Architecture}}"])
        parts = fields.split("|")
        if len(parts) != 3 or parts[0] != image:
            raise ValueError(f"PINNED_IMAGE_ID_MISMATCH:{role}")
        image_records[role] = {"image_id": parts[0], "os": parts[1], "architecture": parts[2]}

    running_count = len(run(["docker.exe", "ps", "-q"]).splitlines())
    stopped_n05_model_count = len(run([
        "docker.exe", "ps", "-a", "--filter", "name=arena-n05-model", "--format", "{{.Status}}",
    ]).splitlines())
    completed = utc_now()
    report = {
        "artifact_label": LABEL,
        "schema": "arena-owner-delegated-n08-passive-capacity.v1",
        "status": "PASSIVE_MEASUREMENT_ONLY_NOT_N08_PEAK_MEMORY_OR_AUTHORIZATION",
        "collection_started_at_utc": started,
        "collection_completed_at_utc": completed,
        "collector_source_sha256": file_hash(Path(__file__).resolve()),
        "commands": [
            "Get-CimInstance Win32_OperatingSystem FreePhysicalMemory/TotalVisibleMemorySize",
            "Get-CimInstance Win32_Processor LoadPercentage and Win32_ComputerSystem NumberOfLogicalProcessors",
            "Get-CimInstance Win32_LogicalDisk C:/N: FreeSpace/Size/FileSystem",
            "wsl.exe -d docker-desktop -e sh -lc awk MemTotal/MemAvailable and nproc",
            "wsl.exe -d docker-desktop -e sh -lc df -B1 -P /mnt/docker-desktop-disk",
            "docker.exe info --format ServerVersion/OSType/NCPU/MemTotal",
            "docker.exe image inspect pinned model/defense/Python-base candidate image IDs",
            "docker.exe ps -q and filtered stopped N05 model count",
        ],
        "host": {
            "available_memory_bytes": host_values["FreePhysicalMemory"],
            "total_memory_bytes": host_values["TotalVisibleMemorySize"],
            "logical_cpu_count": int(host_cpu["logical_cpu_count"]),
            "cpu_load_percent_sample": int(host_cpu["cpu_load_percent_sample"]),
            "volumes": host_volumes,
        },
        "docker_vm": {
            "available_memory_bytes": wsl_values["memavailable"],
            "total_memory_bytes": wsl_values["memtotal"],
            "online_cpus": wsl_values["online_cpus"],
            "data_disk": docker_disk,
        },
        "docker_engine": {"server_version": docker_parts[0], "os_type": docker_parts[1], "cpus": int(docker_parts[2]), "memory_total_bytes": int(docker_parts[3]), "context": context},
        "pinned_local_image_ids": image_records,
        "containers": {"running_count": running_count, "stopped_n05_model_count": stopped_n05_model_count, "container_mutations_by_collector": False},
        "n08_three_lane_peak_memory_measured": False,
        "n08_workload_authorized": False,
        "model_workload_started_by_collector": False,
        "runtime_network_or_image_downloads": False,
        "scope_limit": "Passive instantaneous capacity and local image presence only; the Python base is not the selected fixture. No three-lane memory peak, host CPU exclusivity, confinement, or N08 authorization is established.",
    }
    payload = json.dumps(report, sort_keys=True, separators=(",", ":")).encode("utf-8")
    from cryptography.hazmat.primitives import serialization
    key = serialization.load_pem_private_key(private_key_path.read_bytes(), password=None)
    signature = key.sign(payload)
    report["self_attestation"] = {
        "artifact_label": LABEL,
        "signer_key_id": "n08-prototype-recorder-001",
        "algorithm": "Ed25519",
        "payload_sha256": hashlib.sha256(payload).hexdigest(),
        "signature_base64": base64.b64encode(signature).decode("ascii"),
    }
    raw = (json.dumps(report, indent=2, sort_keys=True) + "\n").encode("utf-8")
    output_path.parent.mkdir(parents=True, exist_ok=True)
    with output_path.open("xb") as stream:
        stream.write(raw)
        stream.flush()
        os.fsync(stream.fileno())
    print(json.dumps({
        "result": "PASS_PASSIVE_MEASUREMENT",
        "artifact_label": LABEL,
        "report_path": str(output_path.relative_to(REPOSITORY)),
        "report_sha256": hashlib.sha256(raw).hexdigest(),
        "host_available_memory_bytes": host_values["FreePhysicalMemory"],
        "docker_vm_available_memory_bytes": wsl_values["memavailable"],
        "docker_server_version": docker_parts[0],
        "running_container_count": running_count,
        "stopped_n05_model_count": stopped_n05_model_count,
        "n08_peak_memory_measured": False,
    }, sort_keys=True))
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

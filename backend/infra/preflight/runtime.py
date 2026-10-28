"""Inspect local readiness without pulling images, starting services or changing policy.

Run: python -m infra.preflight.runtime --output artifacts/preflight/<new-name>.json
Optional fixture: --probe-image sha256:<approved-local-image-id>
Exit 0 means an approved synthetic fixture passed; 2 means not ready; 1 is a tool error.
No result from this utility establishes an arena guarantee tier or real-model capacity.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
from pathlib import Path
import platform
import re
import shutil
import subprocess
import sys
import time
from datetime import datetime, timezone
import uuid


ROOT = Path(__file__).resolve().parents[2]
REPOSITORY = ROOT.parent
CONFIG = Path(__file__).with_name("policy.json")
IMAGE_ID = re.compile(r"sha256:[0-9a-f]{64}\Z")
STATES = {"ENFORCED", "FAILED", "UNAVAILABLE", "UNTESTED"}
HOST_QUERY = r"""
$os = Get-CimInstance Win32_OperatingSystem
$cpu = Get-CimInstance Win32_Processor | Select-Object -First 1
$principal = [Security.Principal.WindowsPrincipal]::new([Security.Principal.WindowsIdentity]::GetCurrent())
[ordered]@{
 os=$os.Caption; version=$os.Version
 memory_total_bytes=([long]$os.TotalVisibleMemorySize * 1024)
 memory_available_bytes=([long]$os.FreePhysicalMemory * 1024)
 cpu=$cpu.Name.Trim(); physical_cores=$cpu.NumberOfCores; logical_cpus=$cpu.NumberOfLogicalProcessors
 windows_administrator=$principal.IsInRole([Security.Principal.WindowsBuiltInRole]::Administrator)
} | ConvertTo-Json -Compress
"""
# Fixed synthetic commands, no participant strings, downloads, host mounts or sockets.
FIXTURE_SCRIPT = r"""
set -eu
printf 'uid=%s\n' "$(id -u)"
awk '/^CapEff:/ {print "cap_eff=" $2} /^NoNewPrivs:/ {print "no_new_privs=" $2} /^Seccomp:/ {print "seccomp=" $2}' /proc/self/status
if touch /preflight-write-test 2>/dev/null; then echo root_readonly=0; rm /preflight-write-test; else echo root_readonly=1; fi
printf 'interfaces='; ls /sys/class/net | tr '\n' ','; echo
for file in memory.max pids.max cpu.max; do
 if [ -r /sys/fs/cgroup/$file ]; then printf '%s=' "$file"; cat /sys/fs/cgroup/$file; fi
done
"""


def decode(data: bytes) -> str:
    # wsl.exe emits UTF-16LE even when stdout is redirected on some installations.
    encoding = "utf-16-le" if b"\x00" in data[:100] else "utf-8-sig"
    return data.decode(encoding, errors="replace").strip()


def run_command(args: list[str], timeout: int = 12) -> dict:
    started = time.monotonic()
    try:
        result = subprocess.run(args, capture_output=True, timeout=timeout, shell=False)
        return {"argv": args, "exit_code": result.returncode, "timed_out": False,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "stdout": decode(result.stdout), "stderr": decode(result.stderr)}
    except subprocess.TimeoutExpired as exc:
        return {"argv": args, "exit_code": None, "timed_out": True,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "stdout": decode(exc.stdout or b""), "stderr": decode(exc.stderr or b"")}
    except OSError as exc:
        return {"argv": args, "exit_code": None, "timed_out": False,
                "duration_ms": round((time.monotonic() - started) * 1000),
                "stdout": "", "stderr": type(exc).__name__}


def parsed(result: dict) -> dict:
    try:
        value = json.loads(result["stdout"])
        return value if isinstance(value, dict) else {}
    except (ValueError, TypeError):
        return {}


def local_endpoint(endpoint: str) -> bool:
    # Even tcp://localhost may forward elsewhere; only a local socket/pipe is admitted.
    return endpoint.startswith("npipe://") or endpoint.startswith("unix://")


def image_approved(image: str, policy: dict) -> bool:
    return bool(IMAGE_ID.fullmatch(image)) and any(
        row.get("image_id") == image and row.get("purpose") == "synthetic-preflight"
        for row in policy["approved_probe_images"]
    )


def fixture_values(output: str) -> dict[str, str]:
    return dict(line.split("=", 1) for line in output.splitlines() if "=" in line)


def fixture_checks(output: str) -> dict[str, bool]:
    values = fixture_values(output)
    return {
        "NON_ROOT_UID": values.get("uid") == "65534",
        "CAPABILITIES_DROPPED": values.get("cap_eff") == "0000000000000000",
        "NO_NEW_PRIVILEGES": values.get("no_new_privs") == "1",
        "SECCOMP_FILTER_ACTIVE": values.get("seccomp") == "2",
        "READ_ONLY_ROOT": values.get("root_readonly") == "1",
        # Interface observation, not proof of every possible egress or covert channel.
        "NO_NETWORK_INTERFACE": values.get("interfaces") == "lo,",
        "CGROUP_MEMORY_LIMIT": values.get("memory.max") == "134217728",
        "CGROUP_PIDS_LIMIT": values.get("pids.max") == "32",
        "CGROUP_CPU_QUOTA": values.get("cpu.max") == "50000 100000",
    }


def assess(raw: dict, policy: dict) -> dict:
    controls = {}

    def add(name: str, state: str, detail: str) -> None:
        if state not in STATES:
            raise ValueError("Invalid control state")
        controls[name] = {"state": state, "detail": detail}

    version = parsed(raw["docker_version"])
    info = parsed(raw["docker_info"])
    reachable = (raw["docker_version"]["exit_code"] == 0 and
                 raw["docker_info"]["exit_code"] == 0 and bool(version.get("Server")))
    add("DOCKER_CLIENT", "ENFORCED" if version.get("Client") else "UNAVAILABLE", "Client responds; not an isolation claim")
    add("LINUX_ENGINE", "ENFORCED" if reachable and info.get("OSType") == "linux" else "UNAVAILABLE", "Requires successful server and info responses from a Linux engine")
    add("COMPOSE_CLIENT", "ENFORCED" if raw["compose_version"]["exit_code"] == 0 else "UNAVAILABLE", "Compose client only; no deployment inferred")
    endpoint = raw["docker_endpoint"]["stdout"].strip('"')
    # Environment overrides affect what docker actually talks to, even with a selected context.
    override = raw.get("docker_host_override", "")
    # Fail closed if either the selected context or an environment override is remote.
    # This also avoids guessing precedence between DOCKER_CONTEXT and DOCKER_HOST.
    local = local_endpoint(endpoint) and (not override or local_endpoint(override))
    add("LOCAL_DAEMON", "ENFORCED" if local else "UNAVAILABLE", "Active endpoint must be local; TCP/SSH/unknown endpoints cannot run the fixture")
    add("CGROUP_V2_AVAILABLE", "ENFORCED" if reachable and str(info.get("CgroupVersion")) == "2" else "UNAVAILABLE", "Daemon metadata availability only; fixture checks actual limits separately")
    for name in fixture_checks(""):
        add(name, "UNTESTED", "No successful approved local synthetic fixture")
    probe = raw.get("fixture")
    fixture_ok = False
    if probe is not None:
        approved = image_approved(raw.get("probe_image", ""), policy)
        results = fixture_checks(probe["stdout"]) if probe["exit_code"] == 0 else fixture_checks("")
        for name, passed in results.items():
            passed = passed and approved and local and reachable and info.get("OSType") == "linux"
            add(name, "ENFORCED" if passed else "FAILED", "Synthetic fixture only; not full arena policy coverage")
        fixture_ok = approved and local and reachable and info.get("OSType") == "linux" and all(results.values()) and probe["exit_code"] == 0
    for name in ("CROSS_CELL_NETWORK_POLICY", "CPUSET_EXCLUSIVITY", "SMT_SEPARATION", "IO_FAIRNESS", "ROOTLESS_OR_USERNS", "GVISOR_OR_MICROVM", "MODEL_LANES_AND_RESET", "MTLS_AND_ABAC", "RECORDER_WITNESS_BOUNDARY"):
        add(name, "UNTESTED", "Requires actual deployed arena/host tests; tool availability is insufficient")
    return {
        "controls": controls,
        "synthetic_fixture_ready": fixture_ok,
        "arena_ready": False,
        "guarantee_tier_achieved": None,
        "linux_engine_reachable": reachable and info.get("OSType") == "linux",
        "daemon": {key: info.get(key) for key in ("ServerVersion", "OSType", "Architecture", "KernelVersion", "OperatingSystem", "CgroupVersion", "CgroupDriver", "NCPU", "MemTotal", "SecurityOptions")},
        "docker_client_version": version.get("Client", {}).get("Version"),
        "compose_version": raw["compose_version"]["stdout"] if raw["compose_version"]["exit_code"] == 0 else None,
        "blockers": [key for key, value in controls.items() if value["state"] != "ENFORCED"],
    }


def collect(policy: dict, image: str | None) -> dict:
    raw = {
        "docker_version": run_command(["docker", "version", "--format", "{{json .}}"]),
        "docker_info": run_command(["docker", "info", "--format", "{{json .}}"]),
        "docker_endpoint": run_command(["docker", "context", "inspect", "--format", "{{json .Endpoints.docker.Host}}"]),
        "compose_version": run_command(["docker", "compose", "version", "--short"]),
        "docker_host_override": os.environ.get("DOCKER_HOST", ""),
    }
    if platform.system() == "Windows":
        raw["host"] = run_command(["powershell", "-NoProfile", "-NonInteractive", "-Command", HOST_QUERY])
        raw["wsl"] = run_command(["wsl", "--list", "--verbose"])
    else:
        raw["host"] = {"stdout": json.dumps({"os": platform.system(), "version": platform.release(), "logical_cpus": os.cpu_count(), "effective_uid": os.geteuid() if hasattr(os, "geteuid") else None}), "exit_code": 0}
    raw["gpu"] = run_command(["nvidia-smi", "--query-gpu=name,memory.total,memory.free,driver_version", "--format=csv,noheader"])
    if image is not None:
        if not image_approved(image, policy):
            raise ValueError("Probe image must be an explicitly approved local sha256 image ID")
        initial = assess(raw, policy)
        if not initial["linux_engine_reachable"] or initial["controls"]["LOCAL_DAEMON"]["state"] != "ENFORCED":
            raise ValueError("Fixture requires a reachable local Linux daemon")
        inspected = run_command(["docker", "image", "inspect", image, "--format", "{{.Id}}"])
        raw["probe_image_inspect"] = inspected
        if inspected["exit_code"] != 0 or inspected["stdout"] != image:
            raise ValueError("Approved image is not present locally; automatic pulls are forbidden")
        name = "blindshield-preflight-" + uuid.uuid4().hex[:12]
        raw["probe_image"] = image
        try:
            raw["fixture"] = run_command([
                "docker", "run", "--rm", "--pull=never", "--name", name,
                "--network=none", "--read-only", "--user=65534:65534", "--cap-drop=ALL",
                "--security-opt=no-new-privileges=true", "--pids-limit=32",
                "--memory=128m", "--memory-swap=128m", "--cpus=0.5", "--cgroupns=private",
                "--entrypoint=/bin/sh", image, "-c", FIXTURE_SCRIPT,
            ], timeout=20)
        finally:
            # Exact generated name only; never stop/prune other workloads.
            raw["fixture_cleanup"] = run_command(["docker", "rm", "--force", name])
    return raw


def write_new(path: Path, value: dict) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    with path.open("x", encoding="utf-8", newline="\n") as stream:
        json.dump(value, stream, ensure_ascii=True, indent=2)
        stream.write("\n")


def receipt_path(path: Path) -> Path:
    resolved = path.resolve()
    allowed = (ROOT / "artifacts/preflight", REPOSITORY / "memory files/hackathon/evidence")
    if resolved.suffix != ".json" or not any(resolved.is_relative_to(parent.resolve()) for parent in allowed):
        raise ValueError("Receipt must be a JSON file inside artifacts/preflight or memory files/hackathon/evidence")
    return resolved


def main() -> int:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True, help="New sanitized receipt path; existing files are never overwritten")
    parser.add_argument("--probe-image", help="Explicitly approved local sha256 image ID; never pulls")
    args = parser.parse_args()
    try:
        output = receipt_path(args.output)
        if output.exists():
            raise ValueError("Output already exists; choose a new receipt name")
        policy = json.loads(CONFIG.read_text(encoding="utf-8"))
        if args.probe_image and not image_approved(args.probe_image, policy):
            raise ValueError("Image not approved; policy starts with no admitted images")
        raw = collect(policy, args.probe_image)
        report = assess(raw, policy)
        run_id = uuid.uuid4().hex
        private = ROOT / "artifacts/preflight" / run_id / "raw.json"
        write_new(private, raw)
        report.update({
            "schema": "arena-preflight.v1", "run_id": run_id,
            "observed_at_utc": datetime.now(timezone.utc).isoformat(),
            "scope": "N01 local readiness; no arena acceptance or model benchmark",
            "host": parsed(raw["host"]),
            "workspace_free_bytes": shutil.disk_usage(ROOT).free,
            "gpu_inventory": raw["gpu"]["stdout"] if raw["gpu"]["exit_code"] == 0 else None,
            "raw_receipt": private.relative_to(ROOT).as_posix(),
            "raw_receipt_sha256": hashlib.sha256(private.read_bytes()).hexdigest(),
            "tool_sha256": hashlib.sha256(Path(__file__).read_bytes()).hexdigest(),
            "policy_sha256": hashlib.sha256(CONFIG.read_bytes()).hexdigest(),
            "command_results": {key: {field: val for field, val in value.items() if field not in ("stdout", "stderr")} for key, value in raw.items() if isinstance(value, dict) and "argv" in value},
        })
        # Full argv contains the local host query, but no host paths, private keys or prompts.
        write_new(output, report)
        print(json.dumps({"result": "FIXTURE_READY" if report["synthetic_fixture_ready"] else "NOT_READY", "linux_engine_reachable": report["linux_engine_reachable"], "arena_ready": False, "guarantee_tier_achieved": None, "output": str(args.output)}))
        return 0 if report["synthetic_fixture_ready"] else 2
    except (OSError, ValueError, KeyError) as exc:
        print("Preflight error: " + str(exc), file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())

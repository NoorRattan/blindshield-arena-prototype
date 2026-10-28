"""Scoped Docker Desktop/Linux CPU lane and per-call frozen defense cells.

Uses only locked local images. No pulls, builds, arbitrary routes or tenant Docker
socket. Docker administration is trusted; Windows ACL/host-root isolation and
complete network/side-channel acceptance are explicitly outside this component.
"""

import asyncio
import json
import os
from pathlib import Path
import subprocess
import time
from uuid import uuid4

from arena.adapters.llama_adapter import LlamaModelAdapter
from arena.contracts.api import DefenseDecision
from arena.contracts.crypto import sha256
from arena.contracts.jsonwire import load_wire, strict_json
from arena.ports import DependencyUnavailable
from .types import AdmissionLock


def runtime_source_hashes():
    root = Path(__file__).resolve().parents[3]
    paths = sorted((root / "src/arena").rglob("*.py"))
    paths.extend(
        [
            root / "infra/cells/defense.py",
            root / "infra/cells/Dockerfile.defense",
            root / "config/n04-sources.json",
        ]
    )
    return {
        path.relative_to(root).as_posix(): sha256(path.read_bytes()) for path in paths
    }


def docker(*args, timeout=30):
    result = subprocess.run(["docker", *args], capture_output=True, timeout=timeout)
    if result.returncode:
        # Docker diagnostics can contain paths/payloads. Keep them local, not in participant errors.
        raise DependencyUnavailable("DOCKER_OPERATION_FAILED")
    return result.stdout


def ensure_local_docker():
    context_override = os.environ.get("DOCKER_CONTEXT")
    host_override = os.environ.get("DOCKER_HOST")
    if host_override and not context_override:
        endpoint = host_override
    else:
        name = context_override or docker("context", "show").decode().strip()
        info = json.loads(docker("context", "inspect", name))[0]
        endpoint = info["Endpoints"]["docker"]["Host"]
    if not (
        endpoint.startswith("npipe:////./pipe/") or endpoint.startswith("unix:///")
    ):
        raise DependencyUnavailable("N04_REQUIRES_LOCAL_DOCKER_ENDPOINT")


async def bounded_exchange(args, body, timeout):
    process = await asyncio.create_subprocess_exec(
        *args,
        stdin=asyncio.subprocess.PIPE,
        stdout=asyncio.subprocess.PIPE,
        stderr=asyncio.subprocess.DEVNULL,
    )

    async def exchange():
        process.stdin.write(body)
        await process.stdin.drain()
        process.stdin.close()
        chunks = []
        size = 0
        while chunk := await process.stdout.read(4096):
            size += len(chunk)
            if size > 70000:
                raise DependencyUnavailable("CELL_RESPONSE_SIZE_EXCEEDED")
            chunks.append(chunk)
        output = b"".join(chunks)
        await process.wait()
        if process.returncode:
            raise DependencyUnavailable("CELL_REQUEST_FAILED")
        return strict_json(output)

    try:
        return await asyncio.wait_for(exchange(), timeout=timeout)
    finally:
        if process.returncode is None:
            process.kill()
            await process.wait()


class DockerExecModelAdapter(LlamaModelAdapter):
    """Same private HTTP protocol inside a no-network cell, without a host socket."""

    def __init__(self, container, timeout_sec, input_token_cap):
        super().__init__(
            endpoint_url="http://127.0.0.1:8080",
            max_lanes=1,
            timeout_sec=timeout_sec,
            input_token_cap=input_token_cap,
        )
        self.container = container

    async def _request_json(self, path, content):
        if path not in {"/tokenize", "/completion", "/slots/0?action=erase"}:
            raise DependencyUnavailable("PRIVATE_MODEL_ROUTE_DENIED")
        return await bounded_exchange(
            [
                "docker",
                "exec",
                "--interactive",
                self.container,
                "curl",
                "--silent",
                "--show-error",
                "--fail",
                "--max-time",
                str(self.timeout_sec),
                "--noproxy",
                "*",
                "--header",
                "Content-Type: application/json",
                "--data-binary",
                "@-",
                "http://127.0.0.1:8080" + path,
            ],
            json.dumps(content).encode(),
            self.timeout_sec,
        )

    async def _erase_server_slot(self, lane_id):
        try:
            data = await self._request_json("/slots/0?action=erase", {})
            if (
                type(data.get("id_slot")) is not int
                or data["id_slot"] != 0
                or type(data.get("n_erased")) is not int
                or data["n_erased"] < 0
            ):
                raise DependencyUnavailable("MODEL_RESET_UNCONFIRMED")
        except BaseException:
            self._poisoned_lanes.add(lane_id)
            raise


class DockerRuntime:
    lane_count = 1

    def model_resource_args(self):
        return []

    def defense_resource_args(self):
        return []

    def __init__(self, lock_path: Path, model_path: Path, private_root: Path):
        self.lock_bytes = lock_path.read_bytes()
        self.lock = load_wire(AdmissionLock, self.lock_bytes).model_dump()
        self.model_path = Path(model_path).resolve()
        self.root = Path(private_root).resolve()
        self.root.mkdir(parents=True, exist_ok=False)
        suffix = uuid4().hex
        self.container = "arena-n04-model-" + suffix
        self.model = None
        self.started = False
        self._owns_local_resources = False

    def start(self):
        ensure_local_docker()
        self._owns_local_resources = True
        if runtime_source_hashes() != self.lock["runtime_source_sha256"]:
            raise DependencyUnavailable(
                "FROZEN_RUNTIME_SOURCE_CHANGED_REPREPARE_ADMISSION"
            )
        h = __import__("hashlib").sha256()
        with self.model_path.open("rb") as stream:
            while chunk := stream.read(1048576):
                h.update(chunk)
        if h.hexdigest() != self.lock["model_sha256"]:
            raise DependencyUnavailable("MODEL_BYTES_CHANGED")
        if (
            sha256((self.model_path.parent / "LICENSE").read_bytes())
            != self.lock["model_license_sha256"]
        ):
            raise DependencyUnavailable("MODEL_LICENSE_BYTES_CHANGED")
        for image in (self.lock["llama_image"], self.lock["defense_image"]):
            if not (image.startswith("sha256:") or "@sha256:" in image):
                raise DependencyUnavailable("IMMUTABLE_LOCAL_IMAGE_REQUIRED")
            docker("image", "inspect", image)
        defense = json.loads(docker("image", "inspect", self.lock["defense_image"]))[0]
        if (
            defense["Config"]["Labels"].get("arena.defense_source_sha256")
            != self.lock["defense_source_sha256"]
        ):
            raise DependencyUnavailable("DEFENSE_IMAGE_SOURCE_MISMATCH")
        model_image = json.loads(docker("image", "inspect", self.lock["llama_image"]))[
            0
        ]
        if (
            model_image["Config"]["Labels"].get("org.opencontainers.image.revision")
            != self.lock["llama_source_revision"]
        ):
            raise DependencyUnavailable("MODEL_BACKEND_REVISION_MISMATCH")
        try:
            docker(
                "run",
                "--detach",
                "--pull",
                "never",
                "--name",
                self.container,
                "--label",
                "arena.n04=true",
                "--network",
                "none",
                "--read-only",
                "--user",
                "65534:65534",
                "--cap-drop",
                "ALL",
                "--security-opt",
                "no-new-privileges",
                "--memory",
                "2g",
                "--memory-swap",
                "2g",
                "--cpus",
                "2",
                "--pids-limit",
                "128",
                "--log-driver",
                "none",
                "--tmpfs",
                "/tmp:rw,noexec,nosuid,nodev,size=64m",
                "--mount",
                f"type=bind,source={self.model_path},target=/model.gguf,readonly",
                *self.model_resource_args(),
                self.lock["llama_image"],
                "--model",
                "/model.gguf",
                "--host",
                "127.0.0.1",
                "--port",
                "8080",
                "--n-gpu-layers",
                "0",
                "--threads",
                "2",
                "--ctx-size",
                "2048",
                "--parallel",
                "1",
                "--cache-ram",
                "0",
                "--ctx-checkpoints",
                "0",
                "--no-kv-unified",
                "--no-cache-idle-slots",
                "--no-context-shift",
                "--no-webui",
                "--offline",
                "--log-disable",
                "--slots",
                "--slot-save-path",
                "/tmp",
            )
            self.model = DockerExecModelAdapter(
                self.container,
                self.lock["deadline_seconds"],
                self.lock["input_token_cap"],
            )
            deadline = time.monotonic() + 45
            while True:
                try:
                    response = docker(
                        "exec",
                        self.container,
                        "curl",
                        "--silent",
                        "--fail",
                        "--max-time",
                        "1",
                        "--noproxy",
                        "*",
                        "http://127.0.0.1:8080/health",
                        timeout=3,
                    )
                    if strict_json(response).get("status") == "ok":
                        break
                except Exception:
                    if time.monotonic() >= deadline:
                        raise DependencyUnavailable("MODEL_START_TIMEOUT")
                    time.sleep(0.2)
            self.started = True
            return self.inspect()
        except BaseException:
            self.stop()
            raise

    def inspect(self):
        if runtime_source_hashes() != self.lock["runtime_source_sha256"]:
            raise DependencyUnavailable("FROZEN_RUNTIME_SOURCE_CHANGED")
        item = json.loads(docker("inspect", self.container))[0]
        host = item["HostConfig"]
        flags = (
            item["State"]["Running"]
            and item["Config"]["User"] == "65534:65534"
            and host["ReadonlyRootfs"]
            and not host["Privileged"]
            and host["CapDrop"] == ["ALL"]
            and "no-new-privileges" in host["SecurityOpt"]
            and host["Memory"] == 2147483648
            and host["MemorySwap"] == 2147483648
            and host["PidsLimit"] == 128
            and host["NanoCpus"] == 2000000000
            and host["NetworkMode"] == "none"
            and not host["PortBindings"]
            and set(item["NetworkSettings"]["Networks"]) == {"none"}
            and all(
                not mount["RW"] for mount in item["Mounts"] if mount["Type"] == "bind"
            )
        )
        if not flags:
            raise DependencyUnavailable("MODEL_RUNTIME_POLICY_MISMATCH")
        status = docker(
            "exec",
            self.container,
            "/bin/sh",
            "-c",
            "id -u; cat /proc/self/status; cat /sys/fs/cgroup/memory.max; cat /sys/fs/cgroup/pids.max; cat /sys/fs/cgroup/cpu.max; if touch /arena-root-write-test 2>/dev/null; then exit 7; fi",
        ).decode()
        if (
            not status.startswith("65534\n")
            or "NoNewPrivs:\t1" not in status
            or "Seccomp:\t2" not in status
        ):
            raise DependencyUnavailable("EFFECTIVE_MODEL_CONFINEMENT_MISMATCH")
        lines = status.strip().splitlines()
        try:
            effective_memory, effective_pids = int(lines[-3]), int(lines[-2])
            quota, period = (int(value) for value in lines[-1].split())
            if (
                effective_memory != 2147483648
                or effective_pids != 128
                or period <= 0
                or quota != 2 * period
            ):
                raise ValueError()
        except (ValueError, IndexError):
            raise DependencyUnavailable(
                "EFFECTIVE_MODEL_CGROUP_LIMITS_MISMATCH"
            ) from None
        (self.root / "effective-kernel-status.txt").write_bytes(status.encode())
        egress = subprocess.run(
            [
                "docker",
                "exec",
                self.container,
                "curl",
                "--silent",
                "--fail",
                "--noproxy",
                "*",
                "--connect-timeout",
                "1",
                "--max-time",
                "2",
                "http://1.1.1.1",
            ],
            capture_output=True,
            timeout=5,
        )
        routes = (
            docker("exec", self.container, "cat", "/proc/net/route")
            .decode()
            .strip()
            .splitlines()
        )
        if egress.returncode == 0 or len(routes) != 1:
            raise DependencyUnavailable("MODEL_NO_NETWORK_PROBE_FAILED")
        return {
            "scope": "N04_SINGLE_MODEL_CELL_BASELINE_ONLY",
            "container_id": item["Id"],
            "image_id": item["Image"],
            "network_mode": "none",
            "published_ports": False,
            "external_ipv4_probe_denied": True,
            "ipv4_route_entries": 0,
            "transport": "TRUSTED_DOCKER_EXEC_TO_CELL_LOOPBACK",
            "effective_uid": 65534,
            "effective_no_new_privileges": True,
            "effective_seccomp_filter": True,
            "root_write_denied": True,
            "memory_limit_bytes": host["Memory"],
            "effective_cgroup_memory_limit_bytes": effective_memory,
            "effective_cgroup_pid_limit": effective_pids,
            "effective_cgroup_cpu_quota": quota,
            "effective_cgroup_cpu_period": period,
            "cpu_quota_nano": host["NanoCpus"],
            "pids_limit": host["PidsLimit"],
            "raw_effective_status_sha256": sha256(status.encode()),
            "cpuset_exclusivity_verified": False,
            "active_network_probes_complete": False,
            "windows_acl_verified": False,
            "guarantee_tier_achieved": None,
        }

    async def evaluate(self, request):
        """A fresh no-network cell per call; only anonymous permitted mode content enters."""
        name = "arena-n04-defense-" + uuid4().hex
        args = [
            "docker",
            "run",
            "--rm",
            "--interactive",
            "--pull",
            "never",
            "--name",
            name,
            "--network",
            "none",
            "--read-only",
            "--user",
            "65534:65534",
            "--cap-drop",
            "ALL",
            "--security-opt",
            "no-new-privileges",
            "--memory",
            "128m",
            "--memory-swap",
            "128m",
            "--cpus",
            "0.5",
            "--pids-limit",
            "16",
            "--log-driver",
            "none",
            *self.defense_resource_args(),
            self.lock["defense_image"],
        ]
        try:
            raw = await bounded_exchange(args, request.model_dump_json().encode(), 10)
            decision = DefenseDecision.model_validate(raw)
            if decision.call_token != request.call_token:
                raise DependencyUnavailable("DEFENSE_CALL_TOKEN_MISMATCH")
            return decision
        finally:
            # Killing a Docker client does not prove its container stopped.
            await asyncio.to_thread(
                subprocess.run,
                ["docker", "rm", "--force", name],
                capture_output=True,
                timeout=15,
            )

    def stop(self):
        if not self._owns_local_resources:
            return
        subprocess.run(
            ["docker", "rm", "--force", self.container], capture_output=True, timeout=15
        )
        self.started = False

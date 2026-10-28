"""Operator-only, bounded N05 observations. Not the full fifteen-probe suite."""

import asyncio
import json
import subprocess
import time
from uuid import uuid4

from arena.ports import DependencyUnavailable
from .runtime import docker


def fixture_args(image, cpuset, *, network="none", name=None):
    args = ["run", "--pull", "never", "--network", network, "--read-only", "--user", "65534:65534",
            "--cap-drop", "ALL", "--security-opt", "no-new-privileges", "--memory", "128m",
            "--memory-swap", "128m", "--cpus", "0.5", "--cpuset-cpus", cpuset,
            "--pids-limit", "16", "--log-driver", "none"]
    args += ["--detach", "--name", name] if name else ["--rm"]
    return args + ["--entrypoint", "python", image, "-I", "-c"]


def synthetic_network_control(runtime):
    """Matched none/shared-netns control, separate synthetic listener, no real data."""
    name = "arena-n05-synthetic-network-" + uuid4().hex
    marker = "N05_NETWORK_CANARY_" + uuid4().hex
    script = (
        "from http.server import BaseHTTPRequestHandler,HTTPServer\n"
        "class Handler(BaseHTTPRequestHandler):\n"
        " def do_GET(self):\n"
        "  self.send_response(200); self.end_headers(); self.wfile.write(" + repr(marker.encode()) + ")\n"
        " def log_message(self,*args): pass\n"
        "HTTPServer(('127.0.0.1',8080),Handler).serve_forever()\n"
    )
    image, cpus = runtime.lock["defense_image"], runtime.admission.defense_cpuset
    def attempt(network):
        probe = (
            "import urllib.request,json\n"
            "try:\n"
            " data=urllib.request.build_opener(urllib.request.ProxyHandler({})).open('http://127.0.0.1:8080/slots',timeout=2).read(1024)\n"
            " print(json.dumps({'canary_detected':data==" + repr(marker.encode()) + "}))\n"
            "except OSError: print(json.dumps({'canary_detected':False}))\n"
        )
        return json.loads(docker(*fixture_args(image, cpus, network=network), probe))
    try:
        docker(*fixture_args(image, cpus, name=name), script)
        for _ in range(20):
            try:
                docker("exec", name, "python", "-I", "-c",
                       "import socket; socket.create_connection(('127.0.0.1',8080),1).close()")
                break
            except DependencyUnavailable:
                time.sleep(.1)
        else:
            raise DependencyUnavailable("SYNTHETIC_CONTROL_LISTENER_UNAVAILABLE")
        defended, weakened = attempt("none"), attempt("container:" + name)
        if defended["canary_detected"] or not weakened["canary_detected"]:
            raise DependencyUnavailable("NETWORK_NEGATIVE_CONTROL_INCONCLUSIVE")
        return {"scope": "SYNTHETIC_ONLY_MATCHED_NETNS_CONTROL", "defended_canary_detected": False,
                "weakened_canary_detected": True, "private_or_real_data_used": False}
    finally:
        docker("rm", "--force", name)


DEFENSE_PROBE = """
import json,socket,os
from pathlib import Path
paths=['/health','/completion','/slots','/metrics','/props','/slots/0?action=erase']
out={}
for path in paths:
 try:
  s=socket.create_connection(('127.0.0.1',8080),.3);s.close();out[path]='REACHABLE'
 except OSError:out[path]='DENIED'
out['docker_socket_present']=Path('/var/run/docker.sock').exists()
out['model_mount_present']=Path('/model.gguf').exists()
out['effective_uid']=os.getuid()
print(json.dumps(out))
"""


def zero_clock_offsets(raw):
    rows = [line.split() for line in raw.splitlines() if line.strip()]
    return (len(rows) == 2 and {row[0] for row in rows} == {"monotonic", "boottime"}
            and all(len(row) == 3 and row[1:] == ["0", "0"] for row in rows))


def confinement_matrix(runtime):
    rows = []
    for index, cell in enumerate(runtime.cells):
        item = json.loads(docker("inspect", cell.container))[0]
        # Current image has curl and POSIX shell; no guessed image/package acquisition.
        namespaces = {}
        for kind in ("pid", "ipc", "net", "mnt", "time"):
            namespaces[kind] = docker("exec", cell.container, "readlink", "/proc/self/ns/" + kind).decode().strip()
        own = "N05_LANE_CANARY_" + uuid4().hex
        observed = docker("exec", cell.container, "/bin/sh", "-c",
                          'printf %s "$1" > /tmp/n05-canary; cat /tmp/n05-canary', "probe", own).decode()
        if observed != own:
            raise DependencyUnavailable("POSITIVE_PRIVATE_SCRATCH_CONTROL_FAILED")
        denied = {}
        for label, path in {"docker_socket": "/var/run/docker.sock", "blue_source": "/cell/defense.py",
                            "broker_vault": str(runtime.root.parent / "vault/custody.sqlite3")}.items():
            result = subprocess.run(["docker", "exec", cell.container, "cat", path], capture_output=True, timeout=5)
            denied[label] = result.returncode != 0
            if result.returncode == 0:
                raise DependencyUnavailable("PRIVATE_FILE_PROBE_FAILED")
        egress = {}
        for label, url in {
            "internet_ipv4": "http://1.1.1.1", "metadata": "http://169.254.169.254/latest/meta-data/",
            "dns_external": "http://example.com", "host_gateway_name": "http://host.docker.internal:8080/health",
            "ipv6_external": "http://[2606:4700:4700::1111]",
        }.items():
            result = subprocess.run(["docker", "exec", cell.container, "curl", "--silent", "--fail",
                                     "--noproxy", "*", "--connect-timeout", "1", "--max-time", "2", url],
                                    capture_output=True, timeout=5)
            egress[label] = {"exit_code": result.returncode, "denied": result.returncode != 0}
            if result.returncode == 0:
                raise DependencyUnavailable("NETWORK_PROBE_FAILED")
        health = json.loads(docker("exec", cell.container, "curl", "--silent", "--fail", "--noproxy", "*",
                                   "--max-time", "2", "http://127.0.0.1:8080/health"))
        if health.get("status") != "ok":
            raise DependencyUnavailable("POSITIVE_MODEL_ROUTE_FAILED")
        memory_current = int(docker("exec", cell.container, "cat", "/sys/fs/cgroup/memory.current"))
        offsets = docker("exec", cell.container, "cat", "/proc/self/timens_offsets").decode()
        if not zero_clock_offsets(offsets):
            raise DependencyUnavailable("ZERO_VM_CLOCK_OFFSETS_REQUIRED")
        rows.append({"lane": index, "container_id": item["Id"], "vm_host_pid": item["State"]["Pid"],
                     "time_namespace_offsets": offsets,
                     "namespaces": namespaces, "denied_files": denied, "egress": egress,
                     "private_scratch_positive_control": True, "own_loopback_model_health": True,
                     "memory_current_bytes": memory_current, "published_ports": item["HostConfig"]["PortBindings"]})
    for row in rows:
        peers = [other["vm_host_pid"] for other in rows if other != row]
        row["peer_process_environ_denied"] = all(subprocess.run(
            ["docker", "exec", runtime.cells[row["lane"]].container, "cat", f"/proc/{pid}/environ"],
            capture_output=True, timeout=5).returncode != 0 for pid in peers)
        if not row["peer_process_environ_denied"]:
            raise DependencyUnavailable("PEER_PROCESS_VISIBILITY_PROBE_FAILED")
    if any(len({row["namespaces"][kind] for row in rows}) != 3 for kind in ("pid", "ipc", "net", "mnt")):
        raise DependencyUnavailable("NAMESPACE_BOUNDARY_NOT_DISTINCT")
    defense = json.loads(docker(*fixture_args(runtime.lock["defense_image"], runtime.admission.defense_cpuset), DEFENSE_PROBE))
    if (any(defense[path] != "DENIED" for path in defense if path.startswith("/"))
        or defense["docker_socket_present"] or defense["model_mount_present"] or defense["effective_uid"] != 65534):
        raise DependencyUnavailable("DEFENSE_TO_MODEL_BOUNDARY_FAILED")
    return {"models": rows, "defense_fixture": defense, "network_negative_control": synthetic_network_control(runtime),
            "scope": "FINITE_LOCAL_BASELINE_PROBES_NOT_FULL_P001_P015", "host_root_prevention": False,
            "rootless": False, "noisy_neighbor_fairness": "NOT_RUN", "forensic_erasure": "NOT_CLAIMED"}


async def observe_processing(runtime, done, observations, ready, *, max_samples=600):
    """Shared VM uptime clock; checked namespaces have zero monotonic/boottime offsets.

    Captures only id/task/processing. Full slot bodies can contain prompts and are
    never persisted or sent to participants.
    """
    from decimal import Decimal
    if type(max_samples) is not int or not 1 <= max_samples <= 20000:
        raise ValueError("BOUNDED_OBSERVER_SAMPLE_CAP_REQUIRED")
    prepared = set()
    async def sample(lane, cell):
        stop = "/tmp/n05-observer-stop-" + uuid4().hex
        # Finite even if host disconnects; URL is static and arguments are trusted.
        script = '''count=0
while [ "$count" -lt "$2" ] && [ ! -f "$1" ]; do
 read before unused < /proc/uptime
 printf '{"before":"%s","slots":' "$before"
 curl --silent --fail --noproxy '*' --max-time 1 http://127.0.0.1:8080/slots || exit 9
 read after unused < /proc/uptime
 printf ',"after":"%s"}\\036' "$after"
 count=$((count+1))
 sleep .05
done'''
        process = await asyncio.create_subprocess_exec("docker", "exec", cell.container, "/bin/sh", "-c", script, "observer", stop, str(max_samples),
                stdout=asyncio.subprocess.PIPE, stderr=asyncio.subprocess.DEVNULL, limit=70000)
        try:
            while not done.is_set():
                raw = await asyncio.wait_for(process.stdout.readuntil(b"\x1e"), 4)
                data = json.loads(raw[:-1])
                slots = data["slots"]
                if type(slots) is not list or len(slots) != 1 or type(slots[0].get("is_processing")) is not bool:
                    raise DependencyUnavailable("SLOT_OBSERVATION_UNSUPPORTED")
                # /proc/uptime resolution is 10 ms; expand both brackets by one tick.
                start = int(Decimal(data["before"]) * 1_000_000_000) - 10_000_000
                end = int(Decimal(data["after"]) * 1_000_000_000) + 10_000_000
                slot = slots[0]
                observations.append({"lane": lane, "before_ns": start, "after_ns": end,
                                     "processing": slot["is_processing"], "task_id": slot.get("id_task")})
                prepared.add(lane)
                if len(prepared) == 3:
                    ready.set()
        finally:
            try:
                await asyncio.to_thread(docker, "exec", cell.container, "touch", stop, timeout=5)
                # Drain remaining private frames so a full pipe cannot prevent exit.
                await asyncio.wait_for(process.communicate(), 4)
                if process.returncode != 0:
                    raise DependencyUnavailable("OBSERVER_EXIT_UNCONFIRMED")
            finally:
                if process.returncode is None:
                    process.kill()
                    await process.wait()
    tasks = [asyncio.create_task(sample(i, cell)) for i, cell in enumerate(runtime.cells)]
    results = await asyncio.gather(*tasks, return_exceptions=True)
    for result in results:
        if isinstance(result, BaseException):
            raise result


def processing_overlap(observations):
    intervals = []
    for lane in range(3):
        busy = [row for row in observations if row["lane"] == lane and row["processing"]]
        groups = {}
        for row in busy:
            if type(row["task_id"]) is not int:
                continue
            groups.setdefault(row["task_id"], []).append(row)
        intervals.append([(rows[0]["after_ns"], rows[-1]["before_ns"], task)
                          for task, rows in groups.items() if len(rows) >= 2])
    for a in intervals[0]:
        for b in intervals[1]:
            for c in intervals[2]:
                start, end = max(a[0], b[0], c[0]), min(a[1], b[1], c[1])
                if end > start:
                    return {"result": "OBSERVED", "conservative_overlap_ns": end-start,
                            "interval_begin_ns": start, "interval_end_ns": end,
                            "task_ids": [a[2], b[2], c[2]],
                            "clock": "SHARED_LINUX_VM_UPTIME_ZERO_NAMESPACE_OFFSETS_10MS_BRACKETS",
                            "assumption": "One admitted generation per cell in this sampling wave; trusted pinned slot reporter"}
    return {"result": "INCONCLUSIVE", "conservative_overlap_ns": 0}

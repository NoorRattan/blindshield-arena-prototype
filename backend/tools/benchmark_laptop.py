"""Small existing-PyTorch training microbenchmark; no downloads or installs.

This is synthetic tensor throughput, not an LLM training or arena benchmark.
"""

import argparse
import gc
import json
import os
import platform
import statistics
import time
from datetime import datetime, timezone
from pathlib import Path


def run(device, torch):
    def sync():
        if device != "cpu":
            torch.cuda.synchronize()

    torch.manual_seed(0)
    model = torch.nn.Sequential(
        torch.nn.Linear(256, 512), torch.nn.ReLU(), torch.nn.Linear(512, 256)
    ).to(device)
    optim = torch.optim.AdamW(model.parameters(), lr=0.001)
    x = torch.randn(64, 256, device=device)
    target = torch.randn(64, 256, device=device)

    def step():
        optim.zero_grad(set_to_none=True)
        loss = torch.nn.functional.mse_loss(model(x), target)
        loss.backward()
        optim.step()

    for _ in range(3):
        step()
    sync()
    samples = []
    start = time.perf_counter()
    while len(samples) < 200 and (len(samples) < 10 or time.perf_counter() - start < 2):
        sync()
        t = time.perf_counter()
        step()
        sync()
        samples.append((time.perf_counter() - t) * 1000)
    result = {
        "device": device,
        "steps": len(samples),
        "median_step_ms": statistics.median(samples),
        "mean_step_ms": statistics.mean(samples),
        "batch_size": 64,
        "dtype": "float32",
        "model": "Linear(256,512),ReLU,Linear(512,256)",
        "optimizer": "AdamW",
        "includes_forward_backward_optimizer": True,
        "gpu_synchronized_per_step": device != "cpu",
        "raw_step_ms": samples,
    }
    del model, optim, x, target
    gc.collect()
    if device != "cpu":
        torch.cuda.empty_cache()
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", type=Path, required=True)
    parser.add_argument("--device", choices=("cpu", "accelerator"), default="cpu")
    args = parser.parse_args()
    result = {
        "scope": "synthetic MLP training microbenchmark only; not LLM or arena acceptance",
        "timestamp_utc": datetime.now(timezone.utc).isoformat(),
        "python": platform.python_version(),
        "machine": platform.machine(),
        "logical_cpus": os.cpu_count(),
        "results": [],
        "errors": [],
        "installs_or_downloads": False,
        "requested_device": args.device,
    }
    try:
        import torch
        torch.set_num_threads(4)
        result.update(torch_version=torch.__version__, cuda_build=torch.version.cuda,
                      hip_build=getattr(torch.version, "hip", None), cpu_threads=4)
        result["results"].append(run("cpu", torch))
        if args.device == "accelerator" and torch.cuda.is_available():
            p = torch.cuda.get_device_properties(0)
            result["accelerator"] = {
                "torch_device_name": p.name, "reported_memory_bytes": p.total_memory,
                "backend": "ROCm/HIP" if getattr(torch.version, "hip", None) else "CUDA",
            }
            try:
                result["results"].append(run("cuda:0", torch))
            except Exception as exc:
                result["errors"].append({"device": "cuda:0", "error": str(exc)[:1000]})
    except Exception as exc:
        result["errors"].append({"device": "initialization_or_cpu", "error": str(exc)[:1000]})
    args.output.parent.mkdir(parents=True, exist_ok=True)
    args.output.write_text(json.dumps(result, indent=2) + "\n", encoding="utf-8")
    summary = {k: v for k, v in result.items() if k != "results"}
    summary["results"] = [{k: v for k, v in r.items() if k != "raw_step_ms"} for r in result["results"]]
    print(json.dumps(summary, indent=2))


if __name__ == "__main__":
    main()

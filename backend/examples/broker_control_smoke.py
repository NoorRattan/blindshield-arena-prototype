"""Exercise actual CLI + HTTPS with temporary developer credentials, then stop the server.

No model is called. POLICY_NOT_READY at start is the required successful outcome.
"""

import json
from pathlib import Path
import subprocess
import sys
import tempfile


ROOT = Path(__file__).resolve().parents[1]


def run(*args, expected=0):
    result = subprocess.run([sys.executable, "-m", "arena.broker", *map(str, args)], cwd=ROOT,
                            capture_output=True, text=True, timeout=20)
    if result.returncode != expected:
        raise RuntimeError("Unexpected local CLI result")
    return json.loads(result.stdout)


def main():
    parent = ROOT / "artifacts"
    parent.mkdir(exist_ok=True)
    with tempfile.TemporaryDirectory(prefix="broker-cli-", dir=parent) as temporary:
        directory = Path(temporary) / "credentials"
        run("init", "--config", ROOT / "config/broker-demo.json", "--directory", directory)
        process = subprocess.Popen([sys.executable, "-u", "-m", "arena.broker", "serve", "--directory", str(directory), "--port", "0"],
                                   cwd=ROOT, stdout=subprocess.PIPE, stderr=subprocess.PIPE, text=True)
        try:
            # CLI startup output is fixed safe metadata, not private request/certificate logs.
            import queue
            import threading
            pending = queue.Queue()
            threading.Thread(target=lambda: pending.put(process.stdout.readline()), daemon=True).start()
            port = json.loads(pending.get(timeout=15))["port"]
            request_body = Path(temporary) / "request.json"
            config = json.loads((ROOT / "config/broker-demo.json").read_bytes())
            request_body.write_text(json.dumps(config["profiles"][0]["request"]), encoding="utf-8")
            base = ("request", "--directory", directory, "--port", port)
            first = run(*base, "--identity", "operator", "--method", "POST", "--path", "/v1/experiments", "--body", request_body, "--key", "create")
            assert first["http_status"] == 201
            assert run(*base, "--identity", "operator", "--method", "POST", "--path", "/v1/experiments", "--body", request_body, "--key", "create") == first
            identifier, epoch = first["body"]["experiment_id"], first["body"]["epoch"]
            request_body.write_text(json.dumps({"epoch": epoch, "items": [{"item_id": "smoke", "text": "synthetic-cli-only"}]}), encoding="utf-8")
            assert run(*base, "--identity", "red", "--method", "POST", "--path", f"/v1/experiments/{identifier}/attacks", "--body", request_body, "--key", "upload")["http_status"] == 201
            request_body.write_text(json.dumps({"epoch": epoch}), encoding="utf-8")
            assert run(*base, "--identity", "operator", "--method", "POST", "--path", f"/v1/experiments/{identifier}/seal", "--body", request_body, "--key", "seal")["http_status"] == 200
            assert run(*base, "--identity", "blue", "--method", "GET", "--path", f"/v1/experiments/{identifier}/status")["body"] == {"status": "EMBARGOED"}
            blocked = run(*base, "--identity", "operator", "--method", "POST", "--path", f"/v1/experiments/{identifier}/start", "--body", request_body, "--key", "start", expected=2)
            assert blocked["http_status"] == 503 and blocked["body"]["code"] == "POLICY_NOT_READY"
            run("revoke", "--directory", directory, "--subject", "red")
            assert run(*base, "--identity", "red", "--method", "GET", "--path", f"/v1/experiments/{identifier}/status", expected=2)["http_status"] == 401
            print(json.dumps({"result": "PASS", "scope": "actual local CLI/mTLS/SQLite control flow; no model, evidence authority or isolation acceptance", "checks": 8}))
        finally:
            process.terminate()
            try:
                process.communicate(timeout=10)
            except subprocess.TimeoutExpired:
                process.kill()
                process.communicate(timeout=5)


if __name__ == "__main__":
    main()

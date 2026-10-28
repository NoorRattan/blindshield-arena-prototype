"""Local N03 control-plane CLI. No inference, sandbox or evidence success is implied."""

import argparse
import http.client
import json
from pathlib import Path
import ssl
import sys

from arena.contracts.jsonwire import load_wire
from .config import BrokerConfig
from .core import Broker
from .provision import initialize
from .server import Server, tls_context
from .store import Store
from .alerts import OperatorAlerts, journal_path


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    sub = parser.add_subparsers(dest="command", required=True)
    init = sub.add_parser("init")
    init.add_argument("--config", type=Path, required=True)
    init.add_argument("--directory", type=Path, default=Path("artifacts/broker-dev"))
    serve = sub.add_parser("serve")
    serve.add_argument("--directory", type=Path, default=Path("artifacts/broker-dev"))
    serve.add_argument("--port", type=int, default=8443)
    revoke = sub.add_parser("revoke")
    revoke.add_argument("--directory", type=Path, default=Path("artifacts/broker-dev"))
    revoke.add_argument("--subject", required=True)
    alerts = sub.add_parser("alerts", help="Read the private local operator journal; no HTTP route")
    alerts.add_argument("--directory", type=Path, default=Path("artifacts/broker-dev"))
    request = sub.add_parser("request")
    request.add_argument("--directory", type=Path, default=Path("artifacts/broker-dev"))
    request.add_argument("--port", type=int, default=8443)
    request.add_argument("--identity", required=True, help="Selects a local client certificate, never an identity header")
    request.add_argument("--method", choices=("GET", "POST"), required=True)
    request.add_argument("--path", required=True)
    request.add_argument("--body", type=Path)
    request.add_argument("--key", help="Required Idempotency-Key for POST")
    args = parser.parse_args()
    try:
        directory = args.directory
        if args.command == "alerts":
            print(json.dumps(OperatorAlerts(journal_path(directory / "broker.sqlite3")).snapshot()))
            return 0
        if args.command == "init":
            initialize(directory, load_wire(BrokerConfig, args.config.read_bytes()))
            print('{"result":"CREATED","scope":"local developer credentials only"}')
            return 0
        if args.command in ("serve", "revoke"):
            store = Store(directory / "broker.sqlite3", (directory / "vault.key").read_bytes())
            store.initialize()
            if args.command == "revoke":
                store.revoke(args.subject)
                print('{"result":"REVOKED"}')
                return 0
            store.recover_ambiguous()
            broker = Broker(store, load_wire(BrokerConfig, (directory / "config.json").read_bytes()))
            context = tls_context(directory / "server.pem", directory / "server.key", directory / "ca.pem")
            with Server(("127.0.0.1", args.port), broker, context) as server:
                print(json.dumps({"scope": "N03 local control plane; execution unavailable", "port": server.server_address[1]}), flush=True)
                server.serve_forever(poll_interval=0.1)
            return 0
        identities = json.loads((directory / "identities.json").read_bytes())
        label = identities[args.identity]["label"]
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
        context.minimum_version = ssl.TLSVersion.TLSv1_2
        context.load_verify_locations(cafile=str(directory / "ca.pem"))
        context.load_cert_chain(str(directory / f"{label}.pem"), str(directory / f"{label}.key"))
        headers = {}
        body = args.body.read_bytes() if args.body else None
        if args.method == "POST":
            if not args.key or body is None:
                raise ValueError("POST requires body and key")
            headers = {"Idempotency-Key": args.key, "Content-Type": "application/json"}
        connection = http.client.HTTPSConnection("127.0.0.1", args.port, context=context, timeout=10)
        try:
            connection.request(args.method, args.path, body, headers)
            response = connection.getresponse()
            print(json.dumps({"http_status": response.status, "body": json.loads(response.read(100_000))}))
            return 0 if response.status < 400 else 2
        finally:
            connection.close()
    except KeyboardInterrupt:
        return 0
    except Exception:
        print('{"result":"FAIL","code":"LOCAL_BROKER_COMMAND_FAILED"}', file=sys.stderr)
        return 2


if __name__ == "__main__":
    raise SystemExit(main())

# BlindShield Arena console

React 18, TypeScript and Vite console for operator, red-team, blue-team and auditor workflows.

```sh
npm ci
npm run dev
```

Open http://127.0.0.1:5173. The submission UI runs in live mode only. Missing backend values display **NIL**. Model execution requires a separately admitted N04 service.

## Checks

```sh
npm run verify
```

This runs type checking, ESLint, Vitest and the production build. Browser suites use Playwright through `npm run e2e:smoke` and need compatible browser binaries. See [the evaluator guide](../EVALUATION.md) for executed results.

The current delivery passed 284 Vitest tests, type checking, lint and build. Four
smoke/accessibility cases and two judge-walkthrough cases passed across desktop
and mobile viewports using Playwright with installed Microsoft Edge. This is not
a rerun of the entire historical 96-case browser suite.

## Live local connection

Live mode now opens a dedicated API console instead of the mock dashboard. Its loopback-only Vite proxy presents the backend's role-specific mTLS certificate. The browser sends no role or certificate identity headers; backend identity and access decisions come from the TLS certificate. Certificate verification stays enabled against the configured local CA.

Start the backend separately using its owner-managed release runbook. Then launch Vite with the TLS directory and the actual loopback service port:

```powershell
$env:BLINDSHIELD_TLS_DIR = 'C:\path\to\private-backend-output\tls'
$env:VITE_BACKEND_URL = 'https://127.0.0.1:PORT'
npm run dev
```

Replace `PORT` with the port reported by the backend. The local TLS directory must contain its CA certificate and role client certificates/keys. The dev proxy reads those files in the Vite process; they are not copied into the frontend or Git. The proxy rejects non-loopback backend targets and browser origins other than `http://127.0.0.1:5173`. It is a local development aid, not a deployment gateway.

The console supports the backend's exact registered experiment request, status, seal/start/finish/close/release operations, interactive session allocation and turns, and auditor ZIP download. Experiment creation still has to match the pre-registered backend profile and prior owner-run admission. The API does not expose experiment listing, preflight, manifests, resource metrics, or an event stream; live mode does not substitute mock values for them.

### Verified scope

A real browser-to-Python mTLS smoke run passed through the Vite proxy using a disposable local N03 broker fixture. It verified operator create/seal, red-role status, and the blue-role embargo. It made no model calls. This confirms the transport and these control-plane routes; it does not validate the separately admitted three-lane N04 model service from the browser. The 284-test Vitest suite, typecheck, lint, build, and selected UI browser cases are separate checks.

The historical 96-case Playwright receipt predates this frontend delivery and remains historical.


### Live-only video submission

The submission UI is locked to live mode, including when old browser storage requests simulation. The production client uses LiveArenaClient directly. Historical mock fixtures remain for automated tests and are not selected by the submission UI. The existing design system and navigation are retained. Values absent from the backend display NIL.

The demonstrated flow is operator create/seal, red status and blue embargo. Model output, latency, attack success, witness status and evidence verification are NIL until supplied by an admitted backend. N03 refuses model execution with POLICY_NOT_READY. Prior simulation test receipts are historical and do not validate this delivery.

For a fresh local control-plane run, prepare backend dependencies from requirements.lock and frontend dependencies with npm ci. From the repository root, set PYTHONPATH to backend/src, then run python -m arena.broker init --config backend/config/broker-demo.json --directory .local-evaluation/local-run/tls followed by python -m arena.broker serve --directory .local-evaluation/local-run/tls --port 18443. In another terminal under frontend, set BLINDSHIELD_TLS_DIR to the absolute generated tls directory and VITE_BACKEND_URL to https://127.0.0.1:18443, then run npm run dev. Credentials remain ignored locally. Do not initialize over an existing credential directory. The local operator holds all role certificates; this is a single-host demonstration.

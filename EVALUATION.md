# Prototype evaluation guide

## Console walkthrough

From `frontend/`, run `npm ci` and `npm run dev`, then open http://localhost:5173 in **SIMULATED DATA** mode.

1. Explore Overview and Setup to inspect configuration and profile presets.
2. Open War Room and compare operator, red-team, blue-team and auditor views.
3. Submit a simulated attack in Red Portal and inspect lifecycle states.
4. Review embargo, evidence and invalid/failure views.

These steps exercise frontend simulation and do not demonstrate real inference. To use live mode, start the separately admitted backend and configure the local mTLS proxy as described in [frontend/README.md](frontend/README.md). The live console only exposes routes the backend actually implements.

## Actual backend work

The [service guide](backend/docs/PROTOTYPE-SERVICE.md) describes the authenticated lifecycle. The [release runbook](backend/docs/PROTOTYPE-RELEASE.md) covers real-model preparation, admission, execution and offline verification.

Those commands need owner-provisioned model, corpus, images and private authorities, deliberately absent from Git. Backend runtime/admission bytes match the reviewed snapshot that passed fresh prepared-host acceptance at `2f73df8`.

The retained summary records six real-model calibration calls, six authenticated demo calls, three-lane overlap, offline verification exit 0 and cleanup. An earlier mounted-filesystem run failed its overlap observation and remains separately disclosed. Linux/WSL used the same laptop, not independent hardware.

## Application checks

Frontend, from `frontend/`:

```sh
npm run verify
```

Backend, from `backend/`, with Python 3.12 and an isolated environment:

```sh
python -m venv .venv
.venv/Scripts/python.exe -m pip install -r requirements.lock
.venv/Scripts/python.exe -m pip install --no-build-isolation --no-deps -e .
.venv/Scripts/python.exe -m pytest -q tests --ignore=tests/test_memory_acceptance_evidence.py --ignore=tests/test_memory_revision_support.py --ignore=tests/test_n05_candidate_inventory.py --ignore=tests/test_n08_owner_delegated_inputs.py
```

The commands above use the Windows virtual-environment interpreter. On Linux, use `.venv/bin/python` in place of `.venv/Scripts/python.exe`. Three modules are omitted with private memory/registry fixtures. The fourth retained module checks historical owner inputs absent from this snapshot. The public subset previously passed 548 tests and 14 subtests, with one unsupported coordinated-rollback skip. This is not a fresh backend test run of this checkout.

## Current validation

The current package passed these checks with Node 24.19.0 and npm 11.17.0:

| Check | Result and scope |
| --- | --- |
| Type checking and ESLint | PASS |
| Vitest | 284 tests across 32 files passed |
| Production build | PASS, with large-chunk warnings |
| Browser smoke/accessibility | Four cases passed across desktop and mobile viewports |
| Judge walkthrough | Two cases passed across desktop and mobile viewports |
| Browser-to-Python mTLS | PASS through Vite proxy against a disposable N03 broker: operator create/seal, red status, and blue embargo; zero model calls |
| Backend bytes | Runtime/admission inputs match the earlier freshly admitted source; no new model workload was launched for packaging |
| Privacy | Bounded staged-content and reachable-history check passed before release |

Browser checks used Playwright 1.50.1 with installed Microsoft Edge in headless
mode. The four smoke/accessibility and two walkthrough cases exercised the
frontend simulation. A separate browser smoke connected the UI through Vite's
loopback mTLS proxy to a temporary Python N03 control-plane fixture and verified
operator create/seal plus role-scoped red/blue status. That run made no model
calls and does not validate the separately admitted N04 model service from the
browser. The walkthrough now waits for visible UI readiness instead of network
idleness and checks the updated static embargo projection. Its earlier timeout
and stale-label failures remain retained privately and are summarized in the
current validation record.

See [the current package validation record](backend/evidence/prototype-repository-validation-20261028.json).
Historical backend evidence remains in [the snapshot summary](backend/evidence/public-snapshot-validation-20261028.json).
The earlier 96-case browser receipt predates the new frontend and is not a claim
that the entire browser suite was rerun for this package.

## Acceptance and limits

[Step 6](backend/docs/STEP6-ACCEPTANCE.md) reports 19 PASS, 15 PARTIAL and one INCONCLUSIVE result across 35 procedures. These are procedure outcomes, not defense accuracy. Isolated cache timing, resource fairness, physical-I/O enforcement, full route coverage and independent-hardware portability remain open.

Dependency audits and SBOMs are disclosure, not a clean bill of health. The frontend lockfile has known advisories, and some inventory entries remain NOASSERTION. No model, corpus or image binaries are distributed here.


### Live-only video submission

The submission UI is locked to live mode, including when old browser storage requests simulation. The production client uses LiveArenaClient directly. Historical mock fixtures remain for automated tests and are not selected by the submission UI. The existing design system and navigation are retained. Values absent from the backend display NIL.

The demonstrated flow is operator create/seal, red status and blue embargo. Model output, latency, attack success, witness status and evidence verification are NIL until supplied by an admitted backend. N03 refuses model execution with POLICY_NOT_READY. Prior simulation test receipts are historical and do not validate this delivery.

For a fresh local control-plane run, prepare backend dependencies from requirements.lock and frontend dependencies with npm ci. From the repository root, set PYTHONPATH to backend/src, then run python -m arena.broker init --config backend/config/broker-demo.json --directory .local-evaluation/local-run/tls followed by python -m arena.broker serve --directory .local-evaluation/local-run/tls --port 18443. In another terminal under frontend, set BLINDSHIELD_TLS_DIR to the absolute generated tls directory and VITE_BACKEND_URL to https://127.0.0.1:18443, then run npm run dev. Credentials remain ignored locally. Do not initialize over an existing credential directory. The local operator holds all role certificates; this is a single-host demonstration.

Latest recording deck: `submission/BlindShield_Arena_Final_Submission_Live_Prototype.pptx` (10 slides; problem statement on slide 2). The older decks are retained as previous revisions.

With both local services running, `node frontend/scripts/verify-live.mjs` checks live-only startup even with an old simulated-mode preference, NIL values, public profile loading and real mTLS create/seal/status/embargo. It needs installed Microsoft Edge, or PLAYWRIGHT_CHANNEL set to a compatible installed browser channel. It makes zero model calls.

# Staged local prototype service — steps 3–5

This is a single-host offline prototype with three isolated CPU model cells. Step 6 evaluated 35 procedures with mixed results: 19 PASS, 15 PARTIAL, and 1 INCONCLUSIVE. The results do not establish full acceptance.

The Windows and Linux profiles under infra/prototype are dated host-specific artifacts. This history-free snapshot must be initialized and committed in Git before running gates because source identity is derived from committed bytes and ancestry. Its included grants bind the earlier candidate and cannot be reused. A new source root or machine needs owner-provisioned assets, authorities, admission, and calibration. This public snapshot does not include model weights, prepared corpus, private keys, raw run stores, or external rollback-anchor state.

Use PROTOTYPE-RELEASE.md for the bounded demo and verification commands. The frontend is a separate mock UI and is not connected to this service.
## Authority and preparation

Run commands from backend using .venv/Scripts/python.exe. Selected model/image pins and publisher observations are under infra/model-component/. The actual model weights and OCI image bytes are owner-provisioned and are not included. Runtime never downloads.

The prepared JBB corpus and its opening keys used for the recorded demo are not included in this source snapshot. An owner-managed local preparation and receipt are required. No corpus keys, model weights or private authority keys are committed.
The owner CA/recorder/witness public roots are pinned under
infra/owner-delegated-n08/. Their matching private authority keys remain outside
the repository in the owner's LocalAppData/BlindShield/owner-delegated-n08 folder.
A different machine needs an explicitly provisioned matching authority or a new
reviewed profile; a bundled public key alone does not establish external trust.
This owner-local demo layout does not implement tenant key distribution.

Prepare only from committed executable source. Documentation commits do not
invalidate a measured candidate whose executable hashes still match. Source,
input, profile, image, signature, expiry, CPU-set or capacity changes cause refusal.
No gate threshold is lowered to recover a failed run.

```powershell
$keys = Join-Path $env:LOCALAPPDATA 'BlindShield/owner-delegated-n08'
.\.venv\Scripts\python.exe tools/prototype_prepare.py --component infra/model-component/profile.json --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-new
.\.venv\Scripts\python.exe tools/prototype_gate.py static --profile artifacts/prototype-new/profile.json --model artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf --authority-key "$keys/recorder-private.pem" --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-new/static.json
.\.venv\Scripts\python.exe tools/prototype_calibrate.py --profile artifacts/prototype-new/profile.json --static-grant artifacts/prototype-new/static.json --model artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf --authority-key "$keys/recorder-private.pem" --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-calibration-new
.\.venv\Scripts\python.exe tools/prototype_gate.py service --profile artifacts/prototype-new/profile.json --static-grant artifacts/prototype-new/static.json --calibration artifacts/prototype-calibration-new/calibration.json --authority-key "$keys/recorder-private.pem" --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-new/service.json
```

Static admission checks exact local inputs, pinned images, dependency versions,
VM-visible whole-core partitions, disk, at least 8 GiB host-available and 7 GiB
VM-available memory. It permits calibration only. Calibration makes six actual
model calls in three cells, observes server processing overlap and cgroup peaks,
rejects OOM/insufficient fit and confirms owned-container removal. A separately
signed SERVICE grant binds that measurement and rechecks fresh capacity. Service
startup verifies the grant, live source and capacity again before loading cells.
The three lanes each retain a 2 GiB memory cap; host CPU exclusivity, fairness,
forensic erasure and population timing guarantees are not established.

## Start or demonstrate

```powershell
.\.venv\Scripts\python.exe tools/prototype_run.py --profile artifacts/prototype-new/profile.json --service-grant artifacts/prototype-new/service.json --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --authority-directory "$keys" --model artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf --corpus ../artifacts/datasets/prepared-20261019 --corpus-receipt "path/to/public-corpus-preparation.json" --corpus-keys ../artifacts/secrets/dataset-preparation.keys.json --output artifacts/prototype-live --mode INTERACTIVE --defense-mode INPUT
```

Use a fresh output directory each time. Add --demo for a finite authenticated
real-JBB run and independent offline verification, or leave it off to serve until
Ctrl+C. Use --mode SEALED_BATCH for the other interaction mode. Startup freezes
--defense-mode INPUT, FEATURES, OUTPUT or POST_HOC; callers cannot switch it through
request JSON. POST_HOC observations occur only after release and claim no prevention.
Service info, create-request.json and role-specific TLS credentials are written
under the private output directory. The listener binds only 127.0.0.1, on an
assigned local port unless --port is supplied. Cells publish no model port and
have no network, writable root, capabilities, private authority mounts or Docker socket.

## Authenticated lifecycle

Every mutation uses Content-Type application/json and Idempotency-Key. Identity
comes from a provisioned TLS client certificate; request headers cannot assign it.
All routes below are under /v1/experiments/{experiment_id} unless stated otherwise.

| Role | Request | Behavior |
|---|---|---|
| Operator | POST /v1/experiments, exact create-request.json | Create one fresh registered run; same-key replay preserves identity. |
| Red | POST /attacks, existing AttackBatch | Upload before seal; items must resolve to admitted public corpus records for batch execution. |
| Operator | POST /seal, {epoch} | Freeze profile, item references, content commitments/provenance and batch lane/order; interactive also seals transport policy. |
| Operator | POST /start, {epoch} | Return 202 operation receipt; recorder/witness bootstrap completes on the persistent loop. Batch then schedules the exact sealed list. |
| Operator | GET /operations/{operation_id} | Poll PENDING/RUNNING/DONE/FAILED and safe control result. A failed operation is not automatically rerun. |
| Operator | POST /sessions, {epoch} | Interactive only; allocate three server-owned sticky lanes. Participant admission opens after all three exist. |
| Red | POST /sessions/{session_id}/turns, existing TurnSubmission | Interactive admitted public-corpus text/reference, exact epoch and next index. One unresolved turn per session; budget and queue admission are transactional. |
| Red | GET /sessions/{session_id}/turns/{turn_id} | Fixed-size pending/final projection; no inference retry. Same-key replay cannot charge or dispatch again. |
| Red | POST /sessions/{session_id}/cancel, {epoch} | Existing durable cancel intent; ambiguous execution stays UNKNOWN/INVALID and is never refunded or automatically retried. |
| Operator | POST /finish, {epoch} | Durably stop new admissions, settle existing jobs, then reach SCORED or INVALID. It does not cancel healthy queued jobs. |
| Operator | POST /close, {epoch} | Destroy terminal model contexts, retain the exact checkpoint/witness close and prepare ordinary export. Missing evidence leaves failure/pending rather than a successful release. |
| Auditor | GET /bundle | Bounded ZIP with application/zip after a valid authoritative close. No client filesystem path is accepted. |
| Red | POST /v1/turn-feedback/recovery | Versioned `FeedbackRecoveryRequest` for the exact owned orphan reservation. It may return a separately signed stored-response replay after evidence checks; it never reruns inference, refunds budget or returns a new arena.v2 receipt. Verified recovery can close VALID_WITHIN_PROFILE with a separate reconciled bundle. Pre-existing invalidity remains INVALID; an existing original signed receipt is copied exactly. Evidence mismatches quarantine it; timeouts keep admission closed for an exact retry. |
| Auditor | GET /invalid-evidence | Separate signed incomplete-evidence ZIP after a durable CLOSED/INVALID witness close. Offline verification reports `AUTHENTIC_INVALID_INCOMPLETE`; it never releases the run. |
| Operator | POST /release, {epoch} | Valid-only release. Interactive release also waits for the latest frozen per-turn floor. |
| Red/blue | GET /feedback | Static embargo before RELEASED; authorized stored feedback afterward. No raw blue reasons or shared metrics. |
| Operator | POST /analysis, {epoch} | POST_HOC only, after release; separate linked signed observations, never rewritten turn results. |
| Auditor | GET /analysis/{turn_id} | Separately prepared linked analysis ZIP after authorized release. |

The public control response is asynchronous: wait for DONE before the next lifecycle
action. The fixed interactive policy uses a 1-second admission round, 60-second
execution deadline, 61-second release floor and 16,384-byte envelope. It is a
conservative finite engineering policy, not a certified population p99 or channel
bound. Infrastructure failure, model execution and scoring remain separate axes.

Sealed batch uses a dedicated scheduler, not interactive unpublished-job capacity.
Each item is committed to an exact input/provenance and server-owned lane/index;
the signed original artifact also binds item identity, including repeated text.
Participant batch turns and post-seal replacements are refused. The standalone
verifier checks exact sealed-item coverage and lineage with authorized openings
(--require-prototype-batch). Interactive sealed transport requires independently
supplied transport/feedback public roots (--require-transport-profile).

## Recovery and limits

The versioned POST /v1/turn-feedback/recovery route supports only the exact owned
turn/idempotency key after authenticated recovery-only startup. It returns the
exact original receipt when available, or a separately signed stored-response
replay. It never redispatches, refunds or resumes a worker. A fresh 61-second floor
applies after cold startup. Valid recovery preserves original event bytes and
destroys the anchored old model contexts before terminal close.

Use prototype_run.py --recover-only with the existing private output directory,
matching corpus and external authorities. Ordinary startup still refuses an
existing store. Private keys and recovery ledgers must remain outside the repo.

Valid reconciled bundles have an independent offline verifier for recorder,
witness, anchor and recovery authorities, private openings and transport binding.
Auditor-only INVALID/incomplete archives require their separate export authority,
remain INVALID, and expose omitted anchor/private-opening gaps. Neither archive
authorizes participant release on its own. Shared arena.v2 signing bytes are unchanged.

The separate local anchor detects coordinated application-store rollback only while its external ledger and key survive. Host-admin replacement, remote/hardware attestation, population timing, fairness, host CPU exclusivity, model quality, and full T/P acceptance remain unverified. Detailed Step 5 proof records and the private checkpoint are not included in this source snapshot. See STEP6-ACCEPTANCE.md for the procedure-level results and remaining boundaries.

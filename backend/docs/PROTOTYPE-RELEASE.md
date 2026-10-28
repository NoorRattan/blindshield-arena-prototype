# Prototype release runbook

This runbook covers setup and a bounded local demo of the BlindShield Arena backend. The profiles in infra/prototype are host-specific evidence from the measured laptop; they do not provision another host or replace owner-held authorities. A fresh machine requires owner-provisioned model, corpus, image and authority inputs plus a new admission. The backend derives source identity from Git and checks committed bytes. Initialize and commit this history-free snapshot before running gates; the included signed profiles and grants bind the earlier candidate and will not validate this new root. Generate new profiles and signatures for the committed snapshot.

The public source snapshot deliberately omits model weights, prepared corpus, private keys, raw run stores, local environments and detailed path-redacted Step 6 records. Do not use this folder as a drop-in deployment. The current reported Step 6 outcomes remain mixed: 19 PASS, 15 PARTIAL and 1 INCONCLUSIVE across 35 procedures. See STEP6-ACCEPTANCE.md for claim limits.

The candidate-bound prepared-host receipt records six real-model calibration calls, six authenticated demo calls, offline verification exit 0 and cleanup. It is same-laptop evidence, not independent-hardware validation or full acceptance. Its historical blocker fields are retained unchanged; later owner decisions selected MIT and authorized JBB use with citation, but did not resolve every contributor-rights question or verify an event extension.

### Supplemental frontend UI E2E validation

On 28 October 2026, the frontend Playwright suite passed 96 desktop and mobile cases in the matching official Playwright 1.50.1 image. The run also passed the judge-demo rehearsal, accessibility audits and role-matrix checks. It used local mock/browser state; it did not connect to the backend or real model. See the sanitized [frontend E2E receipt](../evidence/frontend-e2e-docker-20261028.json).

To repeat the UI run from the repository root in PowerShell:

~~~powershell
$frontend = (Resolve-Path .\frontend).Path
docker run --rm --init --ipc=host --volume "${frontend}:/work" --volume /work/node_modules --workdir /work --env CI=true mcr.microsoft.com/playwright@sha256:8845c40cdade98fd7a6cd32df75bfc234cd52b3278f9cd1f9fe8d6291e48ea03 bash -lc "npm ci && npx playwright test"
~~~

The frontend lock-only audit reports eight high and one moderate finding; see the [audit receipt](../evidence/frontend-npm-audit-20261028.json). No frontend source or lockfile changes were made by the run.
## Prerequisites and custody

Run these Windows commands from repository `backend/` with Python 3.12. Use
`.venv/Scripts/python.exe` for the service and the separately installed
`artifacts/repro-env/Scripts/python.exe` for independent verification. A new
environment can be prepared with:

```powershell
python -m venv .venv
.\.venv\Scripts\python.exe -m pip install -r requirements.lock
.\.venv\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
.\.venv\Scripts\python.exe -m pip check
python -m venv artifacts/repro-env
.\artifacts\repro-env\Scripts\python.exe -m pip install -r requirements.lock
.\artifacts\repro-env\Scripts\python.exe -m pip install --no-build-isolation --no-deps -e .
.\artifacts\repro-env\Scripts\python.exe -m pip check
```

These installation commands may acquire dependencies during preparation. For an
offline machine, prepare wheels for that OS/Python first and install with
`--no-index --find-links <compatible-local-wheel-directory>`. A Windows wheel
cache is not a Linux cache. Historical Ubuntu/WSL admission, real inference and offline verification were measured against operational source 15a19332eba7f2ecc62eda7fa197449b46d291a7. The later candidate-bound prepared-host run is separately recorded at source 0091c06407da259c907058662f915060fe48838a. The three full-suite results belong to the measured source, not this new history-free tree. The Linux run used the same laptop and WSL kernel/hypervisor, not independent hardware. Package installation alone does not establish T-015/T-020.

Keep the exact source checkout and use the editable install above. The runtime
locates infrastructure and tools relative to the source module location. A
standalone wheel-only deployment has not been established by these measurements.

### Tested fresh Linux preparation

The acceptance machine is a newly imported Ubuntu 24.04 WSL2 distribution on the
same laptop. It shares the WSL kernel/hypervisor; it is not independent hardware.
The official root filesystem was checked against its HTTPS-delivered SHA-256:
`2a790896740b14d637dbdc583cce1ba081ac53b9e9cdb46dc09a2f73abbd9934`.
Retaining a signature file does not constitute an independently verified signing
identity. Original acquisition/preparation logs remain in the local evidence.

The native Docker engine has its own delegated systemd service, UNIX socket and
data directory. Its service uses cgroup delegation and memory/CPU/I/O accounting;
effective memory, swap, PID and cpuset controls passed. The initial undelegated
engine correctly failed the swap-control gate. No threshold was lowered.
It uses no bridge, forwarding or iptables changes and does not replace Docker
Desktop's default context or the default WSL distribution.

Linux dependency preparation used the exact Linux wheels for `requirements.lock`
with `--no-index`, plus the source editable install. Create a **new** independent
verifier environment with copied executable files:

```bash
python3 -m venv --copies artifacts/linux-offline-new
artifacts/linux-offline-new/bin/python -m pip install --no-index --find-links /path/to/pinned-linux-wheels -r requirements.lock
artifacts/linux-offline-new/bin/python -m pip install --no-index --no-build-isolation --no-deps -e .
artifacts/linux-offline-new/bin/python -m pip check
```

Do not run `venv --copies` over an existing environment containing executable
symlinks. The current demo resolves `--offline-python` to its physical path; an
ordinary symlink venv resolved to the unprepared system interpreter and failed.
That attempt is retained. The fresh copied interpreter independently verified
both the earlier archive and a fresh passing real-model run.

The Linux run used a separately admitted profile and the same exact model/image
bytes. Public model bytes on the Linux filesystem were readable by UID 65534;
private owner/opening keys remained restricted. Docker save/load required
restoring verified original OCI digest aliases without changing image bytes.
On another host, prepare and admit a new profile against that host's effective
controls and CPU topology. Owner private keys must be explicitly provisioned to
match the pinned public roots.

Start the owned native engine in the same live WSL command used for a long run,
then use its explicit UNIX endpoint. This distro idles after its last foreground
command; a detached daemon alone did not keep the acceptance environment alive.
The earlier Linux run performed six real INPUT/SEALED_BATCH dispatches, 16 real synthetic reset-canary calls, and network/reset/restart controls. The follow-up against measured source 15a19332eba7f2ecc62eda7fa197449b46d291a7 repeated admission/calibration and six INPUT/SEALED_BATCH dispatches with independent verification; unchanged reset/network paths were not repeated. The weaker unadmitted fallback refused with
expected exit 2. Other defense modes' passing measurements are Windows-host
measurements, not additional Linux results.

The measured run used the following owner-provisioned inputs. These paths describe the historical host and are not a portable checkout:

| Input | Path from `backend/` |
|---|---|
| Historical source-bound profile and receipts (not valid for this new snapshot) | infra/prototype/step6-final-20261028-r1/ |
| Exact Qwen2.5-0.5B-Instruct Q4_K_M | `artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf` |
| Selected model metadata, pinned image and assembly recipe | `infra/model-component/`, `infra/cells/Dockerfile.model` |
| Admitted encrypted public corpus | `../artifacts/datasets/prepared-20261019/` |
| Public corpus receipt | Owner-provided public corpus receipt (not included; provide a verified path) |
| Separate private corpus opening keys | `../artifacts/secrets/dataset-preparation.keys.json` |
| Pinned public owner roots | `infra/owner-delegated-n08/` |
| Matching private CA/recorder/witness keys | `%LOCALAPPDATA%/BlindShield/owner-delegated-n08/` |
| External anchor/recovery custody | sibling `%LOCALAPPDATA%/BlindShield/prototype-recovery/` |

The model is exactly 491,400,032 bytes with SHA-256
`74a4da8c9fdbcd15bd1f6d01d621410d31c6fc00986f5eb687824e7b93d7a9db`.
Its tokenizer is embedded in those GGUF bytes. The selected assembled image is
`sha256:4a5a9f46dc11132862f943e0f3a0c32fa032d84bb52bd0241b7c046515f8ae68`.
Runtime checks the profile's exact local images and source bytes; it never
downloads, trains, quantizes or automatically pulls an image.

Private owner keys must match the pinned public roots. The authority directory
requires `demo-ca-private.pem`, `recorder-private.pem` and `witness-private.pem`.
Recovery also requires the matching authorities named in
`infra/prototype/recovery-authorities.json` and the separate ledger/instance
marker. These are owner-provisioned prerequisites, not values to invent during
setup. A different owner/machine needs explicitly provisioned trust and a newly
reviewed admitted profile where bindings differ. Public roots in Git do not
provide the corresponding private authority.

Keep weights, keys, private credentials/stores, replay openings and encrypted
corpus artifacts out of Git and images. Preserve the external anchor ledger/key
when retaining an application store for recovery. Backing up both as one
rollback unit defeats the local separation assumption.

## Explicit model/image preparation

The existing host already has admitted local assets. Do not redownload or
overwrite them merely because a documentation commit changed. If preparing a
new asset directory, the existing tools accept:

```powershell
.\.venv\Scripts\python.exe tools/prepare_n04.py --download --output artifacts/model-assets-new --corpus-receipt "path/to/public-corpus-preparation.json"
.\.venv\Scripts\python.exe tools/prepare_model_profile.py --model-dir artifacts/model-assets-new --base-admission artifacts/model-assets-new/admission.json --output artifacts/model-component-new
```

Preparation verifies pinned public model/card/license bytes and uses pinned
image recipes. It may use the allowed public acquisition sources. The model
assembly is reproducible metadata assembly over a pinned publisher binary image;
it is not an independent reproduction of training, quantization or a llama.cpp
source compilation. Candidate preparation does not authorize public execution.
If the resulting image/assets differ from the active profile, preserve the
refusal and prepare/review a new binding rather than replacing old signed files.
Public corpus preparation is separate: `tools/prepare_public_corpus.py` takes
`--output`, `--key-file` and `--receipt` for new destinations. Its random encrypted
artifacts and receipt do not automatically match the currently admitted corpus.

## New source or host admission

Use existing current-profile grants only while their executable/input/image/
authority/expiry/capacity bindings still pass. When they change, prepare from
committed source using new ignored directories:

```powershell
$keys = Join-Path $env:LOCALAPPDATA 'BlindShield/owner-delegated-n08'
.\.venv\Scripts\python.exe tools/prototype_prepare.py --component infra/model-component/profile.json --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-candidate-new
.\.venv\Scripts\python.exe tools/prototype_gate.py static --profile artifacts/prototype-candidate-new/profile.json --model artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf --authority-key "$keys/recorder-private.pem" --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-candidate-new/static.json
.\.venv\Scripts\python.exe tools/prototype_calibrate.py --profile artifacts/prototype-candidate-new/profile.json --static-grant artifacts/prototype-candidate-new/static.json --model artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf --authority-key "$keys/recorder-private.pem" --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-calibration-new
.\.venv\Scripts\python.exe tools/prototype_gate.py service --profile artifacts/prototype-candidate-new/profile.json --static-grant artifacts/prototype-candidate-new/static.json --calibration artifacts/prototype-calibration-new/calibration.json --authority-key "$keys/recorder-private.pem" --authority-public-key infra/prototype/step6-final-20261028-r1/admission-public.hex --output artifacts/prototype-candidate-new/service.json
```

STATIC allows calibration only. Calibration makes six actual model calls,
measures three-lane overlap and cgroup peaks, rejects failed fit/OOM and confirms
cleanup. SERVICE binds that calibration and rechecks capacity. Current floors
include 8 GiB host-available and 7 GiB VM-available memory, with 2 GiB per model
lane, exact VM-visible CPU partitions and disk headroom. Gates remain unchanged
on failure. A new candidate is not the official submission profile until its
measurements, evidence and claims are reviewed together.

## Finite authenticated demo or foreground service

Use the freshly generated profile and SERVICE grant from the preceding admission steps, plus a new private output directory. The example below assumes the operator has provisioned matching private authority keys outside Git. Supply the actual prepared model, corpus, receipt and opening keys; those assets are not included in this snapshot.

~~~powershell
$keys = Join-Path $env:LOCALAPPDATA 'BlindShield/owner-delegated-n08'
$profile = 'artifacts/prototype-candidate-new/profile.json'
$serviceGrant = 'artifacts/prototype-candidate-new/service.json'
$authorityPublicKey = 'infra/prototype/step6-final-20261028-r1/admission-public.hex'
$model = 'artifacts/n04-release-preparation/qwen2.5-0.5b-instruct-q4_k_m.gguf'
$corpus = '../artifacts/datasets/prepared-20261019'
$corpusReceipt = 'path/to/public-corpus-preparation.json'
$corpusKeys = '../artifacts/secrets/dataset-preparation.keys.json'
.\.venv\Scripts\python.exe tools/prototype_run.py --profile $profile --service-grant $serviceGrant --authority-public-key $authorityPublicKey --authority-directory $keys --model $model --corpus $corpus --corpus-receipt $corpusReceipt --corpus-keys $corpusKeys --output artifacts/prototype-demo-new --mode INTERACTIVE --defense-mode INPUT --demo --offline-python artifacts/repro-env/Scripts/python.exe
~~~

The demo exercises real public traffic, idempotency, role denial, embargo, three-lane processing overlap, finish/close/release, auditor export and an independent verifier process. Interactive feedback includes the actual 61-second release floor. The final receipt is written only after the demo and cleanup succeed. Inspect its result and offline verifier log; a URL/start message alone is not success.

### Historical Linux evidence

The Linux results describe a separately admitted profile and the same laptop's shared WSL kernel. They are not independent-hardware validation. The included Linux profile binds the earlier measured source and is not valid for this history-free snapshot. To rerun on Linux, initialize and commit this snapshot there, provision fresh authorities and assets, then repeat the admission and calibration steps with a Linux-specific profile.
Choose `--mode SEALED_BATCH` for the sealed scheduler. Supported frozen defense
modes are `INPUT`, `FEATURES`, `OUTPUT` and `POST_HOC`; actual passing combinations
are recorded in the measurement report. POST_HOC analysis occurs after release,
is separately signed, and never changes closed turn results or claims prevention.

Omit `--demo` to serve in the foreground; `--port` optionally selects a loopback
port. `service-info.json` contains the actual URL. `create-request.json` and
short-lived role certificates are under the private output directory. The
listener binds `127.0.0.1` only. Client role comes from its mTLS certificate, not
headers or request text. Use the lifecycle in [PROTOTYPE-SERVICE.md](PROTOTYPE-SERVICE.md)
to create/upload/seal/start, then allocate the three sessions for interactive
turns or let the sealed batch schedule its frozen items. Wait for each accepted
administrative operation to reach `DONE` before the next lifecycle action.

## Authenticated liveness and operation checks

There is no advertised anonymous HTTP health endpoint. After experiment creation,
the actual authenticated status route is
`GET /v1/experiments/{experiment_id}/status`. The operator operation route is
`GET /v1/experiments/{experiment_id}/operations/{operation_id}` and reports
`PENDING`, `RUNNING`, `DONE` or `FAILED`. The experiment and operation IDs must
come from their authenticated create/operation responses. Blue-human status is
deliberately embargoed before release.

For example, with an existing live store and a trusted experiment UUID, this
Python standard-library client checks TLS and operator authentication:

```powershell
$experimentId = '<UUID returned by the authenticated create response>'
@'
import http.client, json, ssl, sys
from pathlib import Path
from urllib.parse import urlsplit
root = Path('artifacts/prototype-live')
url = urlsplit(json.loads((root/'service-info.json').read_bytes())['url'])
tls = ssl.create_default_context(cafile=str(root/'tls/ca.pem'))
tls.load_cert_chain(str(root/'tls/client-operator.pem'), str(root/'tls/client-operator.key'))
client = http.client.HTTPSConnection(url.hostname, url.port, context=tls, timeout=6)
try:
    client.request('GET', '/v1/experiments/'+sys.argv[1]+'/status')
    response = client.getresponse()
    print(response.status)
    print(response.read().decode('utf-8'))
finally:
    client.close()
'@ | .\.venv\Scripts\python.exe - $experimentId
```

Use the output directory actually selected when starting the service; the sample
`artifacts/prototype-live` is not created by the preceding demo command. A 200
status establishes the tested authenticated control path, not model safety,
fairness or submission readiness.

## Shutdown and cleanup

A finite demo shuts down automatically. For a foreground service, press Ctrl+C
in its terminal and allow shutdown to finish. The service stops its listener,
settles/cancels its local tasks as appropriate, removes its owned model
containers and stops its own anchor child. Successful terminal close destroys
the model contexts without creating a new inference worker.

```powershell
docker ps --format '{{.ID}} {{.Names}}'
```

Check the exact owned names/IDs from that run's private runtime records. Other
projects and historical stopped containers are not cleanup targets; never use a
global prune as prototype shutdown. A force-killed host/service can leave model
containers behind. Preserve its store and recorded ownership for authenticated
recovery/fencing rather than assuming cleanup or reusing the directory.

## Independent evidence verification

The finite demo already invokes `artifacts/repro-env/Scripts/python.exe -m
arena.verifier.cli` in a separate process and retains its log. For a separate
review, acquire the evidence through the authorized auditor route after a valid
close, and supply public trust plus expected context through a separate trusted
channel. The current pinned recorder and witness identities are
`n08-prototype-recorder-001` and `n08-prototype-witness-001`; broker actor is the
source-pinned `ACTOR` in `src/arena/integration/controller.py`. Do not accept
context, keys or an alleged prior checkpoint merely because the ZIP includes them.

For an ordinary interactive bundle, first set `$run`, `$recorderHex`, `$witnessHex`,
`$expectedDomain`, `$expectedExperiment`, `$expectedEpoch`, `$manifestDigest` and
`$brokerActor` from the independently trusted operator/authority record:

```powershell
.\artifacts\repro-env\Scripts\python.exe -m arena.verifier.cli --bundle "$run/evidence.zip" --recorder-key "$recorderHex" --witness-key "$witnessHex" --recorder-key-id n08-prototype-recorder-001 --witness-key-id n08-prototype-witness-001 --domain-id "$expectedDomain" --experiment-id "$expectedExperiment" --epoch "$expectedEpoch" --manifest-digest "$manifestDigest" --defense-mode INPUT --broker-actor "$brokerActor" --keys-json "$run/replay-keys.json" --require-transport-profile --transport-profile-key "$recorderHex" --transport-profile-key-id n08-prototype-recorder-001 --feedback-policy-key "$recorderHex" --feedback-policy-key-id n08-prototype-recorder-001
```

Use the independently expected defense mode, not a mode chosen from an untrusted
bundle. `--keys-json` contains authorized private openings and must stay private.
For SEALED_BATCH, replace the transport-profile/feedback-policy options with
`--require-prototype-batch`; this requires complete authorized openings and exact
frozen item coverage. For POST_HOC, additionally supply the trusted release ID
through `--expected-release-id`, its separate `--analysis-keys-json`, and each
expected `--post-hoc-bundle`. The expected bundle set comes from the trusted
completed analysis operation, not arbitrary ZIP discovery.

Verifier exit 0 is a scoped cryptographic/lineage success, not a safety score.
Reconciled recovery bundles additionally require the separately pinned anchor/
recovery keys and identities and canonical signed `--anchor-records`; INVALID
archives require the independent invalid-export authority. Exact executed
recovery-verification commands and output hashes are retained in the
Detailed Step 5 proof records are local-only and are not included in this snapshot.
Read `arena.verifier.cli --help` for the actual flags. An authentic incomplete
INVALID archive deliberately reports `AUTHENTIC_INVALID_INCOMPLETE` with nonzero
exit and never grants participant release. Do not turn it into a passing result.

## Existing-store recovery and release limits

Ordinary startup refuses an existing output store after authenticated inspection.
For an eligible interrupted run, reuse that original private directory, matching
corpus and external authorities, and add `--recover-only` to the same
`prototype_run.py` invocation; remove `--demo`. Recovery startup authenticates the
stores against the original surviving external anchor ledger before listening.
It starts no model or worker. Only the exact owned feedback recovery, permitted
terminal close and relevant authenticated evidence/operation views are available.
Feedback recovery applies a new real 61-second floor and exact same-key replay;
it never redispatches inference, refunds budget or upgrades existing invalidity.

This local separation assumes the external anchor ledger/key survives intact.
Host-admin replacement of both application and anchor stores, full-host snapshot
rollback, remote/hardware attestation, host CPU exclusivity, broad resource
fairness, physical model-read I/O enforcement, population timing/channel bounds,
model-quality accuracy and broader fresh-machine portability remain separate
acceptance questions. The fresh Ubuntu WSL result is bounded above. The retained
legacy production coordinated-rollback skip is not a
pass. Keep the current failed/inconclusive outcomes and acceptance gaps in the
submission claim sheet; do not describe this candidate as 100% accepted.

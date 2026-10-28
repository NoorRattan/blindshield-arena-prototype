# BlindShield Arena

> Local public-release candidate with a new, independent Git history. Publication remains blocked pending contributor permission records. See [release readiness](RELEASE-READINESS.md). The original working repository and its Git history are not included.

BlindShield Arena is a local prototype for evaluating AI model defenses with authenticated execution, isolated model lanes, tamper-evident records, and offline evidence verification.

## Prototype scope

The backend supports bounded local interactive and sealed-batch runs using a pinned Qwen/llama.cpp profile. It is not a production service and does not have complete acceptance across all measured requirements.

The frontend is a separate visual prototype. It uses local mock/browser state and is not connected to the backend or real model.

## Recorded verification

The included records report:

- This independent snapshot passed fresh same-laptop native-Linux prepared-host acceptance at source commit `2f73df8`: six real-model calibration calls, six authenticated demo calls, three-lane processing overlap, independent offline verification (exit 0), and cleanup. Its supported Windows application test subset passed 548 tests and 14 subtests, with one documented skip. The [current validation summary](backend/evidence/public-snapshot-validation-20261028.json) also discloses the retained failed attempt and fixture exclusions.
- Step 6 evaluated 35 procedures: 19 PASS, 15 PARTIAL, and 1 INCONCLUSIVE. Three suites each reported 633 passed and one documented unsupported coordinated-rollback skip. The Linux run used the same laptop and shared WSL kernel, so it is not independent-hardware validation.
- The candidate-bound prepared-host receipt records six real-model calibration calls, six authenticated demo calls, independent offline verification, and cleanup.
- The pinned Playwright Docker run reported 96 UI E2E cases passed across desktop and mobile. It exercises the mock frontend only and does not add backend acceptance procedures.

The Step 6 report is a result summary. Its detailed path-redacted records are omitted because their modified bytes no longer validate the original hashes/signatures. Treat those results as project-reported evidence; this snapshot does not provide independent verification of those omitted records.

Three memory/registry-specific test modules are omitted because they depend on private project memory and registry fixtures not distributed here. This is a source and reviewer snapshot, not the complete private working tree.

See [Step 6 acceptance](backend/docs/STEP6-ACCEPTANCE.md), the [prepared-host receipt](backend/evidence/step7-prepared-host-acceptance-20261028-r2.json), the [frontend E2E receipt](backend/evidence/frontend-e2e-docker-20261028.json), and the [submission packet](backend/docs/PROTOTYPE-SUBMISSION.md).

## Run the frontend

From frontend/:

~~~powershell
npm ci
npm run dev
~~~

The UI suites can be run with npm run verify or npm run e2e:smoke. The current lock-only audit recorded eight high and one moderate finding; see the audit receipt linked from the submission packet.

## Run the backend

A backend demo needs a compatible host, Docker images, the pinned model weights, prepared corpus and receipt, and owner-managed signing/recovery authorities. These files and credentials are intentionally not included.

The backend derives source identity from Git. This candidate has its own Git repository. The included historical signed profiles and grants are tied to the earlier measured candidate; use fresh profiles and signatures bound to this candidate's committed source. See [release readiness](RELEASE-READINESS.md) for the current admission result.

Start with the [backend guide](backend/README.md), [release runbook](backend/docs/PROTOTYPE-RELEASE.md), and [service lifecycle guide](backend/docs/PROTOTYPE-SERVICE.md). Never add model weights, prepared corpus data, private keys, local stores, or raw run artifacts to Git.

## Distribution and limitations

The project license selected for project-authored material is MIT; see [LICENSE](LICENSE) and [third-party notices](THIRD-PARTY-NOTICES.md). Confirm that all contributors authorized distribution of their contributions before publishing. The preserved working repository includes code contributed by collaborators, and this snapshot does not contain a written relicensing record for every contributor.

The JBB-Behaviors dataset is used as an evaluation source and cited under its upstream MIT terms. Dataset records, prepared corpus, source data and opening keys are not included. The root license does not cover third-party model weights, datasets, container images or dependencies.

Do not claim production readiness, 100% acceptance, universal defense accuracy, fairness, independent-machine portability, host-admin rollback resistance, forensic erasure, or zero side-channel leakage. Known limits and unsupported claims remain in the acceptance report.


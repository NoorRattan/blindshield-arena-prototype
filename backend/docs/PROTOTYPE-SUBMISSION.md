# Prototype submission packet

**Package date: 28 October 2026.** This packet accompanies the dedicated `NoorRattan/blindshield-arena-prototype` evaluation repository. Start with the root [evaluator guide](../../EVALUATION.md) for the current frontend delivery and checks. Historical receipts retain their original dates, source identities and blocker states. Event-form and social submission are separate owner actions.

## Reviewer entry points

1. [Backend guide](../README.md)
2. [Release runbook](PROTOTYPE-RELEASE.md)
3. [Authenticated service guide](PROTOTYPE-SERVICE.md)
4. [Step 6 acceptance summary](STEP6-ACCEPTANCE.md)
5. [Candidate-bound prepared-host receipt](../evidence/step7-prepared-host-acceptance-20261028-r2.json)
6. [Frontend Playwright Docker receipt](../evidence/frontend-e2e-docker-20261028.json)
7. [Frontend dependency audit receipt](../evidence/frontend-npm-audit-20261028.json)
8. [Backend dependency advisory query receipt](../evidence/backend-runtime-advisory-query-20261028.json)
9. [Third-party notices and SBOM index](../../THIRD-PARTY-NOTICES.md)

The prepared-host receipt records six real-model calibration calls, six authenticated demo calls, an independent offline verifier exit code of 0, and cleanup on the same Windows laptop with Docker Desktop. It is not independent-hardware evidence, full T/P acceptance, or a production guarantee.

The historical frontend E2E receipt records 96 passed cases across desktop and mobile projects before the new frontend delivery. It does not validate the new code. Current checks are recorded separately in the root evaluator guide. A later local browser smoke verified mTLS proxy interoperability with a disposable N03 control-plane fixture (create, seal, role-scoped status/embargo; zero model calls). It does not validate the separately admitted N04 model service from the browser. The Vitest client tests still use a mocked transport.

Three memory/registry-specific test modules are excluded from this public source snapshot because they require private project memory and registry fixtures. The documented public test command skips those modules; its result is not full acceptance.

## Acceptance results and limits

The Step 6 summary evaluates 35 procedures: **19 PASS, 15 PARTIAL, and 1 INCONCLUSIVE**. Three suites each recorded 633 passed and one documented unsupported coordinated-rollback skip. The Linux run used the same laptop and WSL kernel; it is not independent-hardware validation.

Path-redacted detailed Step 6 files are omitted from this snapshot because their modified bytes no longer validate their original hashes or signatures. The summary remains project-reported and cannot be independently verified from those omitted records. T-006 remains inconclusive. Fairness, model safety, physical-I/O enforcement, host-admin/full-snapshot rollback resistance, forensic erasure, independent-machine portability, and zero timing leakage remain unsupported claims.

The immutable prepared-host receipt includes the blocker state recorded when that run was packaged. Later owner decisions selected MIT, authorized JBB use with citation and explicitly confirmed MIT publication permission from Mayank and Monu, including the new frontend. Private permission correspondence was not inspected. Historical receipts remain unchanged.

## Assets and external actions

Large visual walkthrough and Reel draft files are retained in the local working candidate and are not included in this source snapshot. They are prepared evidence-based visuals, not live screen recordings. No LinkedIn/Instagram post or event form submission is represented here.

A new host needs owner-provisioned model weights, OCI images, prepared corpus and receipt, private authorities, external recovery-anchor state, and a fresh admission. Those assets and credentials are deliberately not included.


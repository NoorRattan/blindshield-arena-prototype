# Backend

BlindShield Arena's backend is a local prototype with three isolated CPU model lanes, an authenticated loopback mTLS API, encrypted artifacts, recorder/witness evidence, bounded recovery, and an independent offline verifier.

It is a bounded prototype with known acceptance gaps. It has not passed every T/P target and is not a production service. The frontend remains a mock UI and is not integrated with this backend.

## Setup and demo

The measured run used Python 3.12 and Docker. Follow the [release runbook](docs/PROTOTYPE-RELEASE.md) for setup, fresh host admission, demo, shutdown, and verification. The [service guide](docs/PROTOTYPE-SERVICE.md) describes the authenticated lifecycle.

The public source snapshot does not include model weights, OCI image archives, prepared corpus data, corpus openings, private signing keys, private stores, or external rollback-anchor state. The published profiles are historical and host-specific. This Git-history-free snapshot must first be initialized and committed in Git; then create new source-bound profiles, grants, and signatures with owner-managed authorities for the chosen host.

The public test set omits the following private-data-specific modules: tests/test_memory_acceptance_evidence.py, tests/test_memory_revision_support.py, and tests/test_n05_candidate_inventory.py. To run the remaining application tests from backend/, use:

~~~powershell
python -m pytest -q tests --ignore=tests/test_memory_acceptance_evidence.py --ignore=tests/test_memory_revision_support.py --ignore=tests/test_n05_candidate_inventory.py
~~~

This test subset is not full acceptance. See the Step 6 report for its separate measured procedure results and limits.

## Evidence

- [Step 6 acceptance summary](docs/STEP6-ACCEPTANCE.md): 19 PASS, 15 PARTIAL, 1 INCONCLUSIVE across 35 procedures. Some detailed path-redacted records were omitted because their original signatures/hashes no longer validate after sanitization; the report is not independently verifiable from those omitted records.
- [Candidate-bound prepared-host receipt](evidence/step7-prepared-host-acceptance-20261028-r2.json): six calibration calls, six authenticated real-model demo calls, offline verification, and cleanup on the measured local host.
- [Submission packet](docs/PROTOTYPE-SUBMISSION.md): evidence scope and outstanding owner-controlled submission actions.

The report's PASS labels are procedure-level results, not proof that every requirement passed. T-006 remains inconclusive, and several fairness, model-safety, host-admin rollback, physical-I/O, portability, and timing boundaries remain unsupported.


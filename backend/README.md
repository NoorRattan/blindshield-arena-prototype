# Backend

BlindShield Arena's backend is a local prototype with three isolated CPU model lanes, an authenticated loopback mTLS API, encrypted artifacts, recorder/witness evidence, bounded recovery, and an independent offline verifier.

It is a bounded prototype with known acceptance gaps. It has not passed every T/P target and is not a production service. The frontend includes a loopback mTLS proxy and a live API console. Browser-to-Python N03 control-plane traffic was smoke-tested using disposable local credentials; the check made no model calls and does not validate the separately admitted N04 service from the browser. See the root evaluator guide for the supported review path.

## Setup and demo

The measured run used Python 3.12 and Docker. Follow the [release runbook](docs/PROTOTYPE-RELEASE.md) for setup, fresh host admission, demo, shutdown, and verification. The [service guide](docs/PROTOTYPE-SERVICE.md) describes the authenticated lifecycle.

The public source snapshot does not include model weights, OCI image archives, prepared corpus data, corpus openings, private signing keys, private stores, or external rollback-anchor state. This candidate has its own independent Git root. The published historical profiles remain host-specific; new execution requires source-bound profiles, grants, and signatures with owner-managed authorities. See [release readiness](../RELEASE-READINESS.md) for current validation status.

The public test set omits three private-data-specific modules: tests/test_memory_acceptance_evidence.py, tests/test_memory_revision_support.py, and tests/test_n05_candidate_inventory.py. The retained tests/test_n08_owner_delegated_inputs.py checks historical owner-input records and host observations omitted from this snapshot; exclude it from the supported public application subset as well. Its missing-fixture failures were retained locally rather than treated as passing tests. From backend/, use:

~~~powershell
python -m pytest -q tests --ignore=tests/test_memory_acceptance_evidence.py --ignore=tests/test_memory_revision_support.py --ignore=tests/test_n05_candidate_inventory.py --ignore=tests/test_n08_owner_delegated_inputs.py
~~~

This test subset is not full acceptance. See the Step 6 report for its separate measured procedure results and limits.

## Evidence

- [Step 6 acceptance summary](docs/STEP6-ACCEPTANCE.md): 19 PASS, 15 PARTIAL, 1 INCONCLUSIVE across 35 procedures. Some detailed path-redacted records were omitted because their original signatures/hashes no longer validate after sanitization; the report is not independently verifiable from those omitted records.
- [Candidate-bound prepared-host receipt](evidence/step7-prepared-host-acceptance-20261028-r2.json): six calibration calls, six authenticated real-model demo calls, offline verification, and cleanup on the measured local host.
- [Submission packet](docs/PROTOTYPE-SUBMISSION.md): evidence scope and outstanding owner-controlled submission actions.

The report's PASS labels are procedure-level results, not proof that every requirement passed. T-006 remains inconclusive, and several fairness, model-safety, host-admin rollback, physical-I/O, portability, and timing boundaries remain unsupported.


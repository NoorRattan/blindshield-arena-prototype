# Step 6 — final current-profile acceptance report

**Procedure evaluation is complete for this bounded local prototype.** The
results below include PASS, PARTIAL and INCONCLUSIVE outcomes. This does not mean
every acceptance requirement passed or that the backend is 100% accepted. Step 7
submission packaging and owner review remain separate.

The detailed path-redacted Step 6 evidence files are intentionally omitted: their modified bytes no longer validate original hashes or signatures. Treat the results in this document as project-reported summaries; this snapshot cannot independently verify the omitted records.

The measured operational source is `15a19332eba7f2ecc62eda7fa197449b46d291a7`.
The active Windows profile is
[`step6-final-20261028-r1/profile.json`](../infra/prototype/step6-final-20261028-r1/profile.json),
SHA-256 `64897a46567430322edd3154f3e8b931c1e65f1f03be77a038e26956a135f188`.
No gate, checker, threshold, release floor, deadline, body limit or signing bytes
were weakened. Historical evidence retains its own source and profile identity.

## Reported evidence from measured source

| Evidence | Result and scope |
|---|---|
| Windows primary suite | 633 passed, 1 documented skip, 55 subtests passed at the measured source. |
| Windows offline suite | 633 passed, 1 documented skip, 55 subtests passed at the same source. |
| Ubuntu 24.04 WSL suite | 633 passed, 1 documented skip, 55 subtests passed at the same source. This is the same laptop and shared WSL kernel/hypervisor, not independent hardware. |
| Fresh Windows admission and recovery | Fresh static admission, six-call calibration and SERVICE grant; both declared real process-crash recovery cuts, exact receipts, valid/INVALID verification and cleanup passed. Detailed Step 5 proof records are local-only and are not included in this snapshot. |
| Fresh native Linux follow-up | Current-source admission/calibration and six real sealed-batch model dispatches passed independent offline verification. The weaker unadmitted profile was refused; the owned engine and model containers were stopped/removed. Network/reset controls remain attributed to the earlier unchanged Linux proof. |
| Populated isolation and reset | Two generations, 16 real canary calls, populated synthetic credential/corpus/source file controls, PID/environment and IPC controls, three-lane continuity/reset and detectable weakened controls passed. Failed first-generation publisher fixture remains preserved separately. |
| Defense-only minimization | Eight actual calls across INPUT, FEATURES, OUTPUT and POST_HOC; eight distinct transient containers removed, with zero target-model starts/calls. |
| Active wire and authority matrix | 36 active wire types, 40 epoch locations and 120 single-location coercion refusals; genuine signed feedback authority reassignment/replay controls also passed. |
| Private operator alerts | Fixed sanitized codes, bounded retention and overflow count, local CLI/restart retrieval, privacy, recorder failure and worker failure paths passed focused and full-suite checks. |

## Final timing procedure

The final study ran on the current admitted Windows Qwen profile with the original
predeclared protocol: 144 observations across 12 authorized campaigns, three
functional controls (ALLOW, SANITIZE and BLOCK), a 61-second release floor, a
60-second execution deadline, 16,384-byte bodies, three lanes, frozen selection
and held-out validation rules, and the original analysis envelope. The prior
interrupted study's 132 observations were not pooled or retried.

**T-018/P-012: PASS** — the study completed all 144 observations; all 12 campaign
authorities and all three functional controls passed; the negative control was
detectable; the source remained unchanged; and owned-container cleanup was
verified. The shaped held-out timing AUC was 0.527 with campaign-bootstrap 95%
interval [0.358, 0.696], inside the predeclared point range [0.35, 0.65] and
interval range [0.2, 0.8]. The unshaped control AUC was 1.000 with interval
[1.000, 1.000]. The protocol labels this `WITHIN_PREDECLARED_EXPLORATORY_ENVELOPE`.

This is a finite exploratory result. The analysis explicitly does not establish
independent campaign samples, p99, zero leakage, public admission, population
performance or total channel capacity. The detailed timing records are omitted from this public snapshot because path-redacted copies do not validate their original hashes or signatures. This timing result remains a project-reported summary, not independently verifiable here. The older interrupted timing evidence remains
INCONCLUSIVE and separate.

## Procedure outcomes

These are evidence-backed procedure outcomes, not blanket acceptance of the
larger requirements. PARTIAL and INCONCLUSIVE findings remain visible.

| Procedure | Result | Measured scope or remaining limit |
|---|---|---|
| T-001 | PASS | Populated synthetic credential, private-corpus and source-file controls; per-cell files, shared memory and process environment; finite exact-profile boundaries. |
| T-002 | PARTIAL | Named IPv4, DNS, IPv6, host, metadata and private-loopback denials were checked before/after restart; complete actor, destination and HTTP-route matrix is not established. |
| T-003 | PASS | Actual mTLS authorization/idempotency plus active wire/epoch matrix and signed authority reassignment/replay refusals. |
| T-004 | PARTIAL | Actual phase embargo, upload freeze, authorized release/export and red-download denial; every log/download/artifact lifecycle path is not exhaustively measured. |
| T-005 | PASS | Three-lane continuity/separation, private history, slot erase and container recreation with a detectable retained-context control; no forensic-erasure claim. |
| T-006 | INCONCLUSIVE | No supported isolated server prefix-cache timing baseline; combined history/slot/container reset is a separate result. |
| T-007 | PASS, retained receipt | Existing named actual-bundle corruption receipt remains bound to its original verifier/source. |
| T-008 | PARTIAL | Actual recorder/witness commit, ACK, process-race and stale-restore controls; physical disk-full and every storage-outage mechanism are not proved. |
| T-009 | PASS | Authorized offline decryption/reconstruction and authentic valid/INVALID distinction, with closed-service checks and finite matched reproduction. |
| T-010 | PARTIAL | Earlier-profile resource phases retained at their actual source; some frozen 10% latency targets were missed; physical model-read I/O quota and general fairness remain unproved. |
| T-011 | PARTIAL | Real permitted inference and separately labeled ALLOW/BLOCK/SANITIZE controls; public defense accuracy and all workload bounds are not established. |
| T-012 | PASS | Named reservation/process/late-response/ACK/publication/cancel/reconnect cases plus fresh real-model crash cuts; no unsafe UNKNOWN retry or authority regression in those cases. |
| T-013 | PASS | Private fixed-code alerts, bounded eviction/overflow count, restart/CLI retrieval, participant privacy and recorder/sink-failure controls. Sink unavailability is not described as durable retention. |
| T-014 | PARTIAL | Backend role-filtered JSON and hostile-markup/reconnect/size controls; browser keyboard/preview/live-frontend coverage was outside this backend proof. |
| T-015 | PASS | Fresh Ubuntu WSL setup and measured-source native admission/calibration, real INPUT batch and independent verification; same laptop/shared kernel, not independent hardware. |
| T-016 | PASS | Six-objective risk, claim, procedure and residual reconciliation includes measured failures and unsupported channels. |
| T-017 | PARTIAL | 100 pinned encrypted public records, provenance/split/refusal checks and closed private-data gate; complete counterfeit-provenance and unauthorized-export lifecycle matrix is not established. |
| T-018 | PASS | Complete predeclared finite timing study passed its exploratory envelope; not a population or zero-leakage guarantee. |
| T-019 | PARTIAL | Actual interactive/batch and three-lane overlap plus finite serial/concurrent/resource observations; latency, fairness and physical-I/O limits remain. |
| T-020 | PASS | Current Windows and native Ubuntu source/profile/capacity admission; unadmitted weaker fallback was refused rather than presented as a working deployment. |
| P-001 | PASS | Finite populated synthetic file/mount/credential/private-corpus canaries with intended reads and detectable weakened controls. |
| P-002 | PASS | Process environment, private/shared PID, POSIX shared memory and daemon-socket controls with exposure controls; not every IPC mechanism. |
| P-003 | PARTIAL | Named network source/destination denial and restart controls; full actor/route matrix remains incomplete. |
| P-004 | PARTIAL | Blue-to-target loopback denial and wrapper source allowlist; six path labels were TCP-port checks, not six HTTP route calls. |
| P-005 | PASS | Actual role/domain/object/phase/expiry/revocation and replay controls plus populated epoch/capability context matrix. |
| P-006 | PARTIAL | Private bounded backend alert/telemetry proof; browser/viewer/preview and every output sink are not proved. |
| P-007 | PARTIAL | Phase embargo/release/decryption and frozen input/artifact controls; full lifecycle leakage matrix remains incomplete. |
| P-008 | PASS | 900 synthetic transmissions through the strict internal nine-tuple parser; `log2(9) ≈ 3.17` bits is only an internal alphabet bound, not public or total channel capacity. |
| P-009 | PASS | Eight actual measured-source defense-only calls across four modes; restricted request keys and cleanup verified, with no target model start. |
| P-010 | PARTIAL | Isolated lanes and combined reset/exposure controls passed; isolated server KV/cache timing remains INCONCLUSIVE. |
| P-011 | PARTIAL | Earlier-profile CPU/RAM/PID/logical model-read/tmpfs pressure retained separately; physical I/O enforcement and noisy-neighbor fairness are unproved, with some latency targets missed. |
| P-012 | PASS | Same complete predeclared timing result as T-018, with all authorities, errors, overruns and cleanup checked. |
| P-013 | PASS | Finite serial/concurrent outcomes showed no observed drift at unchanged comparison paths; this does not prove defense accuracy or universal fairness. |
| P-014 | PASS, retained receipt | Existing actual-bundle corruption receipt and original verifier/source identity are retained. |
| P-015 | PARTIAL | Fresh local crash/recovery and surviving-anchor stale-restore controls; physical disk-full/every storage failure are unmeasured; host-admin/full-snapshot rollback is outside the trust boundary. |

## Six-objective claim sheet and residual risks

| Objective | Supported claim | Residual boundary |
|---|---|---|
| Isolate without breaking function | Enumerated populated file, IPC, network, context and mount boundaries were exercised while real three-lane inference and authenticated workflows operated. | The full actor/route matrix, physical I/O enforcement, host CPU exclusivity and general fairness are not established. |
| Prevent information leakage | Tested phase views are embargoed; histories are separated; fixed typed outputs, bounded shaping and finite timing controls were measured. | T-006 remains INCONCLUSIVE; the timing result does not prove zero leakage, full cache safety or total channel capacity. |
| Audit integrity | Named corruptions are rejected; bounded valid and authentic INVALID histories remain distinct; independent openings verify. | Recovery assumes the separate local anchor ledger/key survives; no host-admin or full-snapshot guarantee. |
| Deployability | Windows and fresh Ubuntu WSL used exact admitted artifacts for real inference and independent verification. | Linux reused the same laptop/kernel/hypervisor; owner keys and host-specific admission are required. |
| LLM-native threats | Actual continuity, lane separation, slot erase, container recreation and a detectable weakened retained-context control were exercised. | No forensic erasure, universal KV/cache safety, model safety or public-defense accuracy claim. |
| Quantify residual risk | Full suites, 144-observation timing, resource measurements, failures, skipped checks and unsupported channels are reported with separate denominators. | Small finite samples do not establish p99, total channel capacity, population fairness, independent review or a guarantee tier. |

The full suites each retain one explicit skip: coordinated rollback has no
production independent-anchor/startup consumer. That skip is not a pass. Resource
measurements from the earlier profile showed concurrent idle-to-load p50 changes
above 10% for several phases, including OUTPUT CPU (+19.59%), OUTPUT model reads
(+10.82%), INPUT PID (+15.13%), INPUT model reads (+19.14%) and INPUT tmpfs
(+13.59%). Buffered Windows model reads do not prove physical disk bandwidth or
quota enforcement. Stressor CPU shared the target cpuset, so host CPU exclusivity
and broad fairness remain unproved. Some latency targets were missed, and all
such results are retained with their original profile attribution.

## Release and custody

Step 6's evidence-backed procedure evaluation is complete, with the mixed
outcomes above. Step 7 still needs the final submission package and owner review.
The frontend is unchanged. Public Git evidence contains only reviewed metadata,
hashes, harnesses and logs; private keys, opening maps, encrypted corpus assets,
model weights, SQLite stores and archives containing openings remain private.
The current [prototype release runbook](PROTOTYPE-RELEASE.md) documents setup,
admission, demo, shutdown and recovery. Do not describe this backend as 100%
accepted or as an independently reviewed security guarantee.

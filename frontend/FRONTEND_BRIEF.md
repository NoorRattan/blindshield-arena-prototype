> Design brief: this describes a proposed platform. The current frontend is a mock and does not implement backend integration, cryptographic proof generation, or verified leakage prevention.

# BlindShield Arena (Bayora) — Frontend Brief

## 1. Product in 5 Lines
The proposed BlindShield Arena product is intended to provide tamper-evident infrastructure assurance for adversarial AI safety evaluations (Red vs. Blue vs. Target).
The proposed architecture uses a trusted Broker, isolated execution cells, an append-only Recorder, and an independent Witness to reduce evaluator leakage; the current mock UI does not implement or verify this property.
The proposed platform is intended to generate verifiable cryptographic proof bundles documenting code versions, execution timing, and communication commitments.
The design separates model safety behavior (for example, jailbreak success) from evaluation integrity (protocol validity).
The design calls for bounded telemetry and claims that remain separate from unverified deployment assumptions.

## 2. The 4 Roles & Visibility Boundary
- `operator`: Complete real-time telemetry, manifest composition and preflight, lifecycle control (start/close), and emergency quarantine.
- `red`: Own submitted attack payloads, commitment hash generators, allocated turn budget meters, and delayed/profile-bounded feedback.
- `blue`: Defense container health (heartbeat, request count, coarse latency) during active rounds; payload forensics strictly post-close.
- `auditor`: Signed bundle verification, offline hash-chain/Merkle proof inspection, tamper simulation, and benchmark distribution matrices.

## 3. The 8 Application Routes (One-Line Purpose)
1. `/` (Landing): Public, judge-facing executive overview featuring the 3D broker core, threat architecture, and residual risk disclosure.
2. `/overview`: High-level arena roster table, active domain status, illustrative integrity metrics, and streaming system alerts.
3. `/setup`: Multi-step experiment composer, canonical JSON manifest preview, preflight environment validation, and witness registration.
4. `/war-room`: Live round operational command center with 5-stage pipeline waterfall, broker queue gauges, and emergency quarantine.
5. `/red`: Red team workshop for crafting prompt payloads, generating cryptographic commitments, and tracking quota consumption.
6. `/blue`: Blue team console for monitoring guardrail container status, sanitized live traffic, and post-round forensic replays.
7. `/evidence`: Cryptographic audit vault with client-side Ed25519/hash verification, ledger inspection, and interactive tamper playground.
8. `/benchmarks`: Robustness and fairness analytics comparing Attack Success Rate, benign over-filtering, and prefix-cache timing.

## 4. Spec Corrections (C-01 … C-09)
- `C-01`: Cache chart displays "measured distinguishability (ROC AUC) with CI", explicitly banning claims that it "proves absence".
- `C-02`: Blue live monitor hides allow/block splits during active rounds; exposes only health, total volume, and coarse latency.
- `C-03`: Verifier marks bundle-supplied keys UNTRUSTED; requires external, user-pinned public keys and witnessed checkpoints.
- `C-04`: Replaces single "VALID" status with 3 distinct verdicts: Authenticity, Completeness, and Experimental Integrity.
- `C-05`: Idempotency key scope excludes body; reusing a key with altered payload triggers an explicit `409 CONFLICT`.
- `C-06`: Epoch is strictly typed across UI, mock, and verifier as a positive integer (`z.number().int().positive()`).
- `C-07`: Red portal feedback strictly obeys the round's disclosure policy (`SEALED_BATCH` withholds until durable close).
- `C-08`: Metric cards display explicit numerator/denominator, invalid trial counts, and mandatory `ILLUSTRATIVE` labels.
- `C-09`: Offline verifier runs `@noble` cryptography inside a Web Worker, removing unnecessary WebAssembly dependencies.

## 5. The 10 Invariants (In Our Own Words)
1. Dual Verdicts Always: Model safety and infrastructure evaluation integrity are displayed side-by-side; never unified into a single status.
2. No Optimistic UI: Success requires confirmed backend receipts; in-flight requests display indeterminate progress spinners only.
3. No Client-Side Embargo Filtering: Role boundaries are enforced at the data layer; withheld fields are absent from DTOs, never hidden via CSS.
4. Untrusted Text Is Inert: Attack, defense, and model outputs render solely via `<UntrustedText>` as raw text nodes with no HTML or unfurls.
5. Exact Positive Integer Epoch: Epoch values must be strictly validated positive integers, rejecting floats, strings, and booleans everywhere.
6. Pinned Verifier Trust: Cryptographic verification relies solely on externally pinned roots of trust; never trust bundle-provided keys.
7. Disciplined Claim Language: Absolutes ("zero leakage", "tamper-proof") are banned; only bounded, detected, and profiled claims are permitted.
8. Honest Telemetry & Hashes: Synthetic demo figures carry `ILLUSTRATIVE` tags; all displayed cryptographic digests are calculated by code.
9. Delayed Observer Feeds: Non-operator telemetry streams are coarse-grained and delayed (`DELAYED T-30s`) to prevent side-channel leaks.
10. Strict Architectural Scope: Code is locked strictly to the 8 approved routes and design system primitives; no feature or dependency bloat.

## 6. Spec Wireframe Invariant Violations
- Overview (§5.3): Metric tile "99.8% integrity" omits trial counts and illustrative tag (violates Invariant 8 & Correction C-08).
- War Room (§5.5): Execution waterfall displays a lone green "SAFE" label without evaluation integrity status (violates Invariant 1).
- Blue Console (§5.7): Displays live allow/block counts and per-turn decisions during active rounds (violates Invariants 3 & 9, C-02).
- Red Portal (§5.6): Exposes per-turn blocked status unconditionally rather than respecting the sealed profile (violates C-07).
- Evidence Inspector (§5.8): Authenticates public key directly from bundle and proposes WASM runtime (violates Invariant 6, C-03, C-09).
- Benchmarks (§5.9): Cache timing chart asserts proof of leakage absence rather than bounded ROC AUC (violates Invariant 7, C-01).

## 7. Open Questions
- Q-01: When swapping from mock to real backend, what authentication scheme (mTLS vs. JWT) will convey the active operator role?
- Q-02: Should `ResidualRiskPanel` support dynamic domain-specific threat scopes or remain anchored to the Q-005 baseline?
- Q-03: For offline forensic replay bundles, will artifact decryption keys be passed via user input or split-key escrow?

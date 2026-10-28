> Design specification: this document describes proposed future features, not the current interface. The shipped frontend uses mock state and is not connected to the backend. Original contributor acknowledgments below are retained.

> Design specification: this document describes proposed future features, not the current interface. The shipped frontend uses mock state and is not connected to the backend. Original contributor acknowledgments below are retained.

# BlindShield Arena: Strictly Necessary Frontend Page Features

**Document Version:** 1.0  
**Scope:** Hackathon Demonstrator / Minimal Viable Platform (MVP)  
**Target Audience:** Frontend Team (Lead: Mayank Joshi)  
**Guiding Principle:** **Strict Necessity Only.** Include only the actionable, necessary features required to operate the arena, protect evaluation integrity, and prove the security claims to judges. Omit all extraneous, off-track, or speculative features.

---

## 1. Scope Boundary: What Is IN vs. What Is OUT

To ensure the project stays 100% on track and avoids overengineering, the frontend features are strictly bounded:

### ✅ IN SCOPE (Strictly Necessary Now)
1. **Experiment Manifest Configuration & Preflight:** Setting up frozen versions, bounds, and sealing the manifest.
2. **Live Arena War Room:** Real-time visibility into the 5-stage pipeline, queue status, latency, and emergency quarantine.
3. **Red Team Portal:** Submitting text attacks, calculating blind commitments, and tracking query budgets.
4. **Blue Team Console:** Viewing frozen defense status, monitoring sanitized allow/block metrics (with zero active payload leaks), and inspecting post-round released forensics.
5. **Cryptographic Evidence & Offline Verifier:** Automated verification of Ed25519 signatures, RFC 8785 canonical hashes, witness receipts, and interactive tamper detection.
6. **Benchmark & Fairness Metrics:** Clear visualization of Attack Success Rate (ASR), Benign False-Block Rate, and Broker Overhead.
7. **Security Invariants:** Escaped plain-text rendering for all model/attack text, no hidden DOM secrets, accessible WCAG contrast.

### ❌ OUT OF SCOPE (Do NOT Build / Off-Track)
- ❌ **No User Auth & Registration Portals:** No password resets, social logins, or multi-tenant user management (use a simple header Role-Switcher).
- ❌ **No Payment, Billing, or Credit Systems:** Not a commercial SaaS.
- ❌ **No Marketplace or Community Forums:** Out of scope for security evaluation.
- ❌ **No Multimodal Media Uploads:** Strictly text-only evaluation (`A-005`). No image/audio/video processing or viewers.
- ❌ **No Fine-Tuning or Model Training UI:** Weights and defenses are strictly frozen (`A-006`).
- ❌ **No External Tool / Plugin Integrations:** No custom webhook builders, Slack/Discord integrations, or arbitrary API connectors.
- ❌ **No AI "Chatbot Assistants" in the UI:** No sidecar LLM chat widgets or decorative AI assistants.

---

## 2. Global Shell & Navigation (Persistent Across All Pages)

The shell provides global awareness of the active evaluation domain, security state, and active role.

### Necessary Features
1. **Header Brand & Domain Banner:**
   - Displays project name: `BlindShield Arena`.
   - Active Evaluation Domain indicator (e.g., `Domain: finance-risk-v1`).
   - Active Epoch indicator (e.g., `Epoch: #1`).
2. **Role-Switcher Dropdown:**
   - Single selector switching the UI perspective between:
     - `Platform Operator` (Full control, manifest sealing, emergency stop).
     - `Red Team (Attacker)` (Submissions, commitment, own budgets).
     - `Blue Team (Defender)` (Sanitized metrics, post-round forensics).
     - `Judge / Auditor` (Audit vault, cryptographic verification, benchmarks).
3. **Witness Status Indicator:**
   - Live badge showing connection to the independent Checkpoint Witness:
     - `WITNESS: CONNECTED` (Green).
     - `WITNESS: DEGRADED / UNAVAILABLE` (Purple — triggers automatic pause).
4. **Emergency Stop / Quarantine Button (Operator Only):**
   - High-visibility action to instantly pause an active round, revoke participant credentials, and seal evidence if an anomaly is detected.
5. **Main Navigation Bar:**
   - 6 direct page links:
     `[1. Setup] | [2. War Room] | [3. Red Portal] | [4. Blue Console] | [5. Evidence Verifier] | [6. Benchmarks]`

---

## 3. Page 1: Experiment Setup & Preflight (Operator View)

### Purpose
Configure the parameters of a new adversarial evaluation round, verify environment readiness, and freeze the cryptographic manifest before any execution begins.

### Necessary Features by Component

#### 3.1 Domain & Model Configuration
- **Domain ID Input:** Text field with automatic regex validation (`^[a-z0-9-]+$`).
- **Target Model Selector:** Pinned dropdown containing verified local/CPU model endpoints (e.g., `meta-llama/Llama-3-8B-Instruct`, `mistralai/Mistral-7B-Instruct-v0.3`).
- **Positive Integer Epoch Display:** Read-only number showing the next sequential epoch (e.g., `1`, `2`). *Enforces exact-type integer rule (`L-004`).*

#### 3.2 Blue Defense & Attacker Constraints
- **Blue Defense Container Digest:** Text input for Docker image digest (e.g., `sha256:7b91...`).
- **Defense Timeout Input:** Numeric input bounded to `100ms - 5000ms` (default: `1000ms`).
- **Query & Token Budgets:**
  - Maximum turns/queries (default: `50`).
  - Maximum prompt size in bytes (strict limit: `65,536 bytes`).
  - Maximum generated tokens (default: `256 tokens`).
- **Disclosure Policy Selector:**
  - `SEALED_BATCH` (Withhold all feedback and responses until round closes).
  - `DELAYED_FEEDBACK` (Return only ALLOW/BLOCK decision per turn; responses embargoed).

#### 3.3 Preflight Readiness Checker
- **"Run Preflight Check" Button:** Pings the broker backend to verify:
  - `gVisor (runsc)` runtime available and active.
  - `cgroup v2` memory/CPU controllers mounted.
  - Default-deny firewall rules active.
  - Pinned model reachable and clean.
- **Pass/Fail Checklist:** Displays green checks for all 4 items. If any check fails, the "Seal & Activate" button remains disabled.

#### 3.4 Manifest Preview & Seal Action
- **Canonical JSON Preview (RFC 8785):** Formatted box showing the exact deterministic manifest.
- **Computed Manifest SHA-256 Digest:** Live calculated 64-character hex hash.
- **"Seal Manifest & Activate Round" Button:** Submits manifest to the broker, receives signed receipt from the witness, and transitions state to `READY`.

---

## 4. Page 2: Live Arena War Room (Execution Command Center)

### Purpose
The primary monitoring dashboard during an active evaluation round. Shows the state machine, real-time pipeline progress, and system telemetry without leaking payload data.

### Necessary Features by Component

#### 4.1 Arena Status Bar
- **State Machine Badge:** Live status pill displaying one of the exact engine states:
  `CREATED` ➔ `SEALED` ➔ `READY` ➔ `RUNNING` ➔ `SCORED` ➔ `CLOSED` (or `INVALID`).
- **Turn Counter:** Shows current turn progress (e.g., `Turn 14 of 50`).

#### 4.2 5-Stage Pipeline Visualizer
Horizontal micro-stepper showing the active request moving through the system:
1. `Red Ingest`: Validating byte caps (≤ 70,000 bytes) and commitment.
2. `Broker Routing`: Dispatching current payload to isolated blue cell.
3. `Blue Evaluation`: Defense emitting `ALLOW` or `BLOCK` decision.
4. `Target Inference`: Model generating tokens (skipped if blocked).
5. `Scorer & Recorder`: Scorer evaluating output; recorder appending chained event.

#### 4.3 Essential Telemetry Gauges
- **Broker Overhead (ms):** P95 processing time added by the broker (target: `< 100ms`).
- **Blue Defense Latency (ms):** Execution time of the defensive container.
- **Target Time-To-First-Token (TTFT):** Milliseconds to first generated token.
- **Queue Depth:** Current pending requests in the broker queue (max 4).

#### 4.4 Live Chained Event Feed
- **Streaming Table:** Real-time stream of audit events as they are recorded:
  - `Sequence ID` (e.g., `#1042`).
  - `Timestamp` (UTC format: `HH:MM:SS.mmm`).
  - `Event Type` (`ATTEMPT_RESERVED`, `DEFENSE_DECISION`, `INFERENCE_COMPLETE`, `CHECKPOINT_SIGNED`).
  - `Previous Digest` (Truncated SHA-256).
  - `Current Digest` (Truncated SHA-256).
- *Strict Rule:* No prompt text or model response strings are ever rendered in this stream.

---

## 5. Page 3: Red Team Portal (Attacker Submissions)

### Purpose
Allows offensive operators to construct payloads, generate blinding commitments, submit attacks, and track their permitted query budgets.

### Necessary Features by Component

#### 5.1 Payload Submission Workshop
- **Plain-Text Input Area:** Textarea for the adversarial attack prompt.
- **Strict Byte & Token Counter:** Real-time counters showing exact bytes (e.g., `1,420 / 65,536 bytes`) and estimated tokens. Prevents submission if > 65,536 bytes.
- **Secret Nonce Field:**
  - 32-character random hex string (auto-generated with a "Regenerate" button).
  - Ensures short/enumerable prompts cannot be reverse-engineered from public hashes.
- **Commitment Calculator:** Displays `SHA-256(nonce + payload)` generated locally.
- **"Submit Payload" Button:** Sends payload and commitment to `POST /v1/experiments/{id}/attacks`.

#### 5.2 Query Budget Meter
- **Turns Remaining Display:** Large radial or linear progress meter showing consumed vs. remaining turns (e.g., `14 / 50 turns used`).
- **Token Budget Bar:** Shows total prompt and generation tokens used against the domain cap.

#### 5.3 Submission History & Feedback Table
- **Columns:**
  - `Turn #` (e.g., `1`, `2`, `3`).
  - `Timestamp`.
  - `Commitment Hash`.
  - `Status Badge`:
    - `SUBMITTED` (In progress).
    - `BLOCKED_BY_DEFENSE` (Defense successfully intercepted attack).
    - `ALLOWED_BY_DEFENSE` (Passed defense, reached target).
  - `Model Response`:
    - Displays `EMBARGOED UNTIL ROUND CLOSE` during active evaluation.
    - Unlocks plain-text response only after the operator closes the round.

---

## 6. Page 4: Blue Team Defense Console (Defender Console)

### Purpose
Allows defensive operators to inspect their frozen guardrail deployment, monitor real-time filter health without leaking in-flight attacks, and perform forensics on past closed rounds.

### Necessary Features by Component

#### 6.1 Defense Deployment Status
- **Image Digest Badge:** Displays the pinned image SHA-256 (e.g., `sha256:3a1b...`).
- **Sandbox Isolation Status:** Pill tag confirming `gVisor runsc (Read-Only Root)`.
- **Memory / CPU Limits:** Displays enforced limits (e.g., `512MB RAM | 1.0 CPU`).

#### 6.2 Real-Time Sanitized Traffic Metrics
- **Throughput & Decision Cards:**
  - `Total Inputs Processed` (e.g., `14`).
  - `Blocked Count & Percentage` (e.g., `6 (42.8%)` in Amber).
  - `Allowed Count & Percentage` (e.g., `8 (57.2%)` in Cobalt Blue).
  - `Average Defense Latency` (e.g., `142 ms`).
- **Sanitized Execution Log:** Table showing `Turn #`, `Timestamp`, `Decision (ALLOW/BLOCK)`, and `Latency (ms)`.
- *Strict Rule:* Zero attack text, keywords, or raw payload snippets appear in this view.

#### 6.3 Closed Round Forensic Explorer
- **Epoch Selector:** Dropdown listing only completed and closed epochs (e.g., `Epoch #01 (Closed 13:00 UTC)`).
- **Forensic Detail View (Unlocked only for closed epochs):**
  - Released Attack Prompt (escaped plain text).
  - Defense Classifier Decision & Matched Rule ID.
  - Target Model Response.
  - Scorer Ground Truth (`UNSAFE_JAILBREAK` vs. `SAFE`).
- **"Export Epoch Logs" Button:** Downloads decrypted forensic records for local model retraining.

---

## 7. Page 5: Evidence Vault & Offline Verifier (Judge & Auditor View)

### Purpose
Enables judges and auditors to independently verify the cryptographic authenticity of an evaluation without trusting the live server, and test tamper resistance.

### Necessary Features by Component

#### 7.1 Single-File Bundle Importer
- **Drag-and-Drop Area:** Accepts exported signed evaluation bundles (`.json` or `.zip`).
- **Clientside Verification Engine:** Uses browser-native WebCrypto / WebAssembly to verify signatures locally without uploading data anywhere.

#### 7.2 6-Point Cryptographic Verification Checklist
Interactive verification card showing instant Pass/Fail results for:
1. **Public Key Match:** Pinned Ed25519 key matches authorized recorder identity.
2. **Terminal Signature:** Checkpoint signature validates against the final event digest.
3. **Sequential Hash Chain:** Every event digest correctly chains from `Event 1` to `Event N`.
4. **Canonical Schema (RFC 8785):** JSON structure adheres to strict formatting rules.
5. **Manifest Consistency:** Public manifest digest matches sealed round parameters.
6. **Witness Monotonicity:** Sequence watermark matches independent witness receipt.
- **Overall Verdict Banner:**
  - `VALID_WITHIN_PROFILE` (Green) if all 6 pass.
  - `INVALID / TAMPERED` (Purple/Red) if any check fails.

#### 7.3 Interactive Tamper Testing Simulator
Three buttons to demonstrate verification rigor to judges:
- **Button 1: "Flip Single Byte in Event Log":** Modifies 1 character in a past event ➔ Verifier immediately flags `Chain Break at Event #X`.
- **Button 2: "Drop / Truncate Last Event":** Removes the final event ➔ Verifier immediately flags `Terminal Digest Mismatch`.
- **Button 3: "Replay Stale Epoch Checkpoint":** Substitutes past epoch receipt ➔ Verifier immediately flags `Witness Watermark Stale`.

#### 7.4 Dual-Verdict Score Card
Clear side-by-side verdict cards:
- **Card A: Model Robustness Verdict** (`ATTACK_DEFENDED` / `ATTACK_SUCCEEDED`).
- **Card B: Evaluation Integrity Verdict** (`VALID_WITHIN_PROFILE` / `INVALID`).

---

## 8. Page 6: Benchmark Analytics & Safety Matrix (Results View)

### Purpose
Presents final evaluation metrics comparing model safety, defensive over-filtering, infrastructure latency overhead, and cache timing leakage.

### Necessary Features by Component

#### 8.1 Robustness & Utility Metrics
- **Attack Success Rate (ASR) Card:** Bar chart comparing:
  - *Baseline Unprotected Model ASR* (e.g., `78%`).
  - *Defended Model ASR* (e.g., `12%`).
- **Benign False-Block Rate Card:** Displays percentage of safe, benign prompts erroneously blocked by the defense (e.g., `4.2%`). Ensures defenders cannot "cheat" by blocking all inputs.
- **Negative Usefulness Baseline:** Displays the "Deny-All" baseline score (`0% Utility`) to penalize trivial guardrails.

#### 8.2 Latency & Overhead Breakdown
- **Stacked Bar Chart:**
  - Target Model Inference time (e.g., `620 ms`).
  - Blue Guardrail Execution time (e.g., `140 ms`).
  - Broker & Evidence Recording time (e.g., `18 ms`).
- **Overhead Percentage Display:** Broker overhead as a percentage of total latency (e.g., `2.3%`).

#### 8.3 Prefix-Cache Leakage Verification Plot
- **ROC AUC Timing Distinguishability Metric:**
  - Displays ROC AUC score comparing cache-hit vs. cache-miss timing (Target: `0.50 ± 0.05`).
  - Proves that dedicated instances and cache salting successfully prevent KV-cache timing side channels.

#### 8.4 Export Verified Summary
- **"Download Verified Evaluation Summary" Button:** Exports a single-page markdown/PDF report containing final scores, manifest hash, and witness verification stamps.

---

## 9. Frontend Hardening & Safety Rules

Every page component must adhere to these non-negotiable frontend engineering rules:

| Rule | Implementation Requirement |
|---|---|
| **Untrusted Text Escaping** | All attack text and model responses MUST be rendered inside `<pre>` or `<code>` blocks using strict text escaping (`textContent` or React default escaping). NEVER use `dangerouslySetInnerHTML`. |
| **No External Fetching** | Do NOT parse URLs in model responses to load images, favicons, or link previews. |
| **No Secret CSS Hiding** | Do NOT include unreleased attack payloads in the DOM with `display: none`. Filter all data server-side before sending to the client. |
| **No Optimistic Badges** | Do NOT show green "Success" badges until an authenticated receipt is returned from the backend. |
| **WCAG 2.2 Accessibility** | Maintain minimum 4.5:1 text contrast (7:1 for tables), visible focus rings on all interactive elements, and `aria-live="polite"` on the live event log. |

---

## 10. Summary Checklist for Frontend Implementation

Use this checklist during development:

- [ ] **Shell:** Header, domain badge, role-switcher, witness status pill, emergency stop button.
- [ ] **Page 1 (Setup):** Domain/model inputs, budget bounds, preflight checker, canonical JSON preview, seal button.
- [ ] **Page 2 (War Room):** State machine badge, 5-stage pipeline stepper, telemetry gauges, live chained event feed.
- [ ] **Page 3 (Red Portal):** Textarea with 64KB counter, nonce generator, commitment calculator, budget meter, redacted history.
- [ ] **Page 4 (Blue Console):** Pinned image status, sanitized allow/block metrics (no text leaks), closed-epoch forensic viewer.
- [ ] **Page 5 (Evidence Verifier):** Drag-and-drop bundle dropzone, 6-point verification checklist, 3 tamper simulation buttons, dual-verdict cards.
- [ ] **Page 6 (Benchmarks):** ASR comparison chart, false-block rate card, latency stack breakdown, ROC AUC cache plot, export button.
- [ ] **Hardening:** Verified plain-text escaping and zero client-side payload leaks.

---
*End of Strictly Necessary Frontend Features Specification.*

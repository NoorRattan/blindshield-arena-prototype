# Infrastructure and local admission

The repository includes source for a host-specific three-lane Qwen/llama.cpp prototype and sanitized profile/receipt metadata. Those artifacts document one bounded local environment; they are not portable credentials or a ready-to-run deployment.

A new host needs a fresh source/profile admission, compatible Docker images, the pinned model, prepared corpus and receipt, matching owner-managed authorities, and sufficient measured capacity. Private keys, corpus openings, local stores, and external rollback-anchor state are intentionally absent. See the [release runbook](../docs/PROTOTYPE-RELEASE.md) and [service guide](../docs/PROTOTYPE-SERVICE.md).

The retained public CA, recorder, and witness files under owner-delegated-n08 are trust metadata needed to identify the historical profile inputs. The alternate SmolLM2 candidate notes and machine-capacity observations are omitted from this public snapshot. No private key is included.

## Limits

The published profile is tied to exact source, input, image, signature, and capacity bindings. Editing or moving those inputs may cause admission to refuse. A new machine must run its own admission and calibration; a previous profile does not transfer.

The measured controls do not establish host CPU exclusivity, broad fairness, physical I/O quota enforcement, host-admin rollback resistance, forensic erasure, population timing/channel bounds, or independent-machine portability. The Step 6 report records mixed results, not full acceptance.


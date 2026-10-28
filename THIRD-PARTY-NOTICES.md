# Third-party notices

The MIT license in the repository root applies only to project-authored material whose contributors have authorized that license. It does not relicense dependencies, model weights, datasets, or container images. Confirm all contributor rights before public distribution.

## Qwen2.5-0.5B-Instruct-GGUF

- Upstream: [Qwen/Qwen2.5-0.5B-Instruct-GGUF](https://huggingface.co/Qwen/Qwen2.5-0.5B-Instruct-GGUF/tree/9217f5db79a29953eb74d5343926648285ec7e67)
- Pinned revision: 9217f5db79a29953eb74d5343926648285ec7e67
- Declared upstream license: Apache-2.0
- Included upstream license and model card: third-party/qwen2.5-0.5b-instruct-gguf/
- Model weights are not included.

## llama.cpp

- Upstream: [ggml-org/llama.cpp](https://github.com/ggml-org/llama.cpp/tree/1d88cb05f1a257f90741538ca3aca6c1b015c6d3)
- Pinned revision: 1d88cb05f1a257f90741538ca3aca6c1b015c6d3
- License: MIT
- Included upstream license: third-party/llama.cpp/LICENSE
- The pinned container image is not included.

## JailbreakBench JBB-Behaviors

- Upstream: [JailbreakBench/JBB-Behaviors](https://huggingface.co/datasets/JailbreakBench/JBB-Behaviors/tree/886acc352a31533ffbcf4ef22c744658688086fc)
- Pinned revision: 886acc352a31533ffbcf4ef22c744658688086fc
- License: MIT; the pinned upstream license text is included at third-party/jailbreakbench-jbb-behaviors/LICENSE.
- Attribution and citation: see third-party/jailbreakbench-jbb-behaviors/README.md.
- Dataset records, prepared corpus, source data, owner-held preparation receipt, and corpus opening keys are not included.

## Frontend fonts

The frontend uses Barlow, Bebas Neue, and DM Mono through the Fontsource packages. The SBOM identifies these font packages as OFL-1.1. Font binaries are obtained through the package dependencies and are not checked into this source snapshot.

## SBOM and dependency limits

SPDX inventories are in third-party/sbom/. They include the frontend lockfile, pinned container images, and exact backend Python package pins. Some entries are NOASSERTION, and the backend requirements lock has no artifact hashes, so the reports do not identify exact installed wheels or source archives. The broader backend environment lock is marked incomplete. These inventories are useful disclosure, not legal clearance or proof of exploitability.


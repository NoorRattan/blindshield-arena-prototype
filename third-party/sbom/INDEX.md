# Local SBOM artifacts

Generated locally on 2026-10-28 for the history-free release-review copy. These are metadata reports; no model weights or dataset payloads are included.

## Provenance

- Source repository revision: `2bfa6916b53f4ee43e551ea063f52ee1ab73d124`.
- Frontend lock input SHA-256: `d054446f651141faeb010db8e9a3798baddc9f60654cd590d1985740964e9940` (`frontend/package-lock.json`).
- Pinned image IDs were read from `backend/infra/model-component/profile.json` (SHA-256 `8671204cda83fcd7198026b9fdcb2f49f9d36016faead59d4e752ffa1ca7d9c5`) and verified with local `docker image inspect` before scanning.
- Tool versions: npm `11.17.0`; Docker Engine `29.9.2`; Docker Scout `v1.27.0` (commit `1be68946eb316438e64568a2a8f1d4858ba9ba21`).
- Scout ran with `DOCKER_SCOUT_OFFLINE=true` and `DOCKER_SCOUT_NO_CACHE=true`; image references used the `local://` resolver. No registry pulls or builds were used.

## Reports

| File | Input | Scout indexed packages | SPDX `packages` entries | SHA-256 |
|---|---|---:|---:|---|
| `frontend-package-lock.spdx.json` | npm lockfile only; `npm sbom --package-lock-only --sbom-format spdx --sbom-type application`, with npm offline mode | n/a | 610 | `4e968fec135cabed6e40a59ea4cfe961971d1cc8abdfae6cee86c4a81b999af7` |
| `llama-image.spdx.json` | pinned assembled llama image `sha256:4a5a9f46dc11132862f943e0f3a0c32fa032d84bb52bd0241b7c046515f8ae68`; scanned as `local://blindshield-sbom:llama-pinned` | 609 | 745 | `0303341af238d71394e0552a0bc1a37efce7dddc2d7f12aaa2819f7582b720bc` |
| `defense-python-image.spdx.json` | pinned defense Python image `sha256:c2ba5e610d1064f1a8b84ee3b1455942eeccca3d90a02909eda80b8f5d26658c`; scanned as `local://blindshield-sbom:defense-python-pinned` | 127 | 159 | `1e8f5c925729923596d6bf4677772b1da3cb47758392c35116672c5d68010662` |
| `backend-python-locked-dependencies.spdx.json` | `backend/requirements.lock` SHA-256 `0e6b8c7b39b814bb4a5395e66d7de69fc635439a048db832465d29c310659678`; exact-version package/license inventory from matching installed metadata | n/a | 15 | `b96ec111132859eb04f264cfc546490e7f2d1eb1726912d7f1054919c57fe996` |

“Scout indexed packages” is the package count printed by the Scout CLI. SPDX `packages` entries is the parsed number of elements in each JSON document's `packages` array; these counters differ for image reports.

Both temporary Docker aliases were verified to resolve to the exact pinned image IDs and were removed after generation. No containers were started, stopped, or removed.

## Remaining Python artifact provenance gap

The backend lock now has an SPDX 2.3 inventory with all 15 pinned package identities and declared license expressions. It is derived from the exact versions in `backend/requirements.lock` and matching installed `.dist-info` metadata; Colorama and Pluggy use their installed license text/metadata. This is a package/license inventory, not an attestation of the exact installed wheels: the lock has no artifact hashes, the wheel cache contains no locally built wheels, and the nonempty pip HTTP cache has no artifact-to-pin binding. No wheel or source-archive digest is established. The wider `backend/environment.lock.json` still says `lock_complete=false`.

The [exact-version advisory query receipt](../../backend/evidence/backend-runtime-advisory-query-20261028.json) covers the 15 package pins in that lock and records no matching advisories. It does not enumerate the repository's private Dependabot alert list or scan container image packages.


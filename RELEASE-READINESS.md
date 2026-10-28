# Prototype release status

The owner authorized pushing this evaluation package to `NoorRattan/blindshield-arena-prototype` on 28 October 2026 and confirmed MIT publication permission from Mayank Joshi and Monu Kumar, including the new frontend. See [the permission record](CONTRIBUTOR-RIGHTS.md).

This repo builds on reviewed sanitized root `2f73df8`, not the original working repository's history. Backend runtime and admission inputs retain their measured bytes. The new frontend comes from delivery `5a6b557`; earlier frontend receipts remain historical and do not validate that delivery.

See [EVALUATION.md](EVALUATION.md) for current checks and integration limits. Existing receipts retain their original blocker state; later owner decisions do not rewrite historical records.

Before later pushes, run `python tools/check_public_snapshot.py` from the root. This bounded checker examines staged content and reachable history for common local-path, key, token and private-artifact patterns. It is not a guarantee that every sensitive fact has been identified.

Keep raw admission/run artifacts under ignored `backend/artifacts/`. Admission grants are source/host specific and time limited. They do not establish complete T/P acceptance or production readiness.

# Local public-release candidate — 28 October 2026

This directory is a separate, locally retained source snapshot. Its Git repository
starts with a new root commit. The original working repository, branches, history,
private artifacts, and remote visibility are preserved. No public GitHub repository
has been created and this candidate has no remote.

Publication status: **BLOCKED — contributor permission records pending review**.
The owner reports that written permission records will be supplied. That statement
is not a substitute for inspecting the records, their scope, and the rights holders.

## Release gates

| Gate | Status |
| --- | --- |
| Independent Git root, no inherited history | PASS: new root commit `2f73df80ba05af51bc10554b606ba22ee3e89ff1`; no remote |
| Tracked content and reachable-history privacy scan | PASS at the initial root; five checker regression cases passed; re-run before sharing |
| Supported public application test subset | PASS: 548 tests, 14 subtests, one documented unsupported coordinated-rollback skip. See backend/README.md for the fixture exclusions. |
| New source-bound static/calibration/service admission and real demo | PASS at source commit `2f73df8`: native-Linux preparation, static admission, six-call calibration, service admission, six-call authenticated demo, offline verification exit 0, and cleanup. Same-laptop prepared-host scope only. |
| Contributor MIT redistribution permission | Pending review of records for Mayank and Monu, plus any other rights holders |
| Third-party source notices | Included; inventories have NOASSERTION entries and do not clear redistribution of model weights, data, or images |
| GitHub upload / public visibility | Not performed; local-only |

The root MIT license records the owner's selected license for contributions whose
rights holders authorize it. It does not resolve missing permissions. Keep private
permission records outside this repository; record a minimal public clearance
summary only after they are reviewed. See [the rights checklist](CONTRIBUTOR-RIGHTS.md).

Run `python tools/check_public_snapshot.py` from this repository before sharing.
It checks staged paths/content and all reachable Git objects for common local-path,
private-key, credential, and forbidden-artifact patterns. It is a bounded automated
check, not a guarantee that every sensitive fact has been identified.

Raw admission logs and run artifacts belong only under ignored `backend/artifacts/`.
New admissions are host-specific and time-limited; they do not establish full T/P
acceptance, production readiness, or independent-machine reproducibility.

The [validation summary](backend/evidence/public-snapshot-validation-20261028.json)
records both the passing native-Linux run and the earlier failed mounted-filesystem
demo. The earlier run reached scoring but failed the three-lane processing-overlap
observation, so it did not reach offline verification. It was not resumed or relabeled
as a pass; a new native-filesystem checkout and new output directory were used with
the same committed source and unchanged checks. Its raw artifacts remain private.
The summary also retains the earlier test-command failure caused by omitted owner
fixtures. Documentation-only updates after the measured root do not change runtime
source, admission inputs, tests, or frontend source.

When all gates are satisfied and publication is authorized, create a **new** GitHub
repository and push only this repository's reviewed branch. Never change the
visibility of the original repository or add its history as a parent, remote,
submodule, bundle, or archive. Re-run the privacy check after any later commit.

The local pre-push hook deliberately refuses pushes during local preparation.
Removing that hook is appropriate only after the unresolved release gates have
actually been closed and the intended destination has been checked.

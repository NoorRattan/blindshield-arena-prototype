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
| Independent Git root, no inherited history | To be verified after initial commit |
| Tracked content and reachable-history privacy scan | To be run before handoff |
| New source-bound static/calibration/service admission and real demo | Pending; historical grants do not admit this snapshot |
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

When all gates are satisfied and publication is authorized, create a **new** GitHub
repository and push only this repository's reviewed branch. Never change the
visibility of the original repository or add its history as a parent, remote,
submodule, bundle, or archive. Re-run the privacy check after any later commit.

The local pre-push hook deliberately refuses pushes during local preparation.
Removing that hook is appropriate only after the unresolved release gates have
actually been closed and the intended destination has been checked.

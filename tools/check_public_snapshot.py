"""Check the staged snapshot and reachable history without printing matched secrets."""
from __future__ import annotations

import io
import json
from pathlib import Path, PurePosixPath
import re
import subprocess


ROOT = Path(__file__).resolve().parents[1]
PATTERNS = {
    "machine_path": re.compile(rb"(?i)(?:[a-z]:[\\/]+(?:users|github-repo|program files)[\\/]|/(?:home|Users)/[^/\s]+/|/mnt/[a-z]/)") ,
    "private_key_block": re.compile(rb"-----BEGIN (?:[A-Z0-9]+ )*PRIVATE KEY-----\s*[\r\n]+[A-Za-z0-9+/=]{20,}"),
    "github_token": re.compile(rb"(?:gh[pousr]_[A-Za-z0-9]{30,}|github_pat_[A-Za-z0-9_]{40,})"),
    "aws_access_key": re.compile(rb"(?:AKIA|ASIA)[A-Z0-9]{16}"),
    "slack_token": re.compile(rb"xox[baprs]-[A-Za-z0-9-]{20,}"),
}
PRIVATE_PARTS = {"artifacts", ".venv", "node_modules", "secrets", "memory files", ".git"}
PRIVATE_SUFFIXES = {".gguf", ".key", ".pfx", ".p12", ".sqlite", ".sqlite3", ".db", ".zip", ".tar", ".bundle"}


def git(*args: str) -> bytes:
    return subprocess.check_output(["git", *args], cwd=ROOT, stderr=subprocess.PIPE)


def main() -> int:
    if Path(git("rev-parse", "--show-toplevel").decode().strip()).resolve() != ROOT:
        raise ValueError("SEPARATE_GIT_ROOT_REQUIRED")
    issues: list[dict] = []
    objects: set[bytes] = set()
    checked: set[bytes] = set()

    def content(label: str, raw: bytes) -> None:
        for name, pattern in PATTERNS.items():
            if pattern.search(raw):
                issues.append({"object": label, "category": name})

    def path_check(path: str) -> None:
        parsed = PurePosixPath(path)
        parts = set(parsed.parts)
        if (parts & PRIVATE_PARTS or parsed.suffix.lower() in PRIVATE_SUFFIXES
            or parsed.name.startswith(".env") or path.startswith(("state/", "backend/state/"))):
            issues.append({"path": path, "category": "private_artifact_path"})
        content("path:" + path, path.encode())

    # Every indexed file is checked, including a staged file not yet in HEAD.
    entries = [x for x in git("ls-files", "--stage", "-z").split(b"\0") if x]
    for entry in entries:
        meta, path = entry.split(b"\t", 1)
        mode, oid, stage = meta.split()
        name = path.decode("utf-8")
        path_check(name)
        if mode not in {b"100644", b"100755"} or stage != b"0":
            issues.append({"path": name, "category": "nonregular_or_unmerged_entry"})
        objects.add(oid)
        checked.add(oid)

    commits = git("rev-list", "--all").splitlines()
    for commit in commits:
        objects.add(commit)
        # Enumerate every historical tree as well as every blob; a removed
        # private file must still prevent publication of this history.
        for entry in git("ls-tree", "-rz", commit.decode()).split(b"\0"):
            if not entry:
                continue
            meta, path = entry.split(b"\t", 1)
            mode, kind, oid = meta.split()
            path_check(path.decode("utf-8"))
            if kind != b"blob" or mode not in {b"100644", b"100755"}:
                issues.append({"object": oid.decode(), "category": "nonregular_history_entry"})
            elif oid not in checked:
                objects.add(oid)
                checked.add(oid)

    # Include tag messages, then inspect all collected objects in one binary-safe
    # batch instead of spawning a process for each source file.
    for line in git("for-each-ref", "--format=%(objectname) %(objecttype)", "refs/tags").splitlines():
        oid, kind = line.split()
        while kind == b"tag":
            objects.add(oid)
            target = git("cat-file", "tag", oid.decode()).splitlines()
            oid, kind = target[0].split()[1], target[1].split()[1]
    batch = subprocess.check_output(["git", "cat-file", "--batch"], cwd=ROOT,
                                    input=b"\n".join(sorted(objects)) + b"\n")
    stream = io.BytesIO(batch)
    for _ in objects:
        oid, kind, length = stream.readline().split()
        raw = stream.read(int(length))
        if stream.read(1) != b"\n":
            raise ValueError("INVALID_GIT_BATCH_FRAMING")
        content(oid.decode(), raw)

    result = {"result": "FAIL" if issues else "PASS_BOUNDED_PRIVACY_CHECK",
              "commits_checked": len(commits), "unique_blobs_checked": len(checked),
              "indexed_files": len(entries), "issues": issues,
              "rights_clearance_established": False, "publication_authorized": False}
    print(json.dumps(result, indent=2))
    return 1 if issues else 0


if __name__ == "__main__":
    raise SystemExit(main())

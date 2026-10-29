#!/usr/bin/env python3
"""Fail-closed, redacted Gitleaks gate for new Git content."""

import hashlib
import json
import os
import re
import select
import shutil
import subprocess
import sys
import tempfile
import time
from pathlib import Path, PurePosixPath


GITLEAKS_VERSION = "8.30.1"
SOURCE_BASE_SHA = "45c35e40c46166dc726ccc52f5d27f40f2449f99"
REVISION_RANGE = re.compile(r"(?:[0-9a-fA-F]{40}|HEAD)(?:\.\.(?:[0-9a-fA-F]{40}|HEAD))?\Z")
KEY_SUFFIXES = (".pem", ".key", ".p12", ".pfx", ".jks", ".keystore")
DATA_SUFFIXES = (".db", ".db-wal", ".db-shm", ".db-journal", ".sqlite", ".sqlite3", ".sqlite-wal", ".sqlite-shm", ".sqlite-journal", ".sqlite3-wal", ".sqlite3-shm", ".sqlite3-journal")
SQLITE_HEADER = b"SQLite format 3\0"


def git(*args: str) -> bytes:
    result = subprocess.run(["git", *args], capture_output=True, timeout=30)
    if result.returncode != 0:
        raise RuntimeError("Git query failed")
    return result.stdout


def protected_path(path: str) -> bool:
    parts = PurePosixPath(path).parts
    if parts[0] in {".codegraph", "graphify-out", ".agentmemory"} or ".aws" in parts:
        return True
    name = parts[-1].lower()
    if name == ".env" or (".env." in name and not name.endswith((".env.example", ".env.sample", ".env.template"))):
        return True
    if name.endswith(".env") and name not in {"example.env", "sample.env", "template.env"}:
        return True
    if name in {".npmrc", ".pypirc", ".netrc", "id_rsa", "id_ed25519", "credentials.json", "service-account.json", ".runner", ".credentials", ".credentials_rsaparams"}:
        return True
    return name.endswith(KEY_SUFFIXES + DATA_SUFFIXES + (".bak", ".backup"))


def decode_paths(output: bytes) -> list[str]:
    return [name.decode("utf-8", "surrogateescape") for name in output.split(b"\0") if name]


def bounded_range(revision: str) -> str:
    if ".." in revision:
        return revision
    git("merge-base", "--is-ancestor", SOURCE_BASE_SHA, revision)
    return f"{SOURCE_BASE_SHA}..{revision}"


def changed_blobs(mode: str, revision_range: str | None) -> set[tuple[str, str]]:
    if mode == "staged":
        output = git("diff", "--cached", "--name-only", "--diff-filter=ACMRT", "-z")
        return {(path, f":{path}") for path in decode_paths(output)}
    paths = set()
    for commit in git("rev-list", revision_range or "").decode("ascii").splitlines():
        output = git("diff-tree", "--root", "-m", "--no-commit-id", "--name-only", "--diff-filter=ACMRT", "-r", "-z", commit)
        paths.update((path, f"{commit}:{path}") for path in decode_paths(output))
    return paths


def has_sqlite_header(blob: str) -> bool:
    process = subprocess.Popen(["git", "cat-file", "blob", blob], stdout=subprocess.PIPE, stderr=subprocess.DEVNULL)
    header = b""
    try:
        deadline = time.monotonic() + 30
        while len(header) < len(SQLITE_HEADER):
            remaining = deadline - time.monotonic()
            if remaining <= 0 or not select.select([process.stdout], [], [], remaining)[0]:
                raise RuntimeError("Git blob read timed out")
            chunk = os.read(process.stdout.fileno(), len(SQLITE_HEADER) - len(header))
            if not chunk:
                break
            header += chunk
    except BaseException:
        process.kill()
        raise
    finally:
        process.stdout.close()
        if len(header) == len(SQLITE_HEADER) and process.poll() is None:
            process.kill()
        code = process.wait(timeout=5)
    if len(header) < len(SQLITE_HEADER) and code != 0:
        raise RuntimeError("Git blob query failed")
    return header == SQLITE_HEADER


def invoke_scanner(scanner: str, kind: str, target: list[str], report: Path) -> list[dict]:
    command = [
        scanner, kind, "--config", ".gitleaks.toml", "--redact=100", "--ignore-gitleaks-allow",
        "--no-banner", "--log-level", "error", "--timeout", "120", "--report-format", "json",
        "--report-path", str(report), *target,
    ]
    result = subprocess.run(command, capture_output=True, timeout=130)
    findings = json.loads(report.read_text()) if report.exists() else []
    if result.returncode == 0 and findings == []:
        return []
    if result.returncode != 1 or not isinstance(findings, list) or not findings:
        raise RuntimeError("Gitleaks scan failed")
    return findings


def print_findings(findings: list[dict]) -> int:
    rows = []
    for finding in findings:
        if not isinstance(finding, dict):
            raise RuntimeError("Gitleaks report malformed")
        rule = finding.get("RuleID")
        path = finding.get("File")
        line = finding.get("StartLine")
        if not isinstance(rule, str) or not isinstance(path, str) or not isinstance(line, int):
            raise RuntimeError("Gitleaks report malformed")
        fingerprint = hashlib.sha256(path.encode("utf-8", "surrogateescape")).hexdigest()
        rows.append(f"{json.dumps(rule)} path-sha256={fingerprint} line={line}")
    for row in rows:
        print(row)
    if rows:
        print(f"Gitleaks blocked {len(rows)} finding(s); values suppressed", file=sys.stderr)
    return 1 if rows else 0


def scan(scanner: str, mode: str, revision: str | None) -> int:
    os.umask(0o077)
    try:
        with tempfile.TemporaryDirectory(prefix="omp-gitleaks-") as temporary:
            root = Path(temporary)
            findings = []
            if mode != "tag":
                target = ["--staged", "."] if mode == "staged" else ["--log-opts", f"--diff-merges=first-parent {revision}", "."]
                findings.extend(invoke_scanner(scanner, "git", target, root / "git-report.json"))

            messages = root / "messages"
            messages.mkdir()
            if mode == "range":
                for commit in git("rev-list", revision or "").decode("ascii").splitlines():
                    (messages / f"commit-{commit}.txt").write_bytes(git("show", "-s", "--format=%B", commit))
            elif mode == "tag":
                tag_object = revision or ""
                seen = set()
                while git("cat-file", "-t", tag_object).strip() == b"tag":
                    if tag_object in seen:
                        raise RuntimeError("Tag object cycle")
                    seen.add(tag_object)
                    payload = git("cat-file", "-p", tag_object)
                    match = re.match(rb"object ([0-9a-f]{40})\n", payload)
                    if match is None:
                        raise RuntimeError("Tag object malformed")
                    (messages / f"tag-{tag_object}.txt").write_bytes(payload)
                    tag_object = match.group(1).decode("ascii")
                if git("cat-file", "-t", tag_object).strip() != b"commit":
                    raise RuntimeError("Tag target is not a commit")

            if any(messages.iterdir()):
                for finding in invoke_scanner(scanner, "dir", [str(messages)], root / "message-report.json"):
                    name = Path(finding.get("File", "")).name
                    if name.startswith("commit-") and name.endswith(".txt"):
                        label = "commit:" + name[7:-4]
                    elif name.startswith("tag-") and name.endswith(".txt"):
                        label = "tag:" + name[4:-4]
                    else:
                        raise RuntimeError("Gitleaks message report malformed")
                    findings.append({**finding, "File": label})
            return print_findings(findings)
    except (OSError, subprocess.TimeoutExpired, ValueError, RuntimeError, UnicodeError):
        print("Git or Gitleaks scan failed; raw output suppressed", file=sys.stderr)
        return 2


def main() -> int:
    if len(sys.argv) not in {2, 3} or sys.argv[1] not in {"staged", "range", "tag"}:
        print("usage: gitleaks_guard.py staged | range REVISION_RANGE | tag TAG_OBJECT_SHA", file=sys.stderr)
        return 2
    mode = sys.argv[1]
    revision = sys.argv[2] if len(sys.argv) == 3 else None
    valid_revision = (mode == "staged" and revision is None) or (
        mode == "range" and revision is not None and REVISION_RANGE.fullmatch(revision)
    ) or (mode == "tag" and revision is not None and re.fullmatch(r"[0-9a-fA-F]{40}", revision))
    if not valid_revision:
        print("Invalid revision range", file=sys.stderr)
        return 2
    scanner = shutil.which("gitleaks")
    if scanner is None:
        print("Gitleaks unavailable", file=sys.stderr)
        return 2
    try:
        version = subprocess.run([scanner, "version"], capture_output=True, text=True, timeout=5)
        if version.returncode != 0 or version.stdout.strip() != GITLEAKS_VERSION:
            print("Gitleaks version mismatch", file=sys.stderr)
            return 2
        root = Path(os.fsdecode(git("rev-parse", "--show-toplevel").strip())).resolve()
        if Path.cwd().resolve() != root:
            print("Git root mismatch", file=sys.stderr)
            return 2
        if mode == "range" and revision is not None:
            revision = bounded_range(revision)
        changed = changed_blobs(mode, revision) if mode != "tag" else set()
        blocked = {path for path, _ in changed if protected_path(path)}
        if not blocked:
            blocked = {path for path, blob in changed if has_sqlite_header(blob)}
    except (OSError, subprocess.TimeoutExpired, RuntimeError, UnicodeError):
        print("Git or scanner preflight failed; details suppressed", file=sys.stderr)
        return 2
    if blocked:
        print(f"Protected path(s): {len(blocked)}")
        return 1
    return scan(scanner, mode, revision)


if __name__ == "__main__":
    sys.exit(main())

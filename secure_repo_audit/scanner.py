"""Small, offline repository security auditor.

The scanner only reads files below the requested directory. It never makes
network requests, executes discovered files, or prints secret values.
"""

from __future__ import annotations

import argparse
import json
import os
import re
import stat
from dataclasses import asdict, dataclass
from pathlib import Path

SKIP_DIRS = {".git", ".venv", "venv", "node_modules", "__pycache__", ".tox", "dist", "build"}
SKIP_SUFFIXES = {".png", ".jpg", ".jpeg", ".gif", ".mp4", ".zip", ".parquet", ".xlsx", ".pdf"}
SECRET_PATTERNS = [
    ("AWS access key", re.compile(r"\bAKIA[0-9A-Z]{16}\b")),
    ("GitHub token", re.compile(r"\bgh[pousr]_[A-Za-z0-9_]{20,}\b")),
    ("private key", re.compile(r"-----BEGIN (?:RSA|OPENSSH|EC|DSA|PRIVATE) KEY-----")),
    ("generic credential assignment", re.compile(
        r"(?i)\b(?:api[_-]?key|access[_-]?token|client[_-]?secret|password)\b\s*[:=]\s*['\"](?!\$\{|\$env:|os\.environ|process\.env)[^'\"]{12,}['\"]"
    )),
]


@dataclass(frozen=True)
class Finding:
    rule_id: str
    severity: str
    path: str
    line: int | None
    message: str
    remediation: str


def iter_files(root: Path):
    for path in root.rglob("*"):
        if not path.is_file() or any(part in SKIP_DIRS for part in path.parts):
            continue
        if path.suffix.lower() in SKIP_SUFFIXES or path.stat().st_size > 2_000_000:
            continue
        yield path


def scan_file(path: Path, root: Path) -> list[Finding]:
    findings: list[Finding] = []
    try:
        text = path.read_text(encoding="utf-8")
    except (UnicodeDecodeError, OSError):
        return findings
    relative = path.relative_to(root).as_posix()
    for number, line in enumerate(text.splitlines(), 1):
        for label, pattern in SECRET_PATTERNS:
            if pattern.search(line):
                findings.append(Finding(
                    rule_id="SRA001" if label != "private key" else "SRA002",
                    severity="high",
                    path=relative,
                    line=number,
                    message=f"Possible {label} found; value is intentionally hidden.",
                    remediation="Remove the value, rotate it if real, and load it from a secret manager or environment variable.",
                ))
                break
    try:
        mode = path.stat().st_mode
        if os.name != "nt" and mode & stat.S_IWOTH:
            findings.append(Finding("SRA003", "medium", relative, None, "File is writable by everyone.", "Remove world-write permission."))
    except OSError:
        pass
    return findings


def scan(root: Path) -> list[Finding]:
    findings: list[Finding] = []
    for path in iter_files(root):
        findings.extend(scan_file(path, root))
    return findings


def to_sarif(findings: list[Finding]) -> dict:
    results = []
    for finding in findings:
        result = {"ruleId": finding.rule_id, "level": "error" if finding.severity == "high" else "warning", "message": {"text": finding.message}, "locations": [{"physicalLocation": {"artifactLocation": {"uri": finding.path}}}]}
        if finding.line:
            result["locations"][0]["physicalLocation"]["region"] = {"startLine": finding.line}
        results.append(result)
    return {"version": "2.1.0", "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "runs": [{"tool": {"driver": {"name": "secure-repo-audit", "version": "1.0.0"}}, "results": results}]}


def main() -> None:
    parser = argparse.ArgumentParser(description="Run offline defensive security checks on a source repository.")
    parser.add_argument("path", nargs="?", default=".", type=Path)
    parser.add_argument("--format", choices=("text", "json", "sarif"), default="text")
    args = parser.parse_args()
    root = args.path.resolve()
    findings = scan(root)
    if args.format == "json":
        print(json.dumps([asdict(item) for item in findings], indent=2))
    elif args.format == "sarif":
        print(json.dumps(to_sarif(findings), indent=2))
    else:
        if findings:
            for item in findings:
                location = f"{item.path}:{item.line}" if item.line else item.path
                print(f"[{item.severity.upper()}] {item.rule_id} {location} - {item.message}")
        else:
            print("No findings.")
        print(f"Scanned {root}; findings: {len(findings)}")
    raise SystemExit(1 if findings else 0)

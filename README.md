# Secure Repo Audit

Secure Repo Audit is a small, offline-first security checker for source repositories. It helps engineers catch accidentally committed credentials and unsafe file permissions before code is shared.

## Checks

- `SRA001`: likely API keys, access tokens, passwords, or cloud credentials
- `SRA002`: private-key material
- `SRA003`: files writable by every local user on POSIX systems

The tool hides matched values in its output. It does not execute repository code, make network requests, alter files, or send findings anywhere.

## Usage

Requires Python 3.10 or newer.

```powershell
python -m secure_repo_audit .
python -m secure_repo_audit . --format json > security-findings.json
python -m secure_repo_audit . --format sarif > security-findings.sarif
```

Exit code `0` means no findings. Exit code `1` means at least one finding was detected.

## Secure development guidance

Use environment variables or a secret manager for credentials. If a real secret is found, revoke or rotate it first, remove it from the working tree and history, and review access logs. This scanner is a lightweight guardrail, not a replacement for code review, dependency scanning, or an enterprise secrets platform.

## Project information

- **Category:** defensive application security / developer tooling
- **Created:** 2026-10-02
- **Author:** Karthikeyan Subramaniyam
- **License:** MIT

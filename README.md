# Source Repository Secret & Supply Chain Auditor

<p align="center">
  <img src="https://img.shields.io/badge/Security-Defensive_Auditor-blue?style=flat" alt="Type">
  <img src="https://img.shields.io/badge/Status-Architectural_Showcase-success?style=flat" alt="Status">
  <img src="https://img.shields.io/badge/Python-3.10+-3776AB?style=flat&logo=python&logoColor=white" alt="Python">
</p>

> 🔒 **Technical Showcase & Architecture Specification**  
> *This repository provides public architectural documentation, system specifications, and implementation summaries. Full production source code, internal test suites, and proprietary algorithms are maintained in a secure private repository.*

---

## 📌 Executive Summary

**Category**: DevSecOps & Supply Chain Security  
**Tech Stack**: `Python 3.10+ · DevSecOps · Entropy Algorithms · CI/CD Supply Chain Security`  

Offline repository security auditor scanning source trees and CI/CD workflows for hardcoded credentials, secret leakage, and vulnerable dependencies.

---

## 🎯 The Problem It Solves

Accidental credential commits (API keys, cloud tokens, private keys) and vulnerable third-party dependencies are major vectors for supply chain compromises.

---

## ⚙️ How the Engine Works

1. **Repository File Tree Traversal**: Scans code repositories, configuration files, and environment templates.
2. **High-Entropy Secret Detection**: Utilizes Shannon entropy algorithms and regex patterns to detect high-entropy strings matching known credential formats (AWS keys, GitHub tokens, JWTs, private keys).
3. **CI/CD Workflow Trust Boundary Check**: Inspects GitHub Actions workflow YAML files for untrusted `pull_request_target` triggers, script injection vulnerabilities, and unpinned action SHA hashes.
4. **Configuration File Audit**: Validates that `.gitignore` properly excludes `.env`, `credentials`, `.pem`, and local virtual environments.
5. **Audit Summary**: Produces an executive security report detailing secret locations, severity levels, and automated remediation guidance.

---

## 🚀 Key Capabilities

- High-entropy secret and private key detection without network connectivity
- Audits GitHub Actions workflow files for supply-chain attack vectors
- Verifies proper repository hygiene and sensitive file exclusion
- Zero false-positive design optimized for fast local developer checks

---

## 🏗️ System Data Flow & Architecture

```
+-----------------------------------+
|  Target Input / Configuration    |
|  (JSON Snapshots / Policies)      |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  1. Schema Normalization Engine   |
|  Validates types & formats        |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  2. Core Analytical Pipeline      |
|  Heuristic rule evaluation,       |
|  invariant checks & drift diffs   |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  3. Risk Classification           |
|  Assigns severity: INFO / HIGH    |
+-----------------+-----------------+
                  |
                  v
+-----------------------------------+
|  4. Structured Findings & Report  |
|  Root cause, evidence &           |
|  actionable remediation steps     |
+-----------------------------------+
```

---

## 📄 Findings Output Structure

The engine generates structured, machine-parsable JSON reports adhering to this standard audit schema:

```json
{
  "results": [
    {
      "resource": "resource-identifier",
      "severity": "HIGH",
      "check": "CHECK_IDENTIFIER",
      "detail": "Descriptive analysis of the identified security posture issue.",
      "remediation": "Actionable step-by-step guidance to restore compliant state.",
      "evidence": {
        "observed_field": "value",
        "required_policy": "enforced_policy"
      }
    }
  ],
  "count": 1,
  "scope": "Comprehensive defensive security audit"
}
```

---

## 🔒 Source Code & Enterprise Inquiries

To protect proprietary intellectual property and client operational security:
* **Public Repository**: Contains comprehensive architecture specifications, schemas, and design overviews.
* **Private Repository**: Contains the complete production implementation, continuous integration pipelines, and full regression test suites.

For architectural questions or enterprise inquiries, connect via [LinkedIn](https://www.linkedin.com/in/karthikeyansubramaniam04/) or visit the [Portfolio Site](https://karthikeyansubramaniyam.github.io).

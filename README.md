<div align="center">

# ScopeForgeX

## Stage-Based Cybersecurity Workflow Automation Framework

**Evidence-driven workflow orchestration for authorized security assessments.**

[![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge&logo=python)](https://www.python.org/)
[![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge&logo=linux)](https://www.linux.org/)
[![Security](https://img.shields.io/badge/Domain-Offensive%20Security-red?style=for-the-badge)](#ethical-use)
[![Architecture](https://img.shields.io/badge/Architecture-Stage--Based-purple?style=for-the-badge)](#architecture)
[![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)](#license)

</div>

---

## Overview

ScopeForgeX is a **stage-based cybersecurity workflow orchestration framework** for authorized security assessments.

It coordinates security tools through a common execution and evidence pipeline instead of treating each tool as an isolated command.

The framework provides:

- Explicit scope and authorization handling
- Reconnaissance
- Enumeration
- Vulnerability assessment
- Conditional analyst-controlled validation capabilities
- Credential-assessment adapters that remain explicitly selectable
- Structured evidence collection
- Finding normalization
- Cross-tool deduplication and correlation
- Vulnerability intelligence
- Professional Markdown and HTML reporting
- Canonical machine-readable JSON reporting
- Runtime execution tracking
- Profile-based assessment configuration

ScopeForgeX is **not an automated penetration tester replacement**.

Its purpose is to reduce repetitive operational work while keeping security decisions, exploitation, credential attacks, and other higher-risk actions under analyst control.

---

## Why ScopeForgeX?

A typical assessment can require repeatedly:

1. Preparing tool-specific commands
2. Executing tools
3. Capturing stdout/stderr and artifacts
4. Parsing heterogeneous output
5. Normalizing observations
6. Deduplicating overlapping results
7. Correlating evidence
8. Preparing reports

ScopeForgeX provides a common workflow around those activities.

| Assessment Problem | ScopeForgeX Approach |
| --- | --- |
| Many independent security tools | Canonical ToolAdapter interface |
| Different command formats | Adapter-owned command construction |
| Heterogeneous output | Collector and observation layer |
| Duplicate findings | Assessment-wide normalization and correlation |
| Large raw tool output | Structured observations plus preserved raw artifacts |
| Inconsistent execution | Central ToolExecutor and RuntimeState |
| Manual report assembly | Automated Markdown, HTML and JSON reporting |
| Unsafe scope assumptions | Explicit authorization and target handling |

---

## Architecture

ScopeForgeX follows this pipeline:

```text
                         Authorized Target
                                |
                                v
                       Stage 0 — Scope
                                |
                                v
                    Tool Registry / Profiles
                                |
                                v
                         Tool Adapter
                                |
                                v
                         Tool Executor
                                |
                                v
                       ExecutionResult
                                |
                                v
                         Raw Evidence
                                |
                                v
                           Collector
                                |
                                v
                  Structured Observations
                                |
                                v
                  Finding Normalization
                                |
                                v
                    Finding Correlation
                    / Deduplication
                                |
                                v
                  Vulnerability Intelligence
                                |
                                v
                       Reporting Engine
                         /           \
                        v             v
                 Human Reports    Canonical JSON
```

### Execution contract

Tool adapters own tool-specific behavior:

- Command construction
- Option validation
- Target normalization
- Tool-specific execution when required

The shared execution layer handles:

- Execution context
- Timeouts
- Process execution
- Runtime status
- stdout/stderr preservation
- Artifact registration
- Collector invocation
- Runtime state

The framework does not perform a second subprocess execution merely to collect or analyze output.

---

## Workflow Pipeline

```text
STAGE 0
Scope & Authorization
        |
        v
STAGE 1
Reconnaissance
        |
        v
STAGE 2
Enumeration
        |
        v
STAGE 3
Vulnerability Assessment
        |
        v
STAGE 4
Validation
        |
        v
STAGE 5
Credential Assessment
        |
        v
STAGE 6
Reporting & Cleanup
```

### Stage responsibilities

| Stage | Responsibility |
| --- | --- |
| Stage 0 | Authorization and scope validation |
| Stage 1 | Network and web reconnaissance |
| Stage 2 | Web, API and technology enumeration |
| Stage 3 | Vulnerability assessment and evidence collection |
| Stage 4 | Conditional analyst-controlled validation |
| Stage 5 | Explicit credential-assessment capabilities |
| Stage 6 | Finding/report generation and cleanup |

Stage availability is profile- and target-dependent. A tool may be intentionally skipped when its input type does not apply to the supplied target.

---

## Execution Profiles

ScopeForgeX currently provides three active profiles:

### FAST

Designed for a smaller, faster assessment.

The profile focuses on a limited set of high-value reconnaissance, HTTP enumeration and vulnerability-assessment capabilities.

### STANDARD

The default professional assessment profile.

It provides:

- Network reconnaissance
- DNS reconnaissance
- Subdomain/virtual-host discovery
- HTTP service enumeration
- Web crawling
- JavaScript attack-surface analysis
- Content discovery
- Technology fingerprinting
- API route discovery
- Web vulnerability assessment
- Web-server security assessment
- TLS assessment when applicable

### FULL

The broadest configured profile.

It extends STANDARD with:

- More aggressive reconnaissance configuration
- Deeper web enumeration
- Broader vulnerability assessment
- Conditional SQL injection validation
- Conditional XSS validation
- Conditional JWT validation
- Conditional SSTI validation

Credential-assessment adapters remain explicitly opt-in even under FULL.

---

## Supported Tools

ScopeForgeX's canonical installed tool set contains **19 tools**.

### Reconnaissance

| Tool | Capability |
| --- | --- |
| Amass | Attack-surface and domain reconnaissance |
| Subhunt | Subdomain and HTTP virtual-host enumeration |
| Nmap | Network service discovery |
| Dig | DNS reconnaissance |

### Enumeration

| Tool | Capability |
| --- | --- |
| httpx | HTTP service enumeration |
| Katana | Web crawling |
| Jsluice | JavaScript attack-surface analysis |
| FFUF | Content discovery |
| WhatWeb | Technology fingerprinting |
| Kiterunner | API route discovery |

### Vulnerability Assessment

| Tool | Capability |
| --- | --- |
| Wapiti | Web application vulnerability assessment |
| Nikto | Web-server security assessment |
| testssl.sh | TLS security assessment |

### Conditional Validation

| Tool | Capability |
| --- | --- |
| SQLMap | SQL injection validation |
| Dalfox | XSS validation |
| jwt_tool | JWT security validation |
| SSTImap | Server-side template injection validation |

### Credential Assessment

| Tool | Capability |
| --- | --- |
| Hydra | Authorized authentication testing |
| Hashcat | Password recovery / analysis |

Higher-risk validation and credential capabilities are not automatically executed simply because their adapters exist.

---

## Target-Aware Execution

ScopeForgeX does not blindly execute every configured tool against every target.

For example, Amass requires a domain-oriented target. A target such as:

```text
http://localhost:3000
```

is not an applicable Amass domain target, so Amass is **skipped rather than reported as a tool failure**.

Likewise, `testssl.sh` is not applicable to an ordinary HTTP target without TLS.

This distinction allows reports to differentiate between:

```text
SUCCESS
SKIPPED
FAILED
```

instead of treating every non-execution as a failure.

---

## Subhunt Integration

Subhunt is integrated as a focused reconnaissance component.

It supports:

- DNS subdomain enumeration
- HTTP virtual-host enumeration
- DNS-over-HTTPS resolver failover
- Wildcard-aware DNS handling
- HTTP baseline fingerprinting
- Catch-all filtering
- Evidence-rich HTTP findings
- Quiet output
- JSON output
- Deterministic result handling

For an HTTP target, ScopeForgeX uses Subhunt's HTTP mode:

```bash
subhunt -u http://target.example \
  --bruteforce /path/to/wordlist.txt \
  --threads 50
```

For a domain target, ScopeForgeX uses DNS enumeration:

```bash
subhunt -d example.com \
  --bruteforce /path/to/wordlist.txt
```

A completed Subhunt scan with zero findings is normalized as a successful completion rather than incorrectly being treated as a failed assessment.

---

## Wapiti Vulnerability Assessment

Wapiti is the current web-application vulnerability assessment engine.

The STANDARD profile uses bounded scanning parameters to control assessment scope and runtime.

Example:

```text
wapiti
  -u <target>
  --scope domain
  --max-links-per-page 100
  --max-files-per-dir 50
  --max-scan-time 540
  --max-attack-time 480
  --max-parameters 50
  -t 10
  -f json
```

Wapiti's raw JSON output is retained as an assessment artifact and processed through the ScopeForgeX collection and normalization pipeline.

---

## Evidence Pipeline

ScopeForgeX separates raw execution evidence from structured security intelligence.

```text
Tool Execution
      |
      v
ExecutionResult
      |
      v
Raw Artifact
      |
      v
Collector
      |
      v
CollectorObservation
      |
      v
Finding Normalization
      |
      v
Correlation / Deduplication
      |
      v
Report
```

Structured observations can contain information such as:

- Observation type
- Title
- Description
- Impact
- Remediation
- Severity
- Confidence
- Status
- Target
- Host
- Port
- URL
- Parameter
- Evidence references
- Source tool
- Detection method
- CWE
- CVE
- References
- Metadata

---

## Evidence Safety

Raw tool output is preserved internally where required for investigation and reproducibility.

Published vulnerability intelligence is sanitized so that raw HTTP payload fields such as:

```text
body
raw_body
raw_header
raw_headers
request
raw_request
response
raw_response
```

are not propagated into published findings and reports.

The current Juice Shop validation run produced:

```text
Forbidden raw HTTP evidence keys: 0
PASS: published report contains zero forbidden raw HTTP evidence keys
```

This keeps the reporting layer focused on structured security evidence rather than unintentionally publishing complete HTTP payloads.

---

## Vulnerability Intelligence

ScopeForgeX includes a vulnerability-intelligence layer that combines observations from multiple sources.

The analysis pipeline supports:

- Finding normalization
- Confidence handling
- Risk classification
- Deduplication
- Cross-tool correlation
- Software identity
- CVE association
- Evidence references

CVE-bearing findings remain represented in the CVE summary regardless of finding severity.

---

## Reporting Engine

Stage 6 produces professional and machine-readable assessment output.

A completed assessment can contain:

```text
outputs/
└── <target>/
    └── <run-id>/
        ├── recon/
        ├── enum/
        ├── vuln/
        ├── findings/
        ├── correlated/
        └── report/
            ├── professional.md
            ├── professional.html
            ├── findings.md
            ├── findings.html
            └── report.json
```

### Report types

**Professional report**

Designed for human review and assessment communication.

**Findings report**

Focused on normalized security findings.

**Canonical JSON**

Machine-readable representation of the assessment and findings.

---

## Example Execution

ScopeForgeX supports explicit non-interactive execution:

```bash
python3 -m scopeforgex \
  --profile standard \
  --target https://example.com \
  --authorized
```

The `--authorized` flag is required for explicit target execution.

The CLI therefore makes authorization an explicit part of the execution request.

---

## Local Juice Shop Example

An authorized local OWASP Juice Shop assessment was executed against:

```text
http://localhost:3000
```

The target returned:

```text
HTTP 200
```

Using the STANDARD profile, 13 tools were selected:

```text
11 SUCCESS
 2 SKIPPED
 0 FAILED
```

The intentionally skipped tools were:

```text
amass
testssl.sh
```

Amass was skipped because `localhost` is not an applicable domain target.

`testssl.sh` was skipped because the target was HTTP rather than HTTPS.

The assessment generated:

```text
professional.md
professional.html
findings.md
findings.html
report.json
```

### Assessment screenshots

The following five screenshots are the documentation roles for the current
authorized local OWASP Juice Shop assessment:

| File | Documentation role |
|---|---|
| `docs/screenshots/dashboard.png` | Workflow overview |
| `docs/screenshots/recon-stage.png` | Reconnaissance execution/results |
| `docs/screenshots/vulnerability-stage.png` | Vulnerability assessment |
| `docs/screenshots/report-summary.png` | Professional report summary |
| `docs/screenshots/report-json.png` | Machine-readable JSON findings |

> **Documentation integrity:** These images should be replaced with fresh
> screenshots captured from the validated local Juice Shop run before the
> README is treated as final repository documentation. Older screenshots
> should not be presented as current assessment evidence.

---

## Benchmark

ScopeForgeX was benchmarked against an independent Python orchestration baseline using the same STANDARD assessment configuration and target.

Reference target:

```text
https://warrantyindia.com/
```

Reference ScopeForgeX run:

```text
1060.648756 seconds
```

Independent baseline:

```text
4 valid runs
Mean: 1025.266754 seconds
Minimum: 984.830250 seconds
Maximum: 1060.844716 seconds
```

The measured relative overhead of the ScopeForgeX orchestration layer was approximately:

```text
3.45%
```

The benchmark is intended to quantify orchestration overhead rather than claim that ScopeForgeX is inherently faster than manually executing individual tools.

---

## Installation

### Requirements

- Linux
- Python 3.10+
- Git
- Go
- Rust/Cargo
- Required security tooling or the ScopeForgeX installer

### Clone

```bash
git clone https://github.com/VikashChoudhary-04/ScopeForgeX.git
cd ScopeForgeX
```

### Python environment

```bash
python3 -m venv .venv
source .venv/bin/activate
```

### Install Python dependencies

```bash
pip install -r requirements.txt
```

### Tool installation

ScopeForgeX includes an installer for its supported security-tool dependencies.

Run:

```bash
python3 -c 'from scopeforgex.installer import install_tools; install_tools()'
```

The installer handles the configured toolchain and its required package/source installation paths.

After installation, verify the required executables before running an assessment.

---

## Usage

### Standard assessment

```bash
python3 -m scopeforgex \
  --profile standard \
  --target https://example.com \
  --authorized
```

### FAST

```bash
python3 -m scopeforgex \
  --profile fast \
  --target https://example.com \
  --authorized
```

### FULL

```bash
python3 -m scopeforgex \
  --profile full \
  --target https://example.com \
  --authorized
```

### Interactive dashboard

Running the module without an explicit target launches the dashboard:

```bash
python3 -m scopeforgex
```

---

## Runtime and Timeouts

Tool execution is centralized through the ScopeForgeX runtime.

Timeout configuration flows from:

```text
Profile configuration
        |
        v
WorkflowEngine
        |
        v
ToolExecutor
        |
        v
ToolContext
        |
        v
ToolAdapter / run_command
```

Explicit tool timeout configuration can override profile/default execution settings where supported.

This keeps timeout behavior consistent across adapters without duplicating process-management logic inside every tool.

---

## Security Model

ScopeForgeX intentionally separates automated assessment from higher-risk security actions.

### Automatically orchestrated

- Scope validation
- Reconnaissance
- Enumeration
- Vulnerability assessment
- Evidence collection
- Finding normalization
- Correlation
- Reporting

### Analyst-controlled

- Exploitation
- SQL injection validation
- XSS validation
- JWT validation
- SSTI validation
- Credential attacks
- Password recovery
- Post-exploitation activity

A prepared command or tool result is not treated as proof of successful compromise.

---

## Authorization

ScopeForgeX is designed for authorized security assessments.

Only use the framework against:

- Systems you own
- Systems for which you have explicit authorization
- Security laboratories
- CTF environments
- Other explicitly permitted assessment targets

Do not use ScopeForgeX to access or test systems without authorization.

---

## Testing

The project maintains automated regression coverage for its core execution, workflow, collector, reporting and integration contracts.

The latest validated regression state during this documentation update:

```text
267 passed
```

Additional validation performed against the local Juice Shop assessment included:

```text
HTTP target: 200
Tool failures: 0
Published forbidden HTTP evidence keys: 0
Reports generated: yes
```

---

## Repository Structure

```text
ScopeForgeX/
├── scopeforgex/
│   ├── collectors/
│   ├── config/
│   ├── models/
│   ├── registry/
│   ├── runtime/
│   ├── tools/
│   ├── workflow.py
│   ├── cli.py
│   └── ...
├── tests/
├── docs/
│   └── screenshots/
├── outputs/
├── requirements.txt
├── README.md
└── ...
```

The canonical architecture is centered on:

```text
ToolAdapter
    ↓
ExecutionResult
    ↓
Collector
    ↓
CollectorObservation
    ↓
Finding
    ↓
Correlation / Deduplication
    ↓
Reporting
```

---

## Engineering Highlights

ScopeForgeX demonstrates:

- Python application architecture
- CLI application development
- Security-tool orchestration
- Adapter-based tool integration
- Profile-driven execution
- Target-aware conditional execution
- Centralized process execution
- Structured evidence collection
- Finding normalization
- Cross-tool correlation
- Runtime state management
- Vulnerability intelligence
- Evidence-safe reporting
- Machine-readable security output
- Automated regression testing

---

## Current Limitations

ScopeForgeX intentionally does not:

- Automatically claim successful exploitation
- Replace manual security validation
- Replace professional penetration testing
- Treat scanner output as unquestionable truth
- Automatically enable credential attacks in the default assessment pipeline

Automated findings require analyst review and validation.

---

## Future Roadmap

Potential areas for future development include:

- Additional assessment integrations
- Expanded evidence normalization
- Additional report formats
- Richer assessment dashboards
- More validation adapters
- Additional correlation rules
- Expanded automated regression coverage
- Further benchmark coverage

---

## License

MIT License.

---

<div align="center">

## ScopeForgeX

**Structured security assessment orchestration with evidence-driven reporting.**

</div>

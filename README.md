<div align="center">

# ScopeForgeX

## Stage-Based Cybersecurity Workflow Automation Framework

**Transforming penetration testing activities into a structured, repeatable, and report-driven security assessment workflow.**

<br>

![Python](https://img.shields.io/badge/Python-3.10%2B-blue?style=for-the-badge\&logo=python)
![Platform](https://img.shields.io/badge/Platform-Linux-orange?style=for-the-badge\&logo=linux)
![Security](https://img.shields.io/badge/Domain-Offensive%20Security-red?style=for-the-badge)
![Architecture](https://img.shields.io/badge/Architecture-Stage--Based-purple?style=for-the-badge)
![License](https://img.shields.io/badge/License-MIT-green?style=for-the-badge)

</div>

---

## Overview

- ScopeForgeX is a **stage-driven cybersecurity workflow automation framework** designed to organize penetration testing activities into a controlled, repeatable assessment pipeline.

- Instead of manually running individual security tools and collecting scattered outputs, ScopeForgeX provides a unified workflow engine that manages:

  * Scope validation
  * Reconnaissance
  * Enumeration
  * Vulnerability identification
  * Analyst-assisted validation preparation
  * Artifact collection
  * Automated reporting

- The goal is not to replace penetration testers.

- The goal is to **reduce repetitive operational work and provide a structured assessment workflow while keeping security decisions under analyst control.**

---

## Why ScopeForgeX?

- Traditional penetration testing workflows often involve:

| Traditional Workflow         | ScopeForgeX Approach            |
| ---------------------------- | ------------------------------- |
| Manually execute many tools  | Stage-based automation          |
| Scattered output files       | Centralized artifact management |
| Inconsistent assessment flow | Repeatable workflow pipeline    |
| Manual report preparation    | Automated reporting             |
| No execution history         | Runtime tracking and metadata   |

- ScopeForgeX brings software engineering principles into offensive security workflows:

  * Modularity
  * Separation of responsibilities
  * Repeatability
  * Structured results
  * Automation safety

---

## Architecture

```text
                         User

                          |
                          v

                  CLI Dashboard

                          |
                          v

                 Workflow Engine

                          |
        +-----------------+-----------------+

        |                 |                 |

     Recon            Enumeration       Validation

        |                 |                 |

        +-----------------+-----------------+

                          |

                          v

              Vulnerability Intelligence

                          |

                          v

                Reporting Engine

                          |

             +------------+------------+

             |                         |

        Markdown Report          JSON Report
```

---

## Workflow Pipeline

- ScopeForgeX follows a professional assessment structure:

```text
STAGE 0
Scope Validation
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
Exploitation Preparation
        |
        v
STAGE 5
Post Assessment Preparation
        |
        v
STAGE 6
Reporting
```

---

## Features

### Stage-Based Execution

- Each security activity is isolated into independent stages:

| Stage   | Function                             |
| ------- | ------------------------------------ |
| Stage 0 | Authorization and scope validation   |
| Stage 1 | Attack surface discovery             |
| Stage 2 | Technology and service enumeration   |
| Stage 3 | Vulnerability identification         |
| Stage 4 | Analyst-assisted exploit preparation |
| Stage 5 | Post-assessment preparation          |
| Stage 6 | Automated reporting                  |

---

## Execution Profiles

### FAST Profile

- Designed for quick assessments.

- Workflow:

  ```text
  Scope
   |
  Recon
   |
  Vulnerability Assessment
   |
  Reporting
  ```

- Suitable for:

  * Initial reconnaissance
  * Bug bounty preparation
  * Rapid attack surface analysis

---

### FULL_SAFE Profile

- Designed for broader assessments.

- Workflow:

  ```text
  Scope
   |
  Recon
   |
  Enumeration
   |
  Vulnerability Assessment
   |
  Exploit Preparation
   |
  Post Assessment Preparation
   |  
  Reporting
  ```

- Higher-risk activities are prepared for manual review.

---

## Security Model

- ScopeForgeX follows a controlled automation approach.

### Automatically Executed

* Scope processing
* Recon workflows
* Enumeration
* Vulnerability scanning
* Artifact collection
* Report generation

### Analyst-Controlled

* Exploitation
* Credential attacks
* Payload generation
* Pivoting
* Post-exploitation actions

Prepared commands are generated for review.

They do not represent successful exploitation.

---

## Supported Integrations

### Reconnaissance

| Tool    | Purpose                     |
| ------- | --------------------------- |
| Subhunt | Subdomain discovery         |
| httpx   | Host validation             |
| Katana  | Optional endpoint discovery |

---

### Enumeration

| Tool          | Purpose                   |
| ------------- | ------------------------- |
| WhatWeb       | Technology fingerprinting |
| wafw00f       | WAF detection             |
| FFUF          | Content discovery         |
| enum4linux-ng | SMB enumeration           |
| snmpwalk      | SNMP enumeration          |

---

### Vulnerability Identification

| Tool   | Purpose                                     |
| ------ | ------------------------------------------- |
| Nuclei | Template-based vulnerability identification |

- Nuclei results are processed into:

  * JSONL vulnerability data
  * Finding summaries
  * Severity statistics
  * Reporting artifacts

---

## Analyst-Assisted Preparation

- ScopeForgeX prepares analyst-reviewed workflows for:

| Tool         | Purpose                           |
| ------------ | --------------------------------- |
| SQLMap       | SQL injection testing preparation |
| Dalfox       | XSS testing preparation           |
| XSStrike     | XSS testing preparation           |
| SSTImap      | SSTI testing preparation          |
| SearchSploit | Exploit research preparation      |
| Chisel       | Tunneling preparation             |
| Hydra        | Credential testing preparation    |
| John         | Password analysis preparation     |
| Hashcat      | Password recovery preparation     |
| Medusa       | Credential testing preparation    |

---

## Reporting Engine

- ScopeForgeX automatically generates professional assessment reports.

- Generated outputs:

```text
report.md
report.json
```

- Reports contain:

  * Assessment information
  * Workflow execution summary
  * Stage results
  * Tool results
  * Vulnerability summaries
  * Severity overview
  * Generated artifacts
  * Analyst guidance

- Example:

  ```text
  outputs/

  └── target/

      ├── recon/

      ├── enum/

      ├── vuln/

      ├── exploit/

      ├── post/

      ├── report.md

      └── report.json
  ```

---

## Example Execution

```text
$ python3 scopeforgex.py


╭──────────────────────────╮
│ ScopeForgeX Dashboard    │
╰──────────────────────────╯


STAGE 0 — SCOPE

STAGE 1 — RECON

STAGE 3 — VULNERABILITY ASSESSMENT

STAGE 6 — REPORTING


[✔] Workflow completed successfully
```

---

## Installation

### Requirements

* Python 3.10+
* Linux environment
* Security tools required by selected workflow

---

### Clone Repository

```bash
git clone https://github.com/VikashChoudhary-04/ScopeForgeX.git

cd ScopeForgeX
```

---

### Create Environment

```bash
python3 -m venv .venv

source .venv/bin/activate
```

---

### Install Dependencies

```bash
pip install -r requirements.txt
```

---

## Usage

- Start ScopeForgeX:

  ```bash
  python3 scopeforgex.py
  ```

- Select:

  ```text
  1. Run FAST Profile
  2. Run FULL_SAFE Profile
  3. Install Tools
  4. View Last Run
  5. Exit
  ```

---

## Repository Structure

```text
ScopeForgeX/

├── config/
│
├── scopeforgex/
│   ├── stages/
│   ├── tools/
│   ├── registry/
│   ├── workflow.py
│   └── cli.py
│
├── reporting/
│   ├── models.py
│   ├── report_generator.py
│   ├── json_exporter.py
│   └── parsers/
│
├── outputs/
│
├── requirements.txt
│
├── scopeforgex.py
│
└── README.md
```

---

## Engineering Highlights

- ScopeForgeX demonstrates:

  * Python software architecture
  * CLI application development
  * Offensive security workflow design
  * Security tool orchestration
  * Modular stage systems
  * Runtime state management
  * Automated report generation
  * Machine-readable security output

---

## Current Limitations

- ScopeForgeX intentionally does not:

  * Automatically exploit vulnerabilities
  * Claim compromise of systems
  * Replace professional penetration testing
  * Replace manual validation

- Automated results require analyst review.

---

## Future Roadmap

- Potential improvements:

  * CVSS scoring automation
  * Evidence management
  * Advanced report templates
  * Plugin-based architecture
  * Additional export formats
  * Workflow checkpoints
  * Dashboard analytics

---

## Ethical Use

- ScopeForgeX must only be used against:

  * Systems you own
  * Authorized penetration testing targets
  * Security laboratories
  * CTF environments

- Always obtain proper authorization before security testing.

---

## License

- MIT License

---

<div align="center">

## ScopeForgeX

**A modular cybersecurity workflow automation framework built for structured security assessments.**

</div>

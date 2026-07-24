# ScopeForgeX

ScopeForgeX is a modular cybersecurity workflow orchestrator designed to organize reconnaissance, enumeration, vulnerability identification, and analyst-assisted security testing into a structured assessment workflow.

Rather than treating security tools as isolated commands, ScopeForgeX provides a stage-based framework for executing supported integrations, organizing per-target output, passing normalized data between connected stages where implemented, preparing higher-risk commands for explicit human review, and generating a Markdown assessment summary from available workflow artifacts.

The project is designed around a safety-conscious execution model:

- Lower-risk discovery and identification tasks may be automated where explicitly implemented.
- Higher-risk exploitation, credential, tunneling, and post-exploitation actions are prepared for analyst review rather than automatically executed.
- Tool execution is organized by workflow stage and target type.
- Generated artifacts are stored in structured per-target output directories.
- Basic metadata from the most recent completed workflow is persisted for later review from the dashboard.

> ScopeForgeX is intended only for authorized security testing, controlled lab environments, CTFs, and systems for which you have explicit permission to assess.

---

## Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Safety-First Execution Model](#safety-first-execution-model)
- [Supported Tool Integrations](#supported-tool-integrations)
- [Configured Tool Catalog](#configured-tool-catalog)
- [Dependencies](#dependencies)
- [Profiles](#profiles)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [Reporting](#reporting)
- [Current Implementation Boundaries](#current-implementation-boundaries)
- [ScopeForgeX vs Subhunt](#scopeforgex-vs-subhunt)
- [Legal and Ethical Use](#legal-and-ethical-use)
- [License](#license)

---

## Key Features

- **Stage-based workflow orchestration**
  * Organizes assessment activity into scope, reconnaissance, enumeration, vulnerability identification, exploitation preparation, post-exploitation preparation, and reporting stages.

- **Web and network target handling**
  * Stage 0 classifies supported input as either a web/domain target or a network target.
  * Target type is used to control applicable workflow behavior where routing has been implemented.

- **Interactive terminal dashboard**
  * Run the FAST profile.
  * Run the FULL_SAFE profile.
  * Install supported external tools.
  * View metadata from the most recent saved run.

- **Connected FAST reconnaissance pipeline**
  * Uses Subhunt for discovery.
  * Normalizes discovered hosts.
  * Uses `httpx` for live-host validation.
  * Optionally uses Katana for endpoint discovery when available.
  * Passes normalized host and URL artifacts into Nuclei.

- **Target-aware Stage 2 enumeration**
  * Web targets use registered web enumeration integrations.
  * Network targets use registered network enumeration integrations.

- **Safety-oriented command preparation**
  * Higher-risk tools are represented through prepared commands requiring explicit analyst review rather than automatic execution.

- **Structured output**
  * Creates per-target directories for reconnaissance, enumeration, vulnerability results, exploitation preparation, post-exploitation preparation, logs, and reporting.

- **Markdown reporting**
  * Generates `report.md` from available workflow metadata and artifacts.
  * Includes available Nuclei host and URL scan logs where present.

- **Last-run metadata persistence**
  * Persists basic metadata for the most recent run, allowing users to review the previous target and output directory from the dashboard.

- **Profile-driven execution**
  * Provides `fast` and `full_safe` workflow profiles.

---

## Architecture

ScopeForgeX separates workflow orchestration from individual tool integrations.

A simplified architecture is:

```text
User
  |
  v
CLI / Interactive Dashboard
  |
  v
Profile Selection
  |
  v
Stage 0 - Scope and Target Classification
  |
  +-----------------------------+
  |                             |
  v                             v
Web / Domain Target         Network Target
  |                             |
  v                             v
Stage-Based Tool Selection and Execution
  |
  v
Structured Per-Target Artifacts
  |
  v
Reporting / Last-Run Metadata
```

The workflow is organized into the following stages:

```text
Stage 0 - Scope
Stage 1 - Reconnaissance
Stage 2 - Enumeration
Stage 3 - Vulnerability Identification
Stage 4 - Exploitation Preparation
Stage 5 - Post-Exploitation / Credential Preparation
Stage 6 - Reporting
```

Not every configured tool participates in every profile or target type.

The actual execution path depends on:

- Selected profile.
- Target type.
- Registered workflow integrations.
- Installed external tools.
- Availability of upstream artifacts.
- Safety restrictions implemented by each stage.

### Core Components

- **`scopeforgex.py`**
  * Top-level application entry point.

- **`scopeforgex/cli.py`**
  * Handles command-line interaction and workflow entry behavior.

- **`scopeforgex/dashboard.py`**
  * Provides the interactive terminal dashboard.
  * Supports profile execution, tool installation, and viewing metadata from the most recent saved run.

- **`scopeforgex/workflow.py`**
  * Loads the selected profile.
  * Executes enabled stages in sequence.
  * Passes shared workflow context between stages.
  * Saves basic last-run metadata after workflow completion.

- **`scopeforgex/runner.py`**
  * Provides command execution support used by tool integrations.

- **`scopeforgex/state.py`**
  * Persists basic metadata from the most recent run.
  * Stores information such as:
    * Target type.
    * Target.
    * Output directory.
  * This state is currently used for review through **View Last Run**.
  * It is not a stage-checkpoint or interrupted-workflow resume engine.

- **`scopeforgex/merger.py`**
  * Provides reusable line-reading and target-merging helpers.
  * The module exists as a utility component but is not currently wired into the primary workflow dispatch.

- **`scopeforgex/toolcheck.py`**
  * Supports external-tool availability checks.

- **`scopeforgex/installer.py`**
  * Provides installation logic for a subset of external dependencies.
  * Installer coverage is not identical to the complete configured tool catalog.

- **`scopeforgex/wordlists.py`**
  * Supports wordlist-related workflow behavior.

- **`scopeforgex/registry/`**
  * Defines tool abstractions, registration, and grouping behavior used by the workflow.

- **`scopeforgex/stages/`**
  * Contains stage-level orchestration.

- **`scopeforgex/tools/`**
  * Contains concrete tool integrations and command-preparation integrations.

- **`reporting/`**
  * Contains reporting-related code outside the main `scopeforgex` package.

### How ScopeForgeX Works

At a high level:

1. The user launches ScopeForgeX.
2. A workflow profile is selected.
3. Stage 0 collects and classifies the target.
4. A shared workflow context is created.
5. Enabled stages are executed in profile order.
6. Registered tools are selected for each stage.
7. Target-type filtering is applied where implemented.
8. Automatically supported tools execute through the workflow.
9. Connected stages consume generated artifacts where explicitly implemented.
10. Higher-risk operations are prepared as commands for analyst review.
11. Stage 6 creates a Markdown report from available workflow information and artifacts.
12. Basic metadata from the completed run is saved for later dashboard review.

ScopeForgeX should therefore be understood as a **workflow orchestrator with selectively connected automation**, not as a claim that every configured security tool forms one fully automated end-to-end pipeline.

### Connected FAST Pipeline

The FAST profile contains the clearest implemented cross-tool data flow.

For supported web/domain targets, the intended flow is:

```text
Target
  |
  v
Subhunt
  |
  v
subhunt.txt
  |
  v
Host normalization
  |
  v
hosts_raw.txt
  |
  v
httpx
  |
  v
hosts_alive.txt
  |
  v
hosts_final.txt
  |
  +-----------------------------+
  |                             |
  v                             v
Optional Katana             Nuclei host scan
  |                             |
  v                             v
katana.txt                  nuclei_hosts.txt
  |
  v
URL normalization
  |
  v
urls_raw.txt
  |
  v
urls_final.txt
  |
  v
Nuclei URL scan
  |
  v
nuclei_urls.txt
```

The exact artifacts created depend on execution results and installed tools.

Katana is optional in this flow. If it is available, endpoint discovery can contribute normalized URL targets for downstream Nuclei scanning.

This connected pipeline demonstrates the architectural direction of ScopeForgeX: produce structured artifacts that supported downstream stages can consume rather than treating every command as an isolated terminal action.

Not every current integration is connected this deeply.

---

## Safety-First Execution Model

ScopeForgeX distinguishes between operations that can be automated with relatively lower operational risk and operations that should remain under explicit analyst control.

This distinction is architectural rather than merely descriptive.

### Safe Auto-Run

Automatically executed integrations currently include selected reconnaissance, enumeration, and vulnerability-identification operations.

Depending on profile, target type, installed dependencies, and available inputs, registered integrations include:

- Subhunt
- `httpx` as part of the connected FAST pipeline
- Katana as an optional component of the connected FAST pipeline
- Naabu
- RustScan
- Nmap
- WhatWeb
- wafw00f
- ffuf
- enum4linux-ng
- snmpwalk
- Nuclei

Automatic execution does not imply that every tool above runs for every target.

Execution depends on workflow routing and profile selection.

### Prepared Commands + Human Review

Higher-risk tools are handled differently.

ScopeForgeX includes integrations that prepare commands for analyst review rather than automatically carrying out potentially intrusive exploitation or post-exploitation activity.

These integrations include tools such as:

- sqlmap
- Dalfox
- XSStrike
- SSTImap
- SearchSploit
- msfvenom
- Netcat
- Chisel
- SSH
- Hydra
- Medusa
- Hashcat
- John the Ripper

The purpose of this model is to preserve analyst control over actions that may:

- Modify target state.
- Trigger authentication attempts.
- Perform exploitation.
- Establish shells or tunnels.
- Conduct credential attacks.
- Create payloads.
- Increase operational impact.

A generated or prepared command is not evidence that the command was executed or that exploitation succeeded.

---

## Supported Tool Integrations

This section describes tools that are represented by current registered workflow integrations or directly participate in implemented workflow behavior.

It intentionally distinguishes **implemented workflow integrations** from tools that merely appear in configuration.

### Automatically Executed CLI Tools

#### Reconnaissance

- **Subhunt**
  * Registered Stage 1 web reconnaissance integration.
  * Used directly by the FAST workflow.
  * Produces discovery artifacts consumed by the connected reconnaissance pipeline.

- **httpx**
  * Used inside the connected FAST pipeline for live-host validation.
  * Converts normalized discovered hosts into validated live-host artifacts.

- **Katana**
  * Used optionally inside the connected FAST pipeline.
  * Performs endpoint discovery when installed.
  * Discovered URLs can be normalized for downstream vulnerability identification.

- **Naabu**
  * Registered network reconnaissance integration.

- **RustScan**
  * Registered network reconnaissance integration.

- **Nmap**
  * Registered network reconnaissance integration.

#### Enumeration

For web targets, Stage 2 routes execution to registered web enumeration tools:

- **WhatWeb**
- **wafw00f**
- **ffuf**

For network targets, Stage 2 routes execution to registered network enumeration tools:

- **enum4linux-ng**
- **snmpwalk**

This routing prevents the Stage 2 workflow from treating web and network enumeration as interchangeable operations.

#### Vulnerability Identification

- **Nuclei**
  * Registered Stage 3 integration.
  * In the connected FAST workflow, consumes normalized host and URL target files when available.
  * Produces separate host and URL output/log artifacts.

### Assisted Command Tools

The following integrations prepare commands for explicit analyst review.

#### Exploitation / Validation

- **sqlmap**
- **Dalfox**
- **XSStrike**
- **SSTImap**
- **SearchSploit**
- **msfvenom**
- **Netcat**

#### Credential / Tunneling / Post-Exploitation

- **Chisel**
- **SSH**
- **Hydra**
- **Medusa**
- **Hashcat**
- **John the Ripper**

These integrations should not be interpreted as evidence of automatic exploitation.

Their role is to help structure analyst-controlled follow-on activity.

---

## Configured Tool Catalog

`config/tools.yaml` contains a broader catalog than the set of tools currently registered for workflow execution.

Configured entries include:

```text
chisel
dalfox
dig
dnsenum
dnsrecon
enum4linuxng
feroxbuster
ffuf
gau
gobuster
hashcat
httpx
hydra
john
katana
knockpy
lbd
medusa
msfvenom
naabu
nbtstat
netcat
nikto
nmap
nuclei
onesixtyone
rustscan
searchsploit
smbclient
smbmap
snmpcheck
snmpwalk
sqlmap
ssh
sstimap
subhunt
sublist3r
wafw00f
whatweb
wpscan
xsstrike
```

A configured tool is **not automatically equivalent to an active workflow integration**.

At the time of this documentation, the following configured tools are not represented as matching registered workflow integrations:

```text
dig
dnsenum
dnsrecon
feroxbuster
gau
gobuster
knockpy
lbd
nbtstat
nikto
onesixtyone
smbclient
smbmap
snmpcheck
sublist3r
wpscan
```

`httpx` and Katana are important exceptions to a simple registry-only interpretation: they participate directly inside the connected FAST pipeline even though they are not exposed as standalone registered tool classes in the same way as several other integrations.

This distinction is important when evaluating project capabilities:

```text
Configured
    !=
Automatically registered
    !=
Automatically executed in every profile
```

---

## Dependencies

ScopeForgeX combines Python dependencies with external security CLI tools.

The exact external dependencies required depend on the workflow profile and target being assessed.

### Python Dependencies

Install the Python requirements with:

```bash
pip install -r requirements.txt
```

The project uses Python packages for functionality including:

- Interactive terminal prompts.
- Terminal formatting and progress display.
- YAML configuration handling.

Use the repository's `requirements.txt` as the authoritative Python dependency list.

### External CLI Tools

Core external tools used by implemented automated workflow paths include:

```text
subhunt
httpx
katana
naabu
rustscan
nmap
whatweb
wafw00f
ffuf
enum4linux-ng
snmpwalk
nuclei
```

Not all are required for every run.

For example:

- Web and network targets use different tool paths.
- Katana is optional in the FAST pipeline.
- Missing tools may cause a specific integration to skip or return an unavailable-tool result rather than making every workflow identical.

### Assisted Command Dependencies

Analyst-assisted command generation references tools including:

```text
sqlmap
dalfox
xsstrike
sstimap
searchsploit
msfvenom
netcat
chisel
ssh
hydra
medusa
hashcat
john
```

If an analyst chooses to execute a prepared command, the corresponding external tool must be installed separately.

### Installer Coverage

ScopeForgeX includes an installer module, but the installer does **not** currently provide complete installation coverage for every configured or registered tool.

The installer currently references a subset including tools such as:

```text
sublist3r
dnsrecon
httpx
gau
katana
subhunt
nmap
whatweb
wafw00f
ffuf
nuclei
nikto
wpscan
sqlmap
msfvenom
nc
ssh
hydra
john
```

It also contains dedicated installation logic for selected Go-based tools and Subhunt.

Because installer coverage and workflow integration coverage are not identical, users should verify required external dependencies before running a profile.

---

## Profiles

ScopeForgeX currently defines two workflow profiles in `config/profiles.yaml`.

### FAST

```text
FAST: Subhunt discovery -> httpx validation -> optional Katana endpoint discovery -> Nuclei
```

Enabled stages:

```text
1 -> Reconnaissance
3 -> Vulnerability Identification
6 -> Reporting
```

Stage 0 still runs before profile stages to collect and classify the target.

For the connected web/domain workflow, FAST prioritizes:

```text
Subhunt
   |
   v
Normalized discovered hosts
   |
   v
httpx
   |
   v
Validated hosts
   |
   +----------------------+
   |                      |
   v                      v
Optional Katana        Nuclei
   |                      |
   v                      v
Normalized URLs        Host results
   |
   v
Nuclei URL results
   |
   v
Reporting
```

FAST Stage 1 explicitly filters registered Stage 1 execution to:

```text
subhunt
pipeline_builder
```

The pipeline builder then handles the connected host-validation and optional endpoint-discovery behavior.

### FULL_SAFE

```text
Full safe workflow automation (CLI-only)
```

Enabled stages:

```text
1
2
3
4
5
6
```

Stage 0 runs before these stages.

FULL_SAFE executes the broader registered workflow while preserving the project's safety model.

This means higher-risk stages can prepare commands for review rather than automatically performing exploitation or post-exploitation activity.

The name `FULL_SAFE` should therefore be interpreted as a broader **safety-constrained workflow**, not unrestricted autonomous penetration testing.

---

## Repository Structure

The repository is organized around configuration, orchestration, tool registration, workflow stages, integrations, reporting, and generated output.

A simplified structure is:

```text
ScopeForgeX/
├── README.md
├── requirements.txt
├── scopeforgex.py
│
├── config/
│   ├── default.yaml
│   ├── profiles.yaml
│   └── tools.yaml
│
├── scopeforgex/
│   ├── cli.py
│   ├── dashboard.py
│   ├── installer.py
│   ├── merger.py
│   ├── runner.py
│   ├── state.py
│   ├── toolcheck.py
│   ├── ui.py
│   ├── wordlists.py
│   ├── workflow.py
│   │
│   ├── registry/
│   │   ├── tool_base.py
│   │   ├── tool_groups.py
│   │   └── tool_registry.py
│   │
│   ├── stages/
│   │   ├── stage0_scope.py
│   │   ├── stage1_recon.py
│   │   ├── stage2_enum.py
│   │   ├── stage3_vuln.py
│   │   ├── stage4_exploit.py
│   │   ├── stage5_post.py
│   │   └── stage6_report_cleanup.py
│   │
│   └── tools/
│       └── Python tool-integration modules
│
├── reporting/
│   └── Reporting-related modules
│
└── outputs/
    └── Generated per-target assessment artifacts
```

The exact repository tree may contain additional implementation files.

Use the tracked repository contents as the authoritative source for the current structure.

### Component Responsibilities

```text
config/
    Workflow and tool configuration.

scopeforgex/registry/
    Tool abstractions, grouping, and registry construction.

scopeforgex/stages/
    Stage-level orchestration and routing.

scopeforgex/tools/
    Concrete external-tool integrations and prepared-command integrations.

scopeforgex/workflow.py
    Profile-driven stage dispatch.

scopeforgex/state.py
    Basic last-run metadata persistence.

scopeforgex/merger.py
    Reusable merge helpers; not currently wired into primary workflow dispatch.

reporting/
    Reporting-related implementation outside the main package.

outputs/
    Runtime-generated assessment artifacts.
```

---

## Installation

### 1. Clone the Repository

```bash
git clone git@github.com:VikashChoudhary-04/ScopeForgeX.git
cd ScopeForgeX
```

If SSH authentication is not configured, clone using the appropriate authenticated Git transport available in your environment.

### 2. Install Python Dependencies

```bash
pip install -r requirements.txt
```

Using a Python virtual environment is recommended:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip install -r requirements.txt
```

### 3. Install External Tools

ScopeForgeX provides an installer entry point for a subset of dependencies:

```bash
python3 scopeforgex.py --install-tools
```

The installer should not be interpreted as a complete dependency manager for every tool listed in `config/tools.yaml`.

Before running a workflow, verify that the tools required by the intended profile are installed and available in `PATH`.

For the connected FAST workflow, important dependencies include:

```text
subhunt
httpx
nuclei
```

Katana adds optional endpoint discovery when available.

---

## Usage

Launch ScopeForgeX according to the supported CLI behavior:

```bash
python3 scopeforgex.py
```

The interactive dashboard provides actions including:

```text
Run FAST Profile
Run FULL_SAFE Profile
Install Tools
View Last Run
Exit
```

### Run FAST Profile

Use FAST when you want the narrower connected reconnaissance and vulnerability-identification workflow.

Its implemented connected path emphasizes:

```text
Subhunt
-> host normalization
-> httpx
-> optional Katana
-> normalized host / URL targets
-> Nuclei
-> reporting
```

### Run FULL_SAFE Profile

Use FULL_SAFE for the broader stage sequence.

It enables Stages 1 through 6 after Stage 0 scope collection.

Target type and registered integrations determine which supported operations apply.

Higher-risk actions remain subject to the prepared-command safety model.

### View Last Run

The dashboard can display metadata persisted from the most recent completed workflow.

The stored information includes basic fields such as:

```text
Target Type
Target
Output Directory
```

**View Last Run does not continue an interrupted assessment.**

The current implementation does not persist:

- Current stage checkpoints.
- Completed-tool checkpoints.
- Partial-stage execution state.
- Artifact validation state required for safe continuation.
- A restored context that is passed back into `run_profile()` for continuation.

A true workflow-resume engine would require explicit checkpointing and safe handling of partially generated artifacts.

---

## Output Structure

ScopeForgeX creates structured per-target workflow output.

The exact files depend on:

- Target type.
- Selected profile.
- Installed tools.
- Tool execution results.
- Whether optional pipeline components are available.

A run may contain directories conceptually organized as:

```text
outputs/
└── <target>/
    ├── recon/
    ├── enum/
    ├── vuln/
    ├── exploit/
    ├── post/
    └── report.md
```

Actual generated filenames are determined by the implementation.

### FAST Reconnaissance Artifacts

The connected FAST pipeline can produce files including:

```text
recon/subhunt.txt
recon/subhunt.log
recon/subhunt_wordlist_used.txt

recon/hosts_raw.txt
recon/hosts_alive.txt
recon/hosts_final.txt

recon/httpx.log

recon/katana.txt
recon/katana.log

recon/urls_raw.txt
recon/urls_final.txt
```

Katana-related artifacts are conditional on Katana availability and execution.

### Vulnerability Artifacts

Stage 3 can produce Nuclei artifacts including:

```text
vuln/nuclei_hosts.txt
vuln/nuclei_urls.txt
vuln/nuclei.txt

vuln/nuclei_hosts.log
vuln/nuclei_urls.log
```

Host and URL scans are handled separately where their corresponding normalized target files are available.

### Prepared Commands

Higher-risk workflow stages may produce or expose commands intended for manual analyst review.

These commands should be treated as **prepared actions**, not evidence of execution.

### Last-Run State

Basic run metadata is persisted under:

```text
outputs/.last_run.json
```

This supports the dashboard's **View Last Run** functionality.

It is not a workflow checkpoint file.

---

## Reporting

Stage 6 generates:

```text
report.md
```

The report summarizes available workflow information such as:

- Target.
- Target type.
- Profile.
- Output directory.
- Available stage/tool results.
- Available vulnerability-identification artifacts.

The current Stage 6 implementation reads the Nuclei logging contract used by Stage 3:

```text
vuln/nuclei_hosts.log
vuln/nuclei_urls.log
```

It does not depend on a nonexistent:

```text
vuln/nuclei.log
```

The report should be treated as an automatically generated workflow summary.

It is not automatically equivalent to a complete professional penetration-test report containing:

- Fully validated findings.
- Manual exploit verification.
- Business-impact analysis.
- CVSS scoring.
- Evidence screenshots.
- Executive risk narratives.
- Remediation verification.

Those activities still require analyst review and, where appropriate, manual documentation.

### Reporting Package

The repository contains a top-level:

```text
reporting/
```

package/directory with reporting-related implementation.

Documentation should not assume the existence of:

```text
scopeforgex/reporting/
```

unless that package exists in the tracked repository.

The active Stage 6 Markdown report generation remains part of the main staged workflow.

---

## Current Implementation Boundaries

ScopeForgeX intentionally documents current implementation boundaries so that portfolio claims remain aligned with the code.

### 1. Last-Run State Is Not Workflow Resume

`state.py` persists basic metadata from the latest run.

The dashboard can load and display this information through:

```text
View Last Run
```

There is currently no full interrupted-workflow continuation engine.

### 2. Not Every Configured Tool Is Registered

`config/tools.yaml` contains a broader catalog than the active workflow registry.

Configuration presence alone does not mean a tool is automatically executed.

### 3. Installer Coverage Is Partial

The installer handles a subset of dependencies.

Users may need to install additional tools separately.

### 4. Pipeline Connectivity Varies

The FAST workflow contains explicit cross-tool artifact flow.

Other integrations may execute as stage-level operations without equivalent producer-to-consumer chaining.

### 5. `merger.py` Is Currently a Utility Module

The merger module provides reusable helpers such as target merging, but the current primary workflow does not import or dispatch it.

It should not be described as an active central pipeline component until it is wired into workflow execution.

### 6. Higher-Risk Actions Are Prepared, Not Automatically Proven

Prepared exploitation or post-exploitation commands do not establish:

- Successful exploitation.
- Shell access.
- Credential compromise.
- Privilege escalation.
- Lateral movement.
- Persistence.
- Target compromise.

Those outcomes require separate authorized execution and validation.

### 7. Reporting Is Artifact-Based

Generated reporting reflects information available to the workflow.

It should not infer evidence, cleanup completion, or security impact that was not actually captured or validated.

---

## ScopeForgeX vs Subhunt

ScopeForgeX and Subhunt serve different purposes.

### Subhunt

Subhunt is a focused subdomain-discovery tool.

Within ScopeForgeX, it acts as a discovery source for the connected FAST web reconnaissance pipeline.

Its output can feed downstream processing such as:

```text
Subhunt
-> normalized hosts
-> httpx validation
-> optional Katana discovery
-> Nuclei
```

### ScopeForgeX

ScopeForgeX is the broader orchestration layer.

It provides:

- Target classification.
- Profile-driven workflow execution.
- Stage-based organization.
- Tool registration.
- Web/network routing where implemented.
- Structured artifact handling.
- Connected FAST data flow.
- Analyst-assisted command preparation.
- Markdown reporting.
- Basic last-run metadata persistence.

The relationship can be summarized as:

```text
Subhunt
    =
Focused discovery capability

ScopeForgeX
    =
Assessment workflow orchestration
```

Subhunt is therefore one component that ScopeForgeX can orchestrate rather than a replacement for the larger workflow.

---

## Portfolio Engineering Focus

ScopeForgeX demonstrates several security-engineering concepts beyond simply invoking command-line tools:

- Workflow decomposition into explicit stages.
- Tool abstraction and registry design.
- Profile-driven execution.
- Shared workflow context.
- Target-type routing.
- Producer-to-consumer artifact flow.
- Normalized intermediate files.
- Optional dependency handling.
- Safety boundaries between automation and analyst-controlled actions.
- Structured output organization.
- State persistence for run metadata.
- Automated Markdown summary generation.
- Separation between configured capabilities and implemented integrations.

The project also deliberately documents incomplete or partially connected capabilities rather than presenting them as finished features.

That distinction is important for maintaining technically defensible portfolio claims.

---

## Legal and Ethical Use

ScopeForgeX is intended exclusively for:

- Authorized penetration testing.
- Red-team exercises conducted with explicit permission.
- Controlled cybersecurity labs.
- CTF environments.
- Systems owned by the tester.
- Security research performed within clearly defined authorization and scope.

Do not use ScopeForgeX against systems, networks, applications, accounts, or infrastructure without explicit authorization.

The user is responsible for:

- Obtaining permission before testing.
- Respecting defined scope.
- Understanding the behavior of external tools before execution.
- Reviewing prepared commands before running them.
- Avoiding unnecessary operational impact.
- Protecting collected assessment data.
- Following applicable laws, contracts, and disclosure requirements.

ScopeForgeX's safety-oriented workflow design does not replace professional judgment or legal authorization.

---

## License

This project is distributed under the license included in the repository.

Review the repository's license file for the exact terms governing use, modification, and distribution.

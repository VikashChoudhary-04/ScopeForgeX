# ScopeForgeX

![License](https://img.shields.io/badge/License-MIT-blue?style=flat-square)
![Python](https://img.shields.io/badge/Python-3.x-yellow?style=flat-square)
![Hands-on](https://img.shields.io/badge/Hands--on-Yes-success?style=flat-square)
![Cybersecurity](https://img.shields.io/badge/Cybersecurity-Offensive-red?style=flat-square)
![Pentesting](https://img.shields.io/badge/Pentesting-Web_App-important?style=flat-square)

- ScopeForgeX is a **Python-based penetration-testing workflow orchestrator** designed to coordinate CLI security tools across reconnaissance, enumeration, vulnerability identification, assisted validation, and reporting.

- Rather than treating security tools as isolated commands, ScopeForgeX provides a structured workflow for executing supported tools, organizing per-target results, passing data between connected stages where implemented, resuming interrupted assessments, and preparing higher-risk commands for explicit human review.

- The project follows a **safety-first execution model**: supported lower-risk assessment tasks can run automatically, while exploitation, credential-testing, and post-exploitation actions remain under deliberate user control.

---

## Contents

- [Key Features](#key-features)
- [Architecture](#architecture)
- [Safety-First Execution Model](#safety-first-execution-model)
- [Supported Tool Integrations](#supported-tool-integrations)
- [Dependencies](#dependencies)
- [Profiles](#profiles)
- [Repository Structure](#repository-structure)
- [Installation](#installation)
- [Usage](#usage)
- [Output Structure](#output-structure)
- [Reporting](#reporting)
- [ScopeForgeX vs Subhunt](#scopeforgex-vs-subhunt)
- [Legal and Ethical Use](#legal-and-ethical-use)
- [License](#license)

---

## Key Features

- ScopeForgeX currently provides:

  * Terminal-based interface with no GUI or API-key-dependent integrations
  * Interactive terminal dashboard for profile selection, tool installation, workflow resume, and execution
  * Rich terminal UI with stage panels and progress indicators
  * Profile-driven security workflows
  * Automated execution of supported reconnaissance, enumeration, and vulnerability-identification tools
  * Connected FAST reconnaissance pipeline for discovery, live-host validation, endpoint discovery, and vulnerability identification
  * Structured per-target output organization
  * Target and result normalization for supported workflow stages
  * Default and custom wordlist support for `ffuf`
  * Prepared command generation for higher-risk exploitation, credential-testing, and post-exploitation workflows
  * Resumable workflow support
  * Markdown report generation through the current Stage 6 reporting workflow
  * Built-in supported-tool installation workflow

---

## Architecture

- ScopeForgeX is designed as a **staged security-workflow orchestrator**, rather than simply a collection of independent tool wrappers.

- At a high level, the workflow follows this structure:

  ```text
  Target Input
       ↓
  Scope Validation
       ↓
  Profile Selection
       ↓
  Tool Registry + Configuration
       ↓
  Workflow Engine
       ↓
  Stage 1: Reconnaissance
       ↓
  Stage 2: Enumeration
       ↓
  Stage 3: Vulnerability Identification
       ↓
  Stage 4/5: Prepared Commands + Human Review
       ↓
  Result Processing / Merging
       ↓
  Stage 6: Report Generation
  ```

### Core Components

- **Workflow Engine (`workflow.py`)**

  * Coordinates execution across assessment stages according to the selected workflow and profile.

- **Tool Registry (`registry/`)**

  * Organizes supported tool integrations and provides a structured way for the workflow to work with different security tools.

- **Runner (`runner.py`)**

  * Handles execution of supported external CLI commands and captures their output for use by ScopeForgeX.

- **State Manager (`state.py`)**

  * Tracks workflow progress and supports resumable assessment execution.

- **Merger (`merger.py`)**

  * Consolidates discovered assets and results into normalized data that can be used by supported downstream workflow stages.

- **Configuration (`config/`)**

  * YAML-based configuration controls defaults, tool settings, and workflow profiles without requiring changes to the core orchestration logic.

- **Stages (`stages/`)**

  * Separates the assessment lifecycle into scope handling, reconnaissance, enumeration, vulnerability identification, assisted higher-risk actions, and reporting.

### How ScopeForgeX Works

- ScopeForgeX does not reimplement the functionality of tools such as Nmap, Nuclei, httpx, or ffuf.

- Instead, it acts as an orchestration layer that:

  1. Accepts and validates the target.
  2. Selects an execution profile.
  3. Determines which supported tools apply to the target and workflow stage.
  4. Builds and executes supported tool commands.
  5. Stores tool output in structured per-target locations.
  6. Normalizes or merges relevant results where supported.
  7. Passes data between connected workflow stages where implemented.
  8. Tracks workflow state for resumable execution.
  9. Generates assessment output through the current reporting stage.

- Higher-risk exploitation, credential-testing, tunneling, payload-generation, and post-exploitation commands are prepared for human review rather than silently executed.

### Connected FAST Pipeline

- The FAST workflow contains the clearest example of connected data flow between security tools:

  ```text
  Target
    ↓
  Subhunt
    ↓
  Discovered Hosts
    ↓
  httpx
    ↓
  Validated Live Hosts
    ↓
  Katana
    ↓
  Discovered URLs / Endpoints
    ↓
  Nuclei
    ↓
  Vulnerability Identification
  ```

- This allows output from one supported stage to become useful input for subsequent stages instead of treating every tool as an isolated command.

- Not every current integration is fully pipeline-connected.

  * Some tools execute independently within their stage.
  * Higher-risk stages use assisted command generation.

- Expanding structured data flow across additional stages remains an ongoing architectural improvement.

---

## Safety-First Execution Model

- ScopeForgeX separates automated security-assessment tasks from higher-risk actions that require explicit human review.

### Safe Auto-Run

- Lower-risk reconnaissance, enumeration, and configured vulnerability-identification tools can execute automatically as part of supported workflows.

- Where pipeline integration is implemented, outputs can be normalized and passed into supported downstream stages, reducing repetitive manual work while preserving a structured and traceable assessment process.

  ```text
  Target
    ↓
  Reconnaissance
    ↓
  Enumeration
    ↓
  Vulnerability Identification
    ↓
  Automatic Execution Where Configured
  ```

### Prepared Commands + Human Review

- Higher-risk exploitation, credential-testing, tunneling, payload-generation, and post-exploitation actions are not silently executed.

- ScopeForgeX prepares supported commands for review so that the authorized tester retains deliberate control over intrusive actions.

  ```text
  Potential Finding / Testing Requirement
    ↓
  Exploitation / Credential / Post Stage
    ↓
  Prepared Command
    ↓
  Human Review
    ↓
  Explicit User Execution
  ```

- This separation is intentional.

  * It reduces the risk of an automated workflow unexpectedly progressing from discovery and identification into intrusive activity.
  * It still provides reproducible commands for authorized validation.

---

## Supported Tool Integrations

- ScopeForgeX integrates external CLI tools at different levels of workflow support.

- A tool is listed as **automatically executed** only when ScopeForgeX currently invokes it as part of an implemented workflow.

- Higher-risk tools supported through command generation are listed separately.

### Automatically Executed CLI Tools

#### Reconnaissance

- The currently executed reconnaissance integrations include:

  * `subhunt`
  * `httpx`
  * `katana`
  * `naabu`
  * `rustscan`
  * `nmap`

#### Enumeration

- The currently executed enumeration integrations include:

  * `whatweb`
  * `wafw00f`
  * `ffuf`
  * `enum4linux-ng`
  * `snmpwalk`

#### Vulnerability Identification

- The currently executed vulnerability-identification integration includes:

  * `nuclei`

### Assisted Command Tools

- The following tools are supported through prepared command generation rather than silent automatic execution.

#### Exploitation / Validation

- Supported exploitation and validation command integrations include:

  * `sqlmap`
  * `dalfox`
  * `xsstrike`
  * `sstimap`
  * `searchsploit`
  * `msfvenom`
  * `netcat`

#### Credential / Tunneling / Post-Exploitation

- Supported credential, tunneling, and post-exploitation command integrations include:

  * `chisel`
  * `ssh`
  * `hydra`
  * `medusa`
  * `hashcat`
  * `john`

- Tool availability and execution depend on:

  * Selected workflow
  * Selected profile
  * Target type
  * Installed dependencies
  * Current integration support

---

## Dependencies

- ScopeForgeX has two dependency layers:

  1. Python packages required by the ScopeForgeX application.
  2. External CLI tools used by supported security workflows.

### Python Dependencies

- Install the required Python packages with:

  ```bash
  pip3 install -r requirements.txt
  ```

- These dependencies provide the Python libraries required for:

  * CLI functionality
  * Terminal interface
  * Configuration handling
  * Workflow orchestration
  * Supporting application functionality

### External CLI Tools

- ScopeForgeX relies on external security tools for the capabilities they provide.

- Currently executed CLI integrations include:

  * `subhunt`
  * `httpx`
  * `katana`
  * `naabu`
  * `rustscan`
  * `nmap`
  * `whatweb`
  * `wafw00f`
  * `ffuf`
  * `enum4linux-ng`
  * `snmpwalk`
  * `nuclei`

- Use ScopeForgeX's supported installation workflow where applicable:

  ```bash
  python3 scopeforgex.py --install-tools
  ```

- ScopeForgeX does **not** bundle or redistribute third-party security tools.

- External tools retain their own:

  * Installation requirements
  * Dependencies
  * Licenses
  * Usage restrictions
  * Update mechanisms

- Tool availability may vary by operating system and environment.

- A tool being supported by ScopeForgeX does not necessarily mean that it is already installed on the current system.

### Assisted Command Dependencies

- Higher-risk tools used by the assisted workflow must also be installed separately before their generated commands can be executed manually.

- ScopeForgeX prepares these commands but does not silently execute them.

---

## Profiles

- ScopeForgeX uses profiles to control workflow depth and tool execution.

- Profile definitions are stored in:

  ```text
  config/profiles.yaml
  ```

- This allows different assessment workflows to be selected without modifying the core orchestration code.

- For example, the FAST workflow prioritizes a connected reconnaissance and vulnerability-identification pipeline:

  ```text
  Subhunt
     ↓
  httpx
     ↓
  Katana
     ↓
  Nuclei
  ```

- Other profiles may enable broader assessment stages depending on their current configuration.

- The exact tools and stages executed depend on:

  * Selected profile
  * Target type
  * Installed dependencies
  * Current integration support

---

## Repository Structure

- The current repository is organized as follows:

  ```text
  ScopeForgeX/
  │
  ├── README.md
  ├── LICENSE
  ├── .gitignore
  ├── requirements.txt
  ├── pyproject.toml
  ├── scopeforgex.py
  │
  ├── config/
  │   ├── default.yaml
  │   ├── tools.yaml
  │   └── profiles.yaml
  │
  ├── scopeforgex/
  │   ├── cli.py
  │   ├── dashboard.py
  │   ├── workflow.py
  │   ├── runner.py
  │   ├── toolcheck.py
  │   ├── installer.py
  │   ├── ui.py
  │   ├── state.py
  │   ├── merger.py
  │   ├── wordlists.py
  │   │
  │   ├── registry/
  │   │   ├── tool_base.py
  │   │   ├── tool_registry.py
  │   │   └── tool_groups.py
  │   │
  │   ├── tools/
  │   │   ├── stage1_recon_web.py
  │   │   ├── stage1_recon_network.py
  │   │   ├── stage2_enum_web.py
  │   │   ├── stage2_enum_network.py
  │   │   ├── stage3_vuln.py
  │   │   ├── stage4_exploit.py
  │   │   └── stage5_post.py
  │   │
  │   ├── stages/
  │   │   ├── shared.py
  │   │   ├── stage0_scope.py
  │   │   ├── stage1_recon.py
  │   │   ├── stage2_enum.py
  │   │   ├── stage3_vuln.py
  │   │   ├── stage4_exploit.py
  │   │   ├── stage5_post.py
  │   │   └── stage6_report_cleanup.py
  │   │
  │   └── reporting/
  │       ├── __init__.py
  │       ├── models.py
  │       └── report_generator.py
  │
  └── outputs/
      └── .gitkeep
  ```

- The `reporting/` package currently represents the architectural foundation for a future structured reporting engine.

  * It is not yet the active end-to-end reporting path.
  * Current report generation remains handled by the existing Stage 6 workflow.

---

## Installation

### 1. Clone the Repository

- Clone ScopeForgeX and enter the project directory:

  ```bash
  git clone https://github.com/VikashChoudhary-04/ScopeForgeX.git
  cd ScopeForgeX
  ```

### 2. Install Python Dependencies

- Install the required Python packages:

  ```bash
  pip3 install -r requirements.txt
  ```

### 3. Install Supported External Tools

- Use the built-in installation workflow where applicable:

  ```bash
  python3 scopeforgex.py --install-tools
  ```

- External-tool installation support may vary depending on:

  * Operating system
  * Package manager
  * Individual tool requirements

- Always verify that the tools required by the selected workflow are installed correctly before beginning an assessment.

---

## Usage

- Start ScopeForgeX with:

  ```bash
  python3 scopeforgex.py
  ```

- The terminal dashboard provides access to supported workflow actions such as:

  * Running an assessment profile
  * Installing supported tools
  * Resuming supported workflow state
  * Exiting the application

- The exact stages and tools used during execution depend on the selected profile and target type.

---

## Output Structure

- ScopeForgeX organizes assessment results by target.

- A typical output structure follows this pattern:

  ```text
  outputs/<target-name>/
  ├── recon/
  ├── enum/
  ├── vuln/
  ├── exploit/
  ├── post/
  └── report.md
  ```

- Individual tools may create additional files inside their corresponding stage directories.

- Higher-risk assisted stages may also store generated commands for later review, including files such as:

  ```text
  outputs/<target-name>/exploit/prepared_commands.txt
  outputs/<target-name>/post/prepared_commands.txt
  ```

- Output generated by connected pipelines may also include normalized host or endpoint data used by supported downstream stages.

---

## Reporting

- ScopeForgeX currently generates a Markdown assessment report through its existing Stage 6 reporting workflow.

  ```text
  outputs/<target-name>/report.md
  ```

- A newer structured reporting architecture is under development in:

  ```text
  scopeforgex/reporting/
  ```

- The current foundation includes models intended to support more structured:

  * Target metadata
  * Assessment timing
  * Stage results
  * Statistics
  * Findings
  * Warnings and errors
  * Generated-file tracking

- The scanning workflow does not yet populate this model end-to-end.

- The newer report generator has not yet replaced the existing Stage 6 reporting implementation.

- The newer reporting architecture should therefore be considered **development work rather than a completed feature**.

- Until that integration is complete, the existing Stage 6 reporting workflow remains the active reporting implementation.

---

## ScopeForgeX vs Subhunt

- ScopeForgeX and Subhunt serve different purposes.

### Subhunt

- Subhunt is a **focused subdomain-enumeration tool** designed specifically for discovering and consolidating subdomains during reconnaissance.

### ScopeForgeX

- ScopeForgeX is a **broader penetration-testing workflow orchestrator**.

- It can use Subhunt as one reconnaissance component and then continue into supported stages such as:

  ```text
  Subdomain Discovery
         ↓
  Live-Host Validation
         ↓
  Endpoint Discovery
         ↓
  Enumeration
         ↓
  Vulnerability Identification
         ↓
  Assisted Validation
         ↓
  Reporting
  ```

- In short:

  > **Subhunt provides a focused reconnaissance capability. ScopeForgeX coordinates broader security-assessment workflows and can integrate Subhunt as one component within them.**

---

## Legal and Ethical Use

- ScopeForgeX is intended exclusively for:

  * Authorized penetration testing
  * Security labs
  * Capture-the-Flag environments
  * Systems you own
  * Environments where you have explicit permission to perform security testing

- Do not use ScopeForgeX against systems without authorization.

- Users are responsible for ensuring that all testing complies with:

  * Applicable laws
  * Rules of engagement
  * Program policies
  * Written authorization

---

## License

- This project is licensed under the MIT License.

- See the `LICENSE` file for details.

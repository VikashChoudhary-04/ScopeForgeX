# ScopeForgeX

ScopeForgeX is a **question-driven ethical hacking workflow automation tool** that provides a **single interface** for running a full penetration testing workflow automatically using CLI tools only.

It automates the workflow using:

* ✅ `Safe Auto-Run` for Recon / Enum / Vulnerability Identification
* ✅ `Prepared Commands + Confirmation` for Exploitation / Credential / Post stages

---

## ✅ Key Features

* ✅ CLI-only tool automation (no GUI, no API-key tools)
* ✅ Interactive `Dashboard UI` (Run Profiles / Install Tools / Resume / Exit)
* ✅ Rich `Terminal UI` with stage panels and progress bars
* ✅ Generates clean outputs per target
* ✅ Creates merged and validated target lists:

  * `final_targets.txt`
  * `final_alive.txt`
* ✅ Default + Custom wordlist system for `FFUF`
* ✅ Prepared commands saved automatically:

  * `outputs/<target>/exploit/prepared_commands.txt`
  * `outputs/<target>/post/prepared_commands.txt`
* ✅ Auto report generation (`report.md`)
* ✅ Built-in tool installer mode (`--install-tools`)

---

## ⚠️ Legal Warning

This tool is meant for `authorized security testing only`.

If you do not have `written permission`, `do not use it`.

---

## ✅ CLI Tools Automated (40 Tools)

### 🟩 Stage 1 — Web Recon (6)

* `sublist3r`
* `dnsrecon`
* `httpx`
* `subhunt`
* `gau`
* `katana`

### 🟩 Stage 1 — Network Recon (3)

* `naabu`
* `rustscan`
* `nmap`

### 🟨 Stage 2 — Enumeration (6)

* `gobuster`
* `ffuf`
* `feroxbuster`
* `whatweb`
* `wafw00f`
* `lbd`

### 🟨 SMB Enumeration (4)

* `enum4linux-ng`
* `smbclient`
* `smbmap`
* `nbtstat`

### 🟨 SNMP Enumeration (3)

* `onesixtyone`
* `snmpwalk`
* `snmp-check`

### 🟨 DNS Enumeration (2)

* `dnsenum`
* `dig`

### 🟥 Stage 3 — Vulnerability Identification (3)

* `nuclei`
* `nikto`
* `wpscan`

### 🟥 Stage 4 — Exploit Prep (Prepared + Confirmation) (7)

* `sqlmap`
* `dalfox`
* `xsstrike`
* `sstimap`
* `searchsploit`
* `msfvenom`
* `netcat`

### 🟪 Stage 5 — Post/Creds Prep (Prepared + Confirmation) (6)

* `chisel`
* `ssh`
* `hydra`
* `medusa`
* `hashcat`
* `john`

---

## 📁 Repository Structure
```txt
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
│ ├── default.yaml
│ ├── tools.yaml
│ └── profiles.yaml
│
├── scopeforgex/
│ ├── init.py
│ ├── cli.py
│ ├── dashboard.py
│ ├── workflow.py
│ ├── runner.py
│ ├── toolcheck.py
│ ├── installer.py
│ ├── ui.py
│ ├── state.py
│ ├── merger.py
│ ├── wordlists.py
│ │
│ ├── registry/
│ │ ├── init.py
│ │ ├── tool_base.py
│ │ ├── tool_registry.py
│ │ └── tool_groups.py
│ │
│ ├── tools/
│ │ ├── init.py
│ │ ├── stage1_recon_web.py
│ │ ├── stage1_recon_network.py
│ │ ├── stage2_enum_web.py
│ │ ├── stage2_enum_network.py
│ │ ├── stage3_vuln.py
│ │ ├── stage4_exploit.py
│ │ ├── stage5_post.py
│ │ └── osint_cloud_mobile_wireless.py
│ │
│ └── stages/
│ ├── init.py
│ ├── shared.py
│ ├── stage0_scope.py
│ ├── stage1_recon.py
│ ├── stage2_enum.py
│ ├── stage3_vuln.py
│ ├── stage4_exploit.py
│ ├── stage5_post.py
│ └── stage6_report_cleanup.py
│
└── outputs/
└── .gitkeep
```
---

## 📦 Installation

### 1) Install Python requirements

`bash
pip install -r requirements.txt
`

### 2) Install tools automatically (Linux apt best support)

`bash
python scopeforgex.py --install-tools
`

---

## 🚀 Run ScopeForgeX

`bash
python scopeforgex.py
`

---

## ✅ Output Structure

```txt
outputs/<target-name>/
recon/
enum/
vuln/
exploit/
post/
report.md
```


---

## 📜 License

MIT License

import os
import platform
import subprocess
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.ui import stage, info, ok, warn

REQUIRED_TOOLS = [
    "nmap",
    "whatweb",
    "wafw00f",
    "ffuf",
    "dnsrecon",
    "wpscan",
    "sublist3r",
    "httpx",
    "gau",
    "katana",
    "nuclei",
    "subhunt",
    "sqlmap",
    "nikto",
    "hydra",
    "john",
]

def run(cmd: str):
    info(f"$ {cmd}")
    subprocess.run(cmd, shell=True, check=False)

def detect_pkg_manager():
    if os.system("which apt >/dev/null 2>&1") == 0:
        return "apt"
    return None

def install_go_tools():
    run("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    run("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    run("go install -v github.com/projectdiscovery/katana/cmd/katana@latest")
    run("go install -v github.com/lc/gau/v2/cmd/gau@latest")
    run("go install -v github.com/g0ldencybersec/subhunt/cmd/subhunt@latest")

def install_tools():
    stage("ScopeForgeX Tool Installer", "green")

    missing = [t for t in REQUIRED_TOOLS if not is_tool_installed(t)]
    if not missing:
        ok("All core tools already installed ✅")
        return

    warn("Missing tools detected:")
    for t in missing:
        info(f"- {t}")

    system = platform.system().lower()
    pm = detect_pkg_manager()

    if system == "linux" and pm == "apt":
        info("Installing tools using apt + pip + go...")

        run("sudo apt update -y")
        run("sudo apt install -y nmap whatweb wafw00f ffuf dnsrecon wpscan nikto sqlmap hydra john python3-pip golang")

        run("pip3 install --upgrade pip")
        run("pip3 install sublist3r knockpy")

        install_go_tools()

        ok("✅ Installation completed.")
        warn("Go binaries usually install to: ~/go/bin")
        warn("Ensure PATH includes: export PATH=$PATH:$HOME/go/bin")
        return

    warn("Auto-install only supports Linux apt currently.")

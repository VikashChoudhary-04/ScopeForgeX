"""
ScopeForgeX Tool Installer
==========================

Installs and verifies the external tools required by ScopeForgeX.

Currently supports:
    • Linux (APT-based distributions)

v0.4.0
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.ui import err, info, ok, stage, warn


# ----------------------------------------------------------------------
# Required tools
# ----------------------------------------------------------------------

REQUIRED_TOOLS = [
    "sublist3r",
    "dnsrecon",
    "httpx",
    "gau",
    "katana",
    "subhunt",
    "nmap",
    "whatweb",
    "wafw00f",
    "ffuf",
    "nuclei",
    "nikto",
    "wpscan",
    "sqlmap",
    "msfvenom",
    "nc",
    "ssh",
    "hydra",
    "john",
]

APT_PACKAGES = [
    "nmap",
    "whatweb",
    "wafw00f",
    "ffuf",
    "dnsrecon",
    "wpscan",
    "nikto",
    "sqlmap",
    "hydra",
    "john",
    "netcat-openbsd",
]

GO_TOOLS = [
    "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
    "github.com/projectdiscovery/katana/cmd/katana@latest",
    "github.com/lc/gau/v2/cmd/gau@latest",
]

SUBHUNT_REPO = "https://github.com/VikashChoudhary-04/subhunt.git"


# ----------------------------------------------------------------------
# Helpers
# ----------------------------------------------------------------------

def run(command: str):
    """
    Execute a shell command.
    """

    info(f"$ {command}")

    subprocess.run(
        command,
        shell=True,
        check=False,
    )


def detect_pkg_manager() -> str | None:
    """
    Detect the available package manager.
    """

    return "apt" if shutil.which("apt") else None


def go_bin_path() -> Path:
    """
    Return the user's Go binary directory.
    """

    return Path.home() / "go" / "bin"


def check_path_for_go_bin():
    """
    Warn if ~/go/bin is not present in PATH.
    """

    gobin = str(go_bin_path())

    if gobin not in os.environ.get("PATH", ""):
        warn(f"Go bin directory not found in PATH: {gobin}")
        warn("Add it with:")
        warn("export PATH=$PATH:$HOME/go/bin")


# ----------------------------------------------------------------------
# Installers
# ----------------------------------------------------------------------

def install_go_tools():
    """
    Install ProjectDiscovery Go tools.
    """

    for tool in GO_TOOLS:
        run(f"go install -v {tool}")


def install_subhunt_from_git():
    """
    Build and install Subhunt from GitHub.
    """

    stage("Installing Subhunt (Go Build)", "cyan")

    tools_dir = Path.home() / "ScopeForgeX-tools"
    repo_dir = tools_dir / "subhunt"

    tools_dir.mkdir(parents=True, exist_ok=True)

    if repo_dir.exists():
        warn("Subhunt repository already exists. Pulling latest changes...")
        run(f"cd {repo_dir} && git pull")
    else:
        info("Cloning Subhunt repository...")
        run(f"cd {tools_dir} && git clone {SUBHUNT_REPO}")

    build_path = repo_dir / "cmd" / "subhunt"

    if not build_path.exists():
        err(f"Subhunt build path not found: {build_path}")
        return

    info("Building Subhunt...")
    run(f"cd {repo_dir} && go build -o subhunt ./cmd/subhunt")

    binary = repo_dir / "subhunt"

    if not binary.exists():
        err("Subhunt build failed.")
        return

    info("Installing Subhunt...")
    run(f"sudo cp {binary} /usr/local/bin/subhunt")
    run("sudo chmod +x /usr/local/bin/subhunt")

    if is_tool_installed("subhunt"):
        ok("Subhunt installed successfully.")
        run("subhunt --help")
    else:
        warn("Subhunt is not currently visible in PATH.")
        warn("Try:")
        warn("export PATH=$PATH:/usr/local/bin")
        warn("which subhunt")


# ----------------------------------------------------------------------
# Main installer
# ----------------------------------------------------------------------

def install_tools():
    """
    Install and verify all supported tools.
    """

    stage("ScopeForgeX Tool Installer", "green")

    if (
        platform.system().lower() != "linux"
        or detect_pkg_manager() != "apt"
    ):
        warn("Automatic installation currently supports Linux (APT) only.")
        warn("Install the tools manually and rerun this installer.")
        return

    info("Installing base dependencies...")
    run("sudo apt update -y")
    run("sudo apt install -y python3-pip golang git")

    info("Installing APT packages...")
    run(f"sudo apt install -y {' '.join(APT_PACKAGES)}")

    info("Installing Python packages...")
    run("pip3 install --upgrade pip")
    run("pip3 install sublist3r knockpy")

    info("Installing Go packages...")
    install_go_tools()
    check_path_for_go_bin()

    install_subhunt_from_git()

    info("Verifying installation...")

    missing = [
        tool
        for tool in REQUIRED_TOOLS
        if not is_tool_installed(tool)
    ]

    if not missing:
        ok("All required tools are installed and detected.")
        return

    err("Some required tools are still missing:")

    for tool in missing:
        warn(f"- {tool}")

    warn("If Go tools are missing, ensure PATH includes:")
    warn("export PATH=$PATH:$HOME/go/bin")

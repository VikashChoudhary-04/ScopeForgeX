import os
import platform
import subprocess

from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.ui import stage, info, ok, warn, err


REQUIRED_TOOLS = [
    # Web recon
    "sublist3r",
    "dnsrecon",
    "httpx",
    "subhunt",
    "gau",
    "katana",

    # Network recon
    "nmap",

    # Enum
    "whatweb",
    "wafw00f",
    "ffuf",

    # Vuln
    "nuclei",
    "nikto",
    "wpscan",

    # Exploit prep
    "sqlmap",
    "msfvenom",
    "nc",

    # Post/creds prep
    "ssh",
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


def go_bin_path() -> str:
    return os.path.join(os.path.expanduser("~"), "go", "bin")


def check_path_for_go_bin():
    gobin = go_bin_path()
    current_path = os.environ.get("PATH", "")
    if gobin not in current_path:
        warn(f"Go bin directory not found in PATH: {gobin}")
        warn("Add it with:")
        warn("export PATH=$PATH:$HOME/go/bin")


def install_go_tools():
    # ✅ ProjectDiscovery tools + Subhunt
    run("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    run("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    run("go install -v github.com/projectdiscovery/katana/cmd/katana@latest")
    run("go install -v github.com/lc/gau/v2/cmd/gau@latest")

    # ✅ Subhunt (your requested tool)
    run("go install -v github.com/g0ldencybersec/subhunt/cmd/subhunt@latest")


def install_tools():
    stage("ScopeForgeX Tool Installer", "green")

    system = platform.system().lower()
    pm = detect_pkg_manager()

    if system != "linux" or pm != "apt":
        warn("Auto-install currently supports Linux (apt-based) only.")
        warn("You can still install tools manually and re-run installer to verify.")
        return

    # Core packages
    info("Installing core dependencies...")
    run("sudo apt update -y")
    run("sudo apt install -y python3-pip golang git")

    # CLI tools from apt
    info("Installing CLI tools from apt...")
    run("sudo apt install -y nmap whatweb wafw00f ffuf dnsrecon wpscan nikto sqlmap hydra john netcat-openbsd")

    # Python tools
    info("Installing Python tools via pip...")
    run("pip3 install --upgrade pip")
    run("pip3 install sublist3r knockpy")

    # Go tools
    info("Installing Go-based tools (ProjectDiscovery + Subhunt)...")
    install_go_tools()

    # PATH sanity
    check_path_for_go_bin()

    # Final verification
    info("Verifying installations...")
    missing = [t for t in REQUIRED_TOOLS if not is_tool_installed(t)]

    if not missing:
        ok("✅ All required tools are installed and detected!")
    else:
        err("❌ Some tools are still missing:")
        for t in missing:
            warn(f"- {t}")
        warn("Most common fix: ensure Go bin path is in your PATH:")
        warn("export PATH=$PATH:$HOME/go/bin")

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
    "gau",
    "katana",
    "subhunt",  # ✅ compiled Go binary from your repo

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
    run("go install -v github.com/projectdiscovery/httpx/cmd/httpx@latest")
    run("go install -v github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest")
    run("go install -v github.com/projectdiscovery/katana/cmd/katana@latest")
    run("go install -v github.com/lc/gau/v2/cmd/gau@latest")


def install_subhunt_from_git():
    """
    ✅ Installs Subhunt from YOUR GitHub repo by compiling a Go binary.
    Repo: https://github.com/VikashChoudhary-04/subhunt.git
    Build path: ./cmd/subhunt
    Output binary: /usr/local/bin/subhunt
    """
    stage("Installing Subhunt (Go Build from GitHub Repo)", "cyan")

    repo_url = "https://github.com/VikashChoudhary-04/subhunt.git"
    tools_dir = os.path.join(os.path.expanduser("~"), "ScopeForgeX-tools")
    repo_dir = os.path.join(tools_dir, "subhunt")

    os.makedirs(tools_dir, exist_ok=True)

    if os.path.exists(repo_dir):
        warn("Subhunt repo already exists. Pulling latest updates...")
        run(f"cd {repo_dir} && git pull")
    else:
        info("Cloning Subhunt repository...")
        run(f"cd {tools_dir} && git clone {repo_url}")

    # ✅ Build path exists?
    cmd_path = os.path.join(repo_dir, "cmd", "subhunt")
    if not os.path.exists(cmd_path):
        err("❌ Subhunt build path not found: ./cmd/subhunt")
        warn(f"Expected path: {cmd_path}")
        return

    # ✅ Compile to local binary inside repo
    info("Building Subhunt binary...")
    run(f"cd {repo_dir} && go build -o subhunt ./cmd/subhunt")

    local_bin = os.path.join(repo_dir, "subhunt")
    if not os.path.exists(local_bin):
        err("❌ Build failed: binary not created.")
        return

    # ✅ Install globally
    info("Installing binary to /usr/local/bin/subhunt ...")
    run(f"sudo cp {local_bin} /usr/local/bin/subhunt")
    run("sudo chmod +x /usr/local/bin/subhunt")

    # ✅ Verify
    if is_tool_installed("subhunt"):
        ok("✅ Subhunt installed successfully as a CLI tool.")
        run("subhunt --help")
    else:
        warn("⚠️ Subhunt binary copied but still not found in PATH.")
        warn("Try running:")
        warn("export PATH=$PATH:/usr/local/bin")
        warn("which subhunt")


def install_tools():
    stage("ScopeForgeX Tool Installer", "green")

    system = platform.system().lower()
    pm = detect_pkg_manager()

    if system != "linux" or pm != "apt":
        warn("Auto-install currently supports Linux (apt-based) only.")
        warn("You can still install tools manually and re-run installer to verify.")
        return

    info("Installing core dependencies...")
    run("sudo apt update -y")
    run("sudo apt install -y python3-pip golang git")

    info("Installing CLI tools from apt...")
    run("sudo apt install -y nmap whatweb wafw00f ffuf dnsrecon wpscan nikto sqlmap hydra john netcat-openbsd")

    info("Installing Python tools via pip...")
    run("pip3 install --upgrade pip")
    run("pip3 install sublist3r knockpy")

    info("Installing Go-based tools (ProjectDiscovery)...")
    install_go_tools()
    check_path_for_go_bin()

    # ✅ Install Subhunt using Go build from your repo
    install_subhunt_from_git()

    info("Verifying installations...")
    missing = [t for t in REQUIRED_TOOLS if not is_tool_installed(t)]

    if not missing:
        ok("✅ All required tools are installed and detected!")
    else:
        err("❌ Some tools are still missing:")
        for t in missing:
            warn(f"- {t}")

        warn("If Go tools are missing, ensure PATH includes:")
        warn("export PATH=$PATH:$HOME/go/bin")

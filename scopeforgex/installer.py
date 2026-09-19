"""
ScopeForgeX Tool Installer
==========================

Installs and verifies the external tools required by the canonical
ScopeForgeX 19-tool registry.

Supported platform:
    - Linux (APT-based distributions)

Canonical tool groups
---------------------

APT packages
    - amass
    - nmap
    - dig
    - ffuf
    - whatweb
    - nikto
    - testssl.sh
    - sqlmap
    - sstimap
    - hydra
    - hashcat

Go-installed tools
    - httpx
    - katana
    - jsluice

Source-built tools
    - kiterunner
    - jwt_tool
    - subhunt

Cargo-installed tools
    - dalfox

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
from pathlib import Path

from scopeforgex.executable import resolve_executable
from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.ui import err, info, ok, stage, warn


###############################################################################
# Canonical Tool Sources
###############################################################################


TOOL_EXECUTABLES = {
    "amass": "amass",
    "subhunt": "subhunt",
    "nmap": "nmap",
    "dig": "dig",
    "httpx": "httpx",
    "katana": "katana",
    "ffuf": "ffuf",
    "whatweb": "whatweb",
    "kiterunner": "kr",
    "jsluice": "jsluice",
    "wapiti": "wapiti",
    "nikto": "nikto",
    "testssl.sh": "testssl.sh",
    "sqlmap": "sqlmap",
    "dalfox": "dalfox",
    "jwt_tool": "jwt_tool",
    "sstimap": "sstimap",
    "hydra": "hydra",
    "hashcat": "hashcat",
}

REQUIRED_TOOLS = tuple(TOOL_EXECUTABLES)

APT_PACKAGES = [
    "amass",
    "nmap",
    "bind9-dnsutils",
    "ffuf",
    "whatweb",
    "nikto",
    "testssl.sh",
    "sqlmap",
    "sstimap",
    "hydra",
    "hashcat",
    "wapiti",
    "seclists",
]


GO_TOOLS = [
    (
        "httpx",
        "github.com/projectdiscovery/httpx/cmd/httpx@latest",
    ),
    (
        "katana",
        "github.com/projectdiscovery/katana/cmd/katana@latest",
    ),
    (
        "jsluice",
        "github.com/BishopFox/jsluice/cmd/jsluice@latest",
    ),
]


DALFOX_INSTALL = (
    "cargo install dalfox --locked"
)


KITERUNNER_REPO = (
    "https://github.com/assetnote/kiterunner.git"
)


JWT_TOOL_REPO = (
    "https://github.com/ticarpi/jwt_tool.git"
)


SSTIMAP_REPO = (
    "https://github.com/vladko312/SSTImap.git"
)


SUBHUNT_REPO = (
    "https://github.com/VikashChoudhary-04/subhunt.git"
)


SOURCE_TOOLS_DIR = (
    Path.home()
    / "ScopeForgeX-tools"
)


###############################################################################
# Generic Helpers
###############################################################################


def run(
    command: str,
) -> bool:
    """
    Execute a shell command and return whether it succeeded.
    """

    info(
        f"$ {command}"
    )

    completed = subprocess.run(
        command,
        shell=True,
        check=False,
    )

    if completed.returncode != 0:
        err(
            f"Command failed with exit code {completed.returncode}: "
            f"{command}"
        )
        return False

    return True


def detect_pkg_manager() -> str | None:
    """
    Detect the available supported package manager.
    """

    if shutil.which(
        "apt"
    ):
        return "apt"

    return None


def resolve_tool_executable(tool_name: str) -> str:
    """
    Return the actual executable name for a logical ScopeForgeX tool.
    """
    try:
        return TOOL_EXECUTABLES[tool_name]
    except KeyError as exc:
        raise KeyError(
            f"Unknown ScopeForgeX tool: {tool_name}"
        ) from exc


def installed_tool_path(tool_name: str) -> str | None:
    """
    Resolve the canonical executable path for a logical ScopeForgeX tool.
    """
    return resolve_executable(
        resolve_tool_executable(tool_name)
    )


def verify_required_tools() -> tuple[list[str], dict[str, str]]:
    """
    Verify every canonical logical tool.
    """
    missing: list[str] = []
    resolved: dict[str, str] = {}

    for tool_name in REQUIRED_TOOLS:
        path = installed_tool_path(tool_name)
        if path is None:
            missing.append(tool_name)
        else:
            resolved[tool_name] = path

    return missing, resolved


def verify_wordlists() -> list[str]:
    """
    Verify the default wordlists required by the profiles.
    """
    from scopeforgex.wordlists import (
        find_default_subdomain_wordlist,
        find_default_web_fuzz_wordlist,
    )

    missing: list[str] = []
    if find_default_subdomain_wordlist() is None:
        missing.append("subdomain wordlist")
    if find_default_web_fuzz_wordlist() is None:
        missing.append("web-content wordlist")
    return missing


def go_bin_path() -> Path:
    """
    Return the user's Go binary directory.
    """

    return (
        Path.home()
        / "go"
        / "bin"
    )


def cargo_bin_path() -> Path:
    """
    Return the user's Cargo binary directory.
    """

    return (
        Path.home()
        / ".cargo"
        / "bin"
    )


def check_path_for_go_bin() -> None:
    """
    Warn when ~/go/bin is not present in PATH.
    """

    gobin = str(
        go_bin_path()
    )

    if gobin not in os.environ.get(
        "PATH",
        "",
    ):
        warn(
            f"Go bin directory not found in PATH: {gobin}"
        )
        warn(
            "Add it with:"
        )
        warn(
            "export PATH=$PATH:$HOME/go/bin"
        )


def check_path_for_cargo_bin() -> None:
    """
    Warn when ~/.cargo/bin is not present in PATH.
    """

    cargo_bin = str(
        cargo_bin_path()
    )

    if cargo_bin not in os.environ.get(
        "PATH",
        "",
    ):
        warn(
            f"Cargo bin directory not found in PATH: {cargo_bin}"
        )
        warn(
            "Add it with:"
        )
        warn(
            "export PATH=$PATH:$HOME/.cargo/bin"
        )


def install_symlink(
    source: Path,
    command_name: str,
) -> bool:
    """
    Expose a locally installed binary through /usr/local/bin.
    """

    if not source.is_file():
        warn(
            f"Binary not found: {source}"
        )
        return False

    destination = (
        Path("/usr/local/bin")
        / command_name
    )

    run(
        f"sudo ln -sf "
        f"'{source}' "
        f"'{destination}'"
    )

    return destination.exists() or destination.is_symlink()


###############################################################################
# APT Installation
###############################################################################


def install_apt_packages() -> bool:
    """
    Install all canonical APT-backed dependencies.
    """

    info(
        "Installing APT packages..."
    )

    if not run(
        "sudo apt update -y"
    ):
        return False

    return run(
        "sudo apt install -y "
        + " ".join(APT_PACKAGES)
    )


###############################################################################
# Go Installation
###############################################################################


def install_go_tools() -> None:
    """
    Install canonical Go-based tools.
    """

    if not shutil.which(
        "go"
    ):
        err(
            "Go is not installed."
        )
        return

    for tool_name, module in GO_TOOLS:

        stage(
            f"Installing {tool_name} (Go)",
            "cyan",
        )

        run(
            f"go install -v {module}"
        )

        binary = (
            go_bin_path()
            / tool_name
        )

        if binary.exists():
            install_symlink(
                binary,
                tool_name,
            )
        else:
            warn(
                f"{tool_name} was not found in {go_bin_path()}"
            )


###############################################################################
# Dalfox Installation
###############################################################################


def install_dalfox() -> None:
    """
    Install Dalfox using Cargo.
    """

    stage(
        "Installing Dalfox",
        "cyan",
    )

    if not shutil.which(
        "cargo"
    ):
        err(
            "Cargo is not installed."
        )
        return

    run(
        DALFOX_INSTALL
    )

    binary = (
        cargo_bin_path()
        / "dalfox"
    )

    if binary.exists():
        install_symlink(
            binary,
            "dalfox",
        )
    else:
        warn(
            f"Dalfox was not found in {cargo_bin_path()}"
        )

    check_path_for_cargo_bin()


###############################################################################
# Subhunt Installation
###############################################################################


def install_subhunt_from_git() -> None:
    """
    Build and install ScopeForgeX's native Subhunt tool.
    """

    stage(
        "Installing Subhunt",
        "cyan",
    )

    SOURCE_TOOLS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    repo_dir = (
        SOURCE_TOOLS_DIR
        / "subhunt"
    )

    if repo_dir.exists():
        warn(
            "Subhunt repository already exists. Pulling latest changes..."
        )

        run(
            f"cd '{repo_dir}' && git pull"
        )

    else:
        info(
            "Cloning Subhunt repository..."
        )

        run(
            f"cd '{SOURCE_TOOLS_DIR}' && "
            f"git clone '{SUBHUNT_REPO}'"
        )

    build_path = (
        repo_dir
        / "cmd"
        / "subhunt"
    )

    if not build_path.exists():
        err(
            f"Subhunt build path not found: {build_path}"
        )
        return

    info(
        "Building Subhunt..."
    )

    run(
        f"cd '{repo_dir}' && "
        "go build -o subhunt ./cmd/subhunt"
    )

    binary = (
        repo_dir
        / "subhunt"
    )

    if not binary.exists():
        err(
            "Subhunt build failed."
        )
        return

    install_symlink(
        binary,
        "subhunt",
    )

    if is_tool_installed(
        "subhunt"
    ):
        ok(
            "Subhunt installed successfully."
        )
    else:
        warn(
            "Subhunt is not currently visible in PATH."
        )


###############################################################################
# Kiterunner Installation
###############################################################################


def install_kiterunner() -> None:
    """
    Build and install Kiterunner from source.

    The canonical executable name is `kr`.
    """

    stage(
        "Installing Kiterunner",
        "cyan",
    )

    SOURCE_TOOLS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    repo_dir = (
        SOURCE_TOOLS_DIR
        / "kiterunner"
    )

    if repo_dir.exists():
        warn(
            "Kiterunner repository already exists. Pulling latest changes..."
        )

        run(
            f"cd '{repo_dir}' && git pull"
        )

    else:
        info(
            "Cloning Kiterunner repository..."
        )

        run(
            f"cd '{SOURCE_TOOLS_DIR}' && "
            f"git clone '{KITERUNNER_REPO}'"
        )

    if not (
        repo_dir
        / "Makefile"
    ).exists():
        err(
            f"Kiterunner Makefile not found: {repo_dir}"
        )
        return

    info(
        "Building Kiterunner..."
    )

    run(
        f"cd '{repo_dir}' && "
        "make build"
    )

    binary = (
        repo_dir
        / "dist"
        / "kr"
    )

    if not binary.exists():
        err(
            f"Kiterunner binary not found: {binary}"
        )
        return

    install_symlink(
        binary,
        "kr",
    )

    if is_tool_installed(
        "kr"
    ):
        ok(
            "Kiterunner installed successfully."
        )
    else:
        warn(
            "Kiterunner is not currently visible in PATH."
        )


###############################################################################
# JWT Tool Installation
###############################################################################


def install_jwt_tool() -> bool:
    """
    Install JWT Tool from its upstream repository.

    JWT Tool is a Python application. ScopeForgeX keeps its Python
    dependencies isolated in a dedicated virtual environment so the
    installer does not modify Kali's system Python environment.
    """

    stage(
        "Installing JWT Tool",
        "cyan",
    )

    SOURCE_TOOLS_DIR.mkdir(
        parents=True,
        exist_ok=True,
    )

    repo_dir = (
        SOURCE_TOOLS_DIR
        / "jwt_tool"
    )

    if repo_dir.exists():
        warn(
            "JWT Tool repository already exists. Pulling latest changes..."
        )

        if not run(
            f"cd '{repo_dir}' && git pull"
        ):
            return False

    else:
        info(
            "Cloning JWT Tool repository..."
        )

        if not run(
            f"cd '{SOURCE_TOOLS_DIR}' && "
            f"git clone '{JWT_TOOL_REPO}' jwt_tool"
        ):
            return False

    script = (
        repo_dir
        / "jwt_tool.py"
    )

    if not script.exists():
        err(
            f"JWT Tool script not found: {script}"
        )
        return False

    requirements = (
        repo_dir
        / "requirements.txt"
    )

    venv_dir = (
        repo_dir
        / ".venv"
    )

    venv_python = (
        venv_dir
        / "bin"
        / "python"
    )

    info(
        "Preparing isolated JWT Tool Python environment..."
    )

    if not venv_python.exists():
        if not run(
            f"python3 -m venv '{venv_dir}'"
        ):
            err(
                "Failed to create JWT Tool virtual environment."
            )
            return False

    if requirements.exists():
        info(
            "Installing JWT Tool Python dependencies into its virtual "
            "environment..."
        )

        if not run(
            f"'{venv_python}' -m pip install "
            f"-r '{requirements}'"
        ):
            err(
                "JWT Tool Python dependency installation failed."
            )
            return False

    else:
        if not run(
            f"'{venv_python}' -m pip install "
            "termcolor cprint pycryptodomex requests ratelimit"
        ):
            err(
                "JWT Tool fallback dependency installation failed."
            )
            return False

    wrapper = (
        repo_dir
        / "jwt_tool"
    )

    wrapper.write_text(
        "#!/bin/sh\n"
        f'exec "{venv_python}" "{script}" "$@"\n',
        encoding="utf-8",
    )

    wrapper.chmod(
        0o755
    )

    install_symlink(
        wrapper,
        "jwt_tool",
    )

    installed_path = installed_tool_path("jwt_tool")

    if installed_path is None:
        err(
            "JWT Tool wrapper is not visible in PATH after installation."
        )
        return False

    if not run(
        f"'{installed_path}' --help "
        "> /dev/null"
    ):
        err(
            "JWT Tool was installed but the canonical jwt_tool command "
            "failed runtime validation."
        )
        return False

    if is_tool_installed(
        "jwt_tool"
    ):
        ok(
            "JWT Tool installed successfully with an isolated Python "
            "environment."
        )
        return True

    warn(
        "JWT Tool is not currently visible in PATH."
    )
    return False


###############################################################################
# Main Installation

###############################################################################


def install_tools() -> None:
    """
    Install and verify all canonical ScopeForgeX tools.
    """

    stage(
        "ScopeForgeX Tool Installer",
        "green",
    )

    if (
        platform.system().lower()
        != "linux"
        or detect_pkg_manager()
        != "apt"
    ):
        warn(
            "Automatic installation currently supports "
            "Linux (APT) only."
        )
        warn(
            "Install missing tools manually and rerun this installer."
        )
        return

    info(
        "Installing base dependencies..."
    )

    run(
        "sudo apt update -y"
    )

    run(
        "sudo apt install -y "
        "python3 "
        "python3-pip "
        "python3-venv "
        "golang "
        "git "
        "build-essential "
        "cargo"
    )

    install_apt_packages()

    install_go_tools()

    check_path_for_go_bin()

    install_dalfox()

    install_subhunt_from_git()

    install_kiterunner()

    install_jwt_tool()

    info(
        f"Verifying canonical {len(REQUIRED_TOOLS)}-tool installation..."
    )

    missing, resolved = verify_required_tools()

    for tool_name in REQUIRED_TOOLS:
        executable = resolve_tool_executable(tool_name)
        path = resolved.get(tool_name)
        if path:
            ok(
                f"{tool_name} -> {executable} -> {path}"
            )
        else:
            warn(
                f"{tool_name} -> {executable} -> MISSING"
            )

    missing_wordlists = verify_wordlists()

    if not missing and not missing_wordlists:
        ok(
            f"All {len(REQUIRED_TOOLS)} canonical ScopeForgeX tools "
            "and required wordlists are installed and detected."
        )
        return

    if missing:
        err(
            f"{len(missing)} of {len(REQUIRED_TOOLS)} canonical "
            "ScopeForgeX tools are still missing:"
        )
        for tool in missing:
            warn(
                f"- {tool} (executable: {resolve_tool_executable(tool)})"
            )

    if missing_wordlists:
        err(
            "Required wordlists are missing:"
        )
        for wordlist in missing_wordlists:
            warn(
                f"- {wordlist}"
            )

    check_path_for_go_bin()
    check_path_for_cargo_bin()
    warn(
        "Run the installer again after correcting the "
        "missing dependencies, wordlists, or PATH entries."
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "TOOL_EXECUTABLES",
    "REQUIRED_TOOLS",
    "APT_PACKAGES",
    "GO_TOOLS",
    "resolve_tool_executable",
    "installed_tool_path",
    "verify_required_tools",
    "verify_wordlists",
    "install_tools",
    "install_go_tools",
    "install_dalfox",
    "install_subhunt_from_git",
    "install_kiterunner",
    "install_jwt_tool",
]

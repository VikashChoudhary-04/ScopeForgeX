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
    - nuclei
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

from scopeforgex.toolcheck import is_tool_installed
from scopeforgex.ui import err, info, ok, stage, warn


###############################################################################
# Canonical Tool Sources
###############################################################################


REQUIRED_TOOLS = [
    "amass",
    "subhunt",
    "nmap",
    "dig",
    "httpx",
    "katana",
    "ffuf",
    "whatweb",
    "kiterunner",
    "jsluice",
    "nuclei",
    "nikto",
    "testssl.sh",
    "sqlmap",
    "dalfox",
    "jwt_tool",
    "sstimap",
    "hydra",
    "hashcat",
]


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
        "nuclei",
        "github.com/projectdiscovery/nuclei/v3/cmd/nuclei@latest",
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
) -> None:
    """
    Execute a shell command and display it.

    Installer commands are generated internally from fixed repository/package
    constants rather than untrusted user input.
    """

    info(
        f"$ {command}"
    )

    subprocess.run(
        command,
        shell=True,
        check=False,
    )


def detect_pkg_manager() -> str | None:
    """
    Detect the available supported package manager.
    """

    if shutil.which(
        "apt"
    ):
        return "apt"

    return None


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


def install_apt_packages() -> None:
    """
    Install all canonical APT-backed dependencies.
    """

    info(
        "Installing APT packages..."
    )

    run(
        "sudo apt update -y"
    )

    run(
        "sudo apt install -y "
        + " ".join(
            APT_PACKAGES
        )
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


def install_jwt_tool() -> None:
    """
    Install JWT Tool from its upstream repository.

    JWT Tool is a Python script, so ScopeForgeX exposes it through the
    canonical `jwt_tool` command.
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

        run(
            f"cd '{repo_dir}' && git pull"
        )

    else:
        info(
            "Cloning JWT Tool repository..."
        )

        run(
            f"cd '{SOURCE_TOOLS_DIR}' && "
            f"git clone '{JWT_TOOL_REPO}' jwt_tool"
        )

    script = (
        repo_dir
        / "jwt_tool.py"
    )

    if not script.exists():
        err(
            f"JWT Tool script not found: {script}"
        )
        return

    info(
        "Installing JWT Tool Python dependencies..."
    )

    requirements = (
        repo_dir
        / "requirements.txt"
    )

    if requirements.exists():
        run(
            f"python3 -m pip install "
            f"-r '{requirements}'"
        )
    else:
        run(
            "python3 -m pip install "
            "termcolor cprint pycryptodomex requests"
        )

    wrapper = (
        SOURCE_TOOLS_DIR
        / "jwt_tool"
        / "jwt_tool"
    )

    wrapper.write_text(
        "#!/bin/sh\n"
        f'exec python3 "{script}" "$@"\n',
        encoding="utf-8",
    )

    wrapper.chmod(
        0o755
    )

    install_symlink(
        wrapper,
        "jwt_tool",
    )

    if is_tool_installed(
        "jwt_tool"
    ):
        ok(
            "JWT Tool installed successfully."
        )
    else:
        warn(
            "JWT Tool is not currently visible in PATH."
        )


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
        "Verifying canonical 19-tool installation..."
    )

    missing = [
        tool
        for tool in REQUIRED_TOOLS
        if not is_tool_installed(
            tool
        )
    ]

    if not missing:
        ok(
            "All 19 canonical ScopeForgeX tools "
            "are installed and detected."
        )
        return

    err(
        "Some canonical ScopeForgeX tools are still missing:"
    )

    for tool in missing:
        warn(
            f"- {tool}"
        )

    check_path_for_go_bin()
    check_path_for_cargo_bin()

    warn(
        "Run the installer again after correcting the "
        "missing dependencies or PATH entries."
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "REQUIRED_TOOLS",
    "APT_PACKAGES",
    "GO_TOOLS",
    "install_tools",
    "install_go_tools",
    "install_dalfox",
    "install_subhunt_from_git",
    "install_kiterunner",
    "install_jwt_tool",
]

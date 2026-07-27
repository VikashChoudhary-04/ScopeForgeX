"""
ScopeForgeX Stage 1 - Network Recon Tools
=========================================

Network reconnaissance implementations.

Tools:
    • Naabu
    • RustScan
    • Nmap

v0.5.0
"""

from __future__ import annotations

import xml.etree.ElementTree as ET
from pathlib import Path

from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolBase
from scopeforgex.runner import run_command
from scopeforgex.toolcheck import is_tool_installed


###############################################################################
# Constants
###############################################################################

HTTP_PORTS = {
    80: "http",
    81: "http",
    88: "http",
    443: "https",
    444: "https",
    591: "https",
    593: "https",
    8000: "http",
    8008: "http",
    8080: "http",
    8081: "http",
    8088: "http",
    8443: "https",
    8888: "http",
}


###############################################################################
# Helpers
###############################################################################


def _network_only(
    tool_name: str,
    ctx: dict,
) -> ExecutionResult | None:
    """
    Skip execution unless the workflow target is a network target.
    """

    if ctx.get("target_type") == "network":
        return None

    return ExecutionResult.skipped(
        tool=tool_name,
        capability="network_recon",
        reason="Skipped (web/domain target)",
    )


def _recon_dir(
    ctx: dict,
) -> Path:
    """
    Return the recon output directory.
    """

    directory = Path(
        ctx["outdir"]
    ) / "recon"

    directory.mkdir(
        parents=True,
        exist_ok=True,
    )

    return directory


def _tool_missing(
    tool_name: str,
) -> ExecutionResult | None:
    """
    Return an ExecutionResult if the executable is unavailable.
    """

    if is_tool_installed(tool_name):
        return None

    return ExecutionResult.failure(
        tool=tool_name,
        capability="network_recon",
        error=f"{tool_name} not installed",
    )


def _extract_web_targets(
    xml_file: str,
) -> list[str]:
    """
    Parse an Nmap XML report and extract HTTP/HTTPS endpoints.
    """

    xml_path = Path(
        xml_file
    )

    if not xml_path.exists():
        return []

    try:

        root = ET.parse(
            xml_path
        ).getroot()

    except ET.ParseError:

        return []

    discovered: set[str] = set()

    for host in root.findall("host"):

        status = host.find(
            "status"
        )

        if (
            status is None
            or status.attrib.get("state") != "up"
        ):
            continue

        address = host.find(
            "address"
        )

        if address is None:
            continue

        host_ip = address.attrib.get(
            "addr"
        )

        if not host_ip:
            continue

        ports = host.find(
            "ports"
        )

        if ports is None:
            continue

        for port in ports.findall("port"):

            state = port.find(
                "state"
            )

            if (
                state is None
                or state.attrib.get("state") != "open"
            ):
                continue

            try:

                port_id = int(
                    port.attrib.get(
                        "portid",
                        "0",
                    )
                )

            except ValueError:

                continue

            service = port.find(
                "service"
            )

            service_name = ""

            if service is not None:

                service_name = service.attrib.get(
                    "name",
                    "",
                ).lower()

            if "https" in service_name:

                scheme = "https"

            elif "http" in service_name:

                scheme = "http"

            else:

                scheme = HTTP_PORTS.get(
                    port_id
                )

            if scheme is None:
                continue

            if (
                (scheme == "http" and port_id == 80)
                or
                (scheme == "https" and port_id == 443)
            ):

                discovered.add(
                    f"{scheme}://{host_ip}"
                )

            else:

                discovered.add(
                    f"{scheme}://{host_ip}:{port_id}"
                )

    return sorted(
        discovered
    )


###############################################################################
# Naabu
###############################################################################


class NaabuTool(ToolBase):

    name = "naabu"
    stage = 1
    description = "Fast port discovery (network targets only)"
    risk = "low"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        skipped = _network_only(
            self.name,
            ctx,
        )

        if skipped:
            return skipped

        missing = _tool_missing(
            self.name,
        )

        if missing:
            return missing

        recon = _recon_dir(
            ctx
        )

        log = recon / "naabu.log"

        return run_command(
            tool=self.name,
            capability="port_discovery",
            cmd=(
                f"naabu "
                f"-host {ctx['target']} "
                f"-top-ports 1000 "
                f"-silent"
            ),
            outfile=str(log),
        )


###############################################################################
# RustScan
###############################################################################


class RustscanTool(ToolBase):

    name = "rustscan"
    stage = 1
    description = "Fast port scan (network targets only)"
    risk = "low"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        skipped = _network_only(
            self.name,
            ctx,
        )

        if skipped:
            return skipped

        missing = _tool_missing(
            self.name,
        )

        if missing:
            return missing

        recon = _recon_dir(
            ctx
        )

        log = recon / "rustscan.log"

        return run_command(
            tool=self.name,
            capability="port_scanning",
            cmd=(
                f"rustscan "
                f"-a {ctx['target']} "
                f"--ulimit 5000 "
                f"-- -sV"
            ),
            outfile=str(log),
        )


###############################################################################
# Nmap
###############################################################################


class NmapTool(ToolBase):

    name = "nmap"
    stage = 1
    description = "Nmap service enumeration (network targets only)"
    risk = "low"

    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:

        skipped = _network_only(
            self.name,
            ctx,
        )

        if skipped:
            return skipped

        missing = _tool_missing(
            self.name,
        )

        if missing:
            return missing

        recon = _recon_dir(
            ctx
        )

        log = recon / "nmap.log"
        xml = recon / "nmap.xml"
        hosts_raw = recon / "hosts_raw.txt"

        command = (
            f"nmap "
            f"-Pn "
            f"-sC "
            f"-sV "
            f"-oX {xml} "
            f"{ctx['target']}"
        )

        result = run_command(
            tool=self.name,
            capability="service_enumeration",
            cmd=command,
            outfile=str(log),
        )

        targets = _extract_web_targets(
            str(xml)
        )

        with hosts_raw.open(
            "w",
            encoding="utf-8",
        ) as outfile:

            for target in targets:

                outfile.write(
                    target + "\n"
                )

        result.add_artifact(
            xml
        )

        result.add_artifact(
            hosts_raw
        )

        result.metadata.update(
            {
                "web_endpoints_discovered": len(targets),
            }
        )

        return result


###############################################################################
# Registry Export
###############################################################################


ALL_STAGE1_NET_TOOLS = [
    NaabuTool(),
    RustscanTool(),
    NmapTool(),
]

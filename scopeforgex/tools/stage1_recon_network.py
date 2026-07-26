import os
import xml.etree.ElementTree as ET

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.runner import run_cmd
from scopeforgex.toolcheck import is_tool_installed


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


def _extract_web_targets(xml_file: str) -> list[str]:
    """
    Parse Nmap XML and extract HTTP/HTTPS endpoints.
    """

    if not os.path.exists(xml_file):
        return []

    try:
        tree = ET.parse(xml_file)
    except Exception:
        return []

    root = tree.getroot()

    targets = []

    for host in root.findall("host"):

        status = host.find("status")
        if status is None or status.attrib.get("state") != "up":
            continue

        addr = host.find("address")
        if addr is None:
            continue

        host_ip = addr.attrib.get("addr")
        if not host_ip:
            continue

        ports = host.find("ports")
        if ports is None:
            continue

        for port in ports.findall("port"):

            state = port.find("state")
            if state is None or state.attrib.get("state") != "open":
                continue

            portid = int(port.attrib.get("portid", "0"))

            service = port.find("service")
            svc = ""

            if service is not None:
                svc = service.attrib.get("name", "").lower()

            scheme = None

            if "https" in svc:
                scheme = "https"
            elif "http" in svc:
                scheme = "http"
            elif portid in HTTP_PORTS:
                scheme = HTTP_PORTS[portid]

            if scheme is None:
                continue

            default = (
                (scheme == "http" and portid == 80)
                or
                (scheme == "https" and portid == 443)
            )

            if default:
                targets.append(f"{scheme}://{host_ip}")
            else:
                targets.append(f"{scheme}://{host_ip}:{portid}")

    return sorted(set(targets))


class NaabuTool(ToolBase):

    name = "naabu"
    stage = 1
    description = "Fast port discovery (network targets only)"
    risk = "low"

    def run(self, ctx: dict) -> ToolResult:

        if ctx.get("target_type") != "network":
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped (web/domain target)"
            )

        recon = os.path.join(ctx["outdir"], "recon")
        os.makedirs(recon, exist_ok=True)

        log = os.path.join(recon, "naabu.log")

        if not is_tool_installed("naabu"):
            return ToolResult(
                self.name,
                False,
                [],
                "naabu not installed"
            )

        run_cmd(
            f"naabu -host {ctx['target']} -top-ports 1000 -silent",
            outfile=log
        )

        return ToolResult(
            self.name,
            True,
            [log],
            "naabu completed"
        )


class RustscanTool(ToolBase):

    name = "rustscan"
    stage = 1
    description = "Fast port scan (network targets only)"
    risk = "low"

    def run(self, ctx: dict):

        if ctx.get("target_type") != "network":
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped (web/domain target)"
            )

        recon = os.path.join(ctx["outdir"], "recon")
        os.makedirs(recon, exist_ok=True)

        log = os.path.join(recon, "rustscan.log")

        if not is_tool_installed("rustscan"):
            return ToolResult(
                self.name,
                False,
                [],
                "rustscan not installed"
            )

        run_cmd(
            f"rustscan -a {ctx['target']} --ulimit 5000 -- -sV",
            outfile=log
        )

        return ToolResult(
            self.name,
            True,
            [log],
            "rustscan completed"
        )


class NmapTool(ToolBase):

    name = "nmap"
    stage = 1
    description = "Nmap service enumeration (network targets only)"
    risk = "low"

    def run(self, ctx: dict):

        if ctx.get("target_type") != "network":
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped (web/domain target)"
            )

        recon = os.path.join(ctx["outdir"], "recon")
        os.makedirs(recon, exist_ok=True)

        log = os.path.join(recon, "nmap.log")
        xml = os.path.join(recon, "nmap.xml")
        hosts_raw = os.path.join(recon, "hosts_raw.txt")

        if not is_tool_installed("nmap"):
            return ToolResult(
                self.name,
                False,
                [],
                "nmap not installed"
            )

        cmd = (
            f"nmap "
            f"-Pn "
            f"-sC "
            f"-sV "
            f"-oX {xml} "
            f"{ctx['target']}"
        )

        run_cmd(cmd, outfile=log)

        targets = _extract_web_targets(xml)

        with open(hosts_raw, "w", encoding="utf-8") as f:
            for target in targets:
                f.write(target + "\n")

        notes = (
            f"nmap completed. "
            f"Discovered {len(targets)} web endpoint(s)."
        )

        return ToolResult(
            self.name,
            True,
            [
                log,
                xml,
                hosts_raw,
            ],
            notes,
        )


ALL_STAGE1_NET_TOOLS = [
    NaabuTool(),
    RustscanTool(),
    NmapTool(),
]

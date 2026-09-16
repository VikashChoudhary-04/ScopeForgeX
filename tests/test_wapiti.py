import json
from pathlib import Path
from types import SimpleNamespace

from scopeforgex.collectors.wapiti import WapitiCollector
from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage3_vuln import WapitiTool


def test_wapiti_builds_bounded_json_command(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="https://example.com/",
            output_dir=tmp_path,
            options={
                "scope": "domain",
                "max_scan_time": 540,
                "max_attack_time": 480,
                "max_links_per_page": 100,
                "max_files_per_dir": 50,
                "max_parameters": 50,
                "timeout": 10,
            },
        )
    )

    arguments = tool.build_arguments()

    assert "-u" in arguments
    assert "https://example.com/" in arguments
    assert "--scope" in arguments
    assert "domain" in arguments
    assert "--max-scan-time" in arguments
    assert "540" in arguments
    assert "--max-attack-time" in arguments
    assert "480" in arguments
    assert "-f" in arguments
    assert "json" in arguments


def test_wapiti_rejects_attack_budget_above_scan_budget(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="https://example.com/",
            output_dir=tmp_path,
            options={
                "max_scan_time": 300,
                "max_attack_time": 301,
            },
        )
    )

    try:
        tool.build_arguments()
    except ValueError as exc:
        assert "max_attack_time" in str(exc)
    else:
        raise AssertionError("Expected invalid Wapiti time budget.")


def test_wapiti_accepts_bare_hostname(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="warrantyindia.com",
            output_dir=tmp_path,
        )
    )

    arguments = tool.build_arguments()

    assert arguments[0:2] == ["-u", "http://warrantyindia.com"]


def test_wapiti_accepts_bare_host_and_port(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="localhost:3000",
            output_dir=tmp_path,
        )
    )

    arguments = tool.build_arguments()

    assert arguments[0:2] == ["-u", "http://localhost:3000"]


def test_wapiti_preserves_https_target(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="https://warrantyindia.com/",
            output_dir=tmp_path,
        )
    )

    arguments = tool.build_arguments()

    assert arguments[0:2] == ["-u", "https://warrantyindia.com/"]


def test_wapiti_preserves_http_target(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="http://localhost:3000/",
            output_dir=tmp_path,
        )
    )

    arguments = tool.build_arguments()

    assert arguments[0:2] == ["-u", "http://localhost:3000/"]


def test_wapiti_rejects_empty_target(tmp_path: Path):
    tool = WapitiTool(
        ToolContext(
            target="   ",
            output_dir=tmp_path,
        )
    )

    try:
        tool.build_arguments()
    except ValueError as exc:
        assert "target URL" in str(exc)
    else:
        raise AssertionError("Expected empty target validation failure.")


def test_wapiti_collector_parses_json(tmp_path: Path):
    report = tmp_path / "wapiti_report.json"

    report.write_text(
        json.dumps(
            {
                "classifications": {},
                "vulnerabilities": {
                    "Clickjacking Protection": [
                        {
                            "method": "GET",
                            "path": "/",
                            "info": "X-Frame-Options is not set",
                            "level": 1,
                            "parameter": None,
                            "referer": "",
                            "module": "http_headers",
                            "http_request": "GET / HTTP/1.1",
                            "curl_command": 'curl "https://example.com/"',
                            "wstg": ["WSTG-CONF-07"],
                        }
                    ]
                },
                "anomalies": {},
                "additionals": {},
                "infos": {},
                "suppressed_findings": {},
            }
        ),
        encoding="utf-8",
    )

    execution = SimpleNamespace(
        success=True,
        artifacts=[report],
        metadata={},
    )

    collector = WapitiCollector()

    observations = collector.parse(
        execution,
        {"target": "https://example.com/"},
    )

    assert len(observations) == 1
    assert observations[0].title == "Clickjacking Protection"
    assert observations[0].severity == "low"
    assert observations[0].url == "https://example.com/"
    assert observations[0].evidence["module"] == "http_headers"


def test_wapiti_collector_ignores_failed_execution(tmp_path: Path):
    collector = WapitiCollector()

    execution = SimpleNamespace(
        success=False,
        artifacts=[],
        metadata={},
    )

    assert collector.parse(
        execution,
        {"target": "https://example.com/"},
    ) == []

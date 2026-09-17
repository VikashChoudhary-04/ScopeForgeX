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

def test_wapiti_collector_maps_all_severity_levels():
    collector = WapitiCollector()

    expected = {
        0: "informational",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
        None: "informational",
        "invalid": "informational",
        99: "informational",
    }

    for value, severity in expected.items():
        assert collector._severity(value) == severity


def test_wapiti_collector_parses_all_finding_sections(tmp_path: Path):
    report = tmp_path / "wapiti_report.json"

    report.write_text(
        json.dumps(
            {
                "classifications": {},
                "vulnerabilities": {
                    "Vulnerability Finding": [
                        {
                            "method": "GET",
                            "path": "/vuln",
                            "info": "Vulnerability finding",
                            "level": 2,
                            "module": "module_v",
                        }
                    ]
                },
                "anomalies": {
                    "Anomaly Finding": [
                        {
                            "method": "GET",
                            "path": "/anomaly",
                            "info": "Anomaly finding",
                            "level": 1,
                            "module": "module_a",
                        }
                    ]
                },
                "additionals": {
                    "Additional Finding": [
                        {
                            "method": "GET",
                            "path": "/additional",
                            "info": "Additional finding",
                            "level": 0,
                            "module": "module_i",
                        }
                    ]
                },
            }
        ),
        encoding="utf-8",
    )

    execution = SimpleNamespace(
        success=True,
        artifacts=[report],
        metadata={},
    )

    observations = WapitiCollector().parse(
        execution,
        {"target": "https://example.com/"},
    )

    assert len(observations) == 3

    by_title = {observation.title: observation for observation in observations}

    assert by_title["Vulnerability Finding"].observation_type == "VULNERABILITY"
    assert by_title["Vulnerability Finding"].severity == "medium"

    assert by_title["Anomaly Finding"].observation_type == "SECURITY_ISSUE"
    assert by_title["Anomaly Finding"].severity == "low"

    assert by_title["Additional Finding"].observation_type == "MISCONFIGURATION"
    assert by_title["Additional Finding"].severity == "informational"


def test_wapiti_collector_extracts_cve_and_cwe():
    record = {
        "method": "GET",
        "path": "/",
        "info": "CVE-2020-1234 and CWE-79 detected",
        "level": 3,
        "module": "test",
    }

    observation = WapitiCollector()._normalize_record(
        category="CVE-2020-1234 / CWE-79",
        record=record,
        observation_type="VULNERABILITY",
        target="https://example.com/",
    )

    assert observation is not None
    assert observation.cve == "CVE-2020-1234"
    assert observation.cwe == "CWE-79"


def test_wapiti_collector_preserves_scanner_evidence_contract():
    record = {
        "method": "GET",
        "path": "/admin",
        "info": "Test Wapiti finding",
        "level": 2,
        "parameter": "id",
        "referer": "https://example.com/",
        "module": "http_headers",
        "http_request": "GET /admin HTTP/1.1",
        "curl_command": 'curl "https://example.com/admin"',
        "wstg": ["WSTG-CONF-01"],
        "custom_field": "preserved-by-raw-record",
    }

    observation = WapitiCollector()._normalize_record(
        category="Test Finding",
        record=record,
        observation_type="VULNERABILITY",
        target="https://example.com/",
    )

    assert observation is not None

    evidence = observation.evidence

    assert evidence["module"] == "http_headers"
    assert evidence["method"] == "GET"
    assert evidence["path"] == "/admin"
    assert evidence["parameter"] == "id"
    assert evidence["referer"] == "https://example.com/"
    assert evidence["http_request"] == "GET /admin HTTP/1.1"
    assert evidence["curl_command"] == 'curl "https://example.com/admin"'
    assert evidence["wstg"] == ["WSTG-CONF-01"]
    assert evidence["category"] == "Test Finding"

    assert evidence["raw_record"] is record
    assert evidence["raw_record"]["custom_field"] == "preserved-by-raw-record"


def test_wapiti_collector_deduplicates_identical_observations(tmp_path: Path):
    report = tmp_path / "wapiti_report.json"

    duplicate = {
        "method": "GET",
        "path": "/",
        "info": "Duplicate finding",
        "level": 1,
        "parameter": None,
        "module": "test",
    }

    report.write_text(
        json.dumps(
            {
                "vulnerabilities": {
                    "Duplicate Finding": [
                        duplicate,
                        dict(duplicate),
                    ]
                },
                "anomalies": {},
                "additionals": {},
            }
        ),
        encoding="utf-8",
    )

    execution = SimpleNamespace(
        success=True,
        artifacts=[report],
        metadata={},
    )

    observations = WapitiCollector().parse(
        execution,
        {"target": "https://example.com/"},
    )

    assert len(observations) == 1
    assert observations[0].title == "Duplicate Finding"


def test_wapiti_collector_ignores_malformed_records_and_sections(tmp_path: Path):
    report = tmp_path / "wapiti_report.json"

    report.write_text(
        json.dumps(
            {
                "vulnerabilities": {
                    "Valid Finding": [
                        "not-a-record",
                        None,
                        {
                            "method": "GET",
                            "path": "/",
                            "info": "Valid finding",
                            "level": 1,
                        },
                    ],
                    "Invalid Records": "not-a-list",
                },
                "anomalies": "not-a-dict",
                "additionals": [],
            }
        ),
        encoding="utf-8",
    )

    execution = SimpleNamespace(
        success=True,
        artifacts=[report],
        metadata={},
    )

    observations = WapitiCollector().parse(
        execution,
        {"target": "https://example.com/"},
    )

    assert len(observations) == 1
    assert observations[0].title == "Valid Finding"


def test_wapiti_collector_ignores_invalid_json(tmp_path: Path):
    report = tmp_path / "wapiti_report.json"
    report.write_text("{invalid json", encoding="utf-8")

    execution = SimpleNamespace(
        success=True,
        artifacts=[report],
        metadata={},
    )

    assert WapitiCollector().parse(
        execution,
        {"target": "https://example.com/"},
    ) == []


def test_wapiti_collector_accepts_output_file_from_metadata(tmp_path: Path):
    report = tmp_path / "wapiti_report.json"

    report.write_text(
        json.dumps(
            {
                "vulnerabilities": {
                    "Metadata Report": [
                        {
                            "method": "GET",
                            "path": "/",
                            "info": "Metadata report finding",
                            "level": 1,
                        }
                    ]
                }
            }
        ),
        encoding="utf-8",
    )

    execution = SimpleNamespace(
        success=True,
        artifacts=[],
        metadata={"output_file": str(report)},
    )

    observations = WapitiCollector().parse(
        execution,
        {"target": "https://example.com/"},
    )

    assert len(observations) == 1
    assert observations[0].title == "Metadata Report"

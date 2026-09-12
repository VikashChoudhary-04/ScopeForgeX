from pathlib import Path
from types import SimpleNamespace

from scopeforgex.collectors.nikto import NiktoCollector
from scopeforgex.collectors.testssl import TestSSLCollector as _TestSSLCollector
from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage3_vuln import TestSSLTool as _TestSSLTool


def test_testssl_builder_does_not_emit_unsupported_socket_timeout():
    tool = _TestSSLTool(
        ToolContext(
            target="warrantyindia.com",
            output_dir=Path("/tmp/scopeforgex-test"),
            options={
                "openssl_timeout": 10,
            },
        )
    )

    arguments = tool.build_arguments()

    assert "--socket-timeout" not in arguments
    assert "--openssl-timeout" in arguments
    assert "10" in arguments


def test_testssl_failed_execution_produces_no_observations():
    collector = _TestSSLCollector()

    execution = SimpleNamespace(
        success=False,
        exit_code=1,
        stdout="testssl.sh: unrecognized option '--socket-timeout'",
        artifacts=[],
    )

    observations = collector.parse(
        execution,
        {"target": "warrantyindia.com"},
    )

    assert observations == []


def test_testssl_help_error_text_is_not_classified_as_tls_finding():
    collector = _TestSSLCollector()

    lines = [
        "testssl.sh: unrecognized option '--socket-timeout'",
        "Usage: testssl.sh [options] target",
        "Error: unknown option --socket-timeout",
        "TLS protocol and certificate configuration options:",
    ]

    for line in lines:
        assert collector._parse_text_record(line) == []


def test_testssl_legitimate_tls_text_remains_parseable():
    collector = _TestSSLCollector()

    parsed = collector._parse_text_record(
        "HTTP Strict Transport Security (HSTS): NOT offered"
    )

    assert parsed
    assert parsed[0]["observation_type"] == "TLS_CONFIGURATION"


def test_nikto_reference_url_does_not_become_affected_asset():
    collector = NiktoCollector()

    content = """
- Target Hostname: warrantyindia.com
- Target Port: 80
+ Missing X-Content-Type-Options header
  See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
"""

    records = collector._parse_plain_text(content)

    assert records
    assert records[0]["host"] == "warrantyindia.com"
    assert records[0].get("url") is None


def test_nikto_explicit_target_url_is_preserved():
    collector = NiktoCollector()

    content = """
- Target: http://warrantyindia.com/
+ Missing X-Content-Type-Options header
  See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/X-Content-Type-Options
"""

    records = collector._parse_plain_text(content)

    assert records
    assert records[0]["url"] == "http://warrantyindia.com/"


def test_nikto_description_reference_url_is_not_affected_asset():
    collector = NiktoCollector()

    record = {
        "description": (
            "Missing X-Content-Type-Options header. "
            "See: https://developer.mozilla.org/en-US/docs/Web/HTTP/Headers/"
            "X-Content-Type-Options"
        ),
        "host": "warrantyindia.com",
    }

    normalized = collector._normalize_record(record)

    assert normalized is not None
    assert normalized["host"] == "warrantyindia.com"
    assert normalized["url"] is None

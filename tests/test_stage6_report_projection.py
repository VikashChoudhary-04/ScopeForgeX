from datetime import datetime, timezone
from pathlib import Path

from scopeforgex.stages.stage6_report_cleanup import (
    _report_state,
    _sanitize_report_payload,
)


_FORBIDDEN = {
    "body",
    "raw_body",
    "raw_header",
    "raw_headers",
    "request",
    "raw_request",
    "response",
    "raw_response",
}


def _walk_keys(value):
    if isinstance(value, dict):
        for key, item in value.items():
            yield str(key).lower()
            yield from _walk_keys(item)
    elif isinstance(value, list):
        for item in value:
            yield from _walk_keys(item)


def _paths_for_test():
    return {
        "professional_markdown": Path("/tmp/sfx-test-professional.md"),
        "professional_html": Path("/tmp/sfx-test-professional.html"),
        "findings_markdown": Path("/tmp/sfx-test-findings.md"),
        "findings_html": Path("/tmp/sfx-test-findings.html"),
        "canonical_json": Path("/tmp/sfx-test-report.json"),
    }


def _httpx_payload():
    return {
        "url": "https://example.test/",
        "status_code": 200,
        "content_type": "text/html",
        "content_length": 45340,
        "webserver": "nginx",
        "tech": ["Express"],
        "body": "<html>" + ("A" * 45300) + "</html>",
        "raw_body": "raw response body",
        "raw_header": "HTTP/1.1 200 OK",
        "raw_headers": "HTTP/1.1 200 OK\\nServer: nginx",
        "request": "GET / HTTP/1.1\\nHost: example.test",
        "raw_request": "GET / HTTP/1.1",
        "response": {
            "status_code": 200,
            "body": "nested response body",
        },
        "raw_response": {
            "body": "nested raw response body",
        },
    }


def test_report_payload_sanitizer_removes_raw_http_material_recursively():
    payload = {
        "finding": {
            "evidence": _httpx_payload(),
        },
        "nested": [
            {
                "BODY": "uppercase body",
                "metadata": {
                    "Request": "nested request",
                    "status_code": 200,
                },
            }
        ],
        "structured": {
            "url": "https://example.test/",
            "status_code": 200,
            "content_type": "text/html",
            "webserver": "nginx",
        },
    }

    original = payload.copy()
    sanitized = _sanitize_report_payload(payload)

    assert not (_FORBIDDEN & set(_walk_keys(sanitized)))

    assert sanitized["finding"]["evidence"]["url"] == (
        "https://example.test/"
    )
    assert sanitized["finding"]["evidence"]["status_code"] == 200
    assert sanitized["finding"]["evidence"]["content_length"] == 45340
    assert sanitized["finding"]["evidence"]["webserver"] == "nginx"
    assert sanitized["nested"][0]["metadata"]["status_code"] == 200

    # The sanitizer must not mutate runtime/source data.
    assert "body" in original["finding"]["evidence"]
    assert "request" in original["finding"]["evidence"]
    assert "response" in original["finding"]["evidence"]


def test_json_exporter_payload_contains_no_raw_http_material():
    from scopeforgex.stages.stage6_report_cleanup import (
        _report_data_from_state,
    )
    from reporting import JSONReportExporter

    now = datetime.now(timezone.utc)
    evidence = _httpx_payload()

    state = {
        "target": "https://example.test/",
        "profile": "fast",
        "target_type": "url",
        "run_id": "exporter-contract-test",
        "start_time": now,
        "end_time": now,
        "duration": 0.0,
        "statistics": {},
        "findings": [
            {
                "finding_id": "SF-HTTPX-EXPORT-001",
                "title": "WEB_SERVER",
                "category": "WEB_SERVER",
                "severity": "Informational",
                "confidence": "Informational",
                "target": "https://example.test/",
                "source_tool": "httpx",
                "detection_method": "httpx web server detection",
                "evidence": evidence,
            }
        ],
        "correlation_groups": [],
        "correlated_findings": [],
        "collector_results": [
            {
                "tool": "httpx",
                "observations": [
                    {
                        "observation_type": "HTTP_SERVICE",
                        "evidence": evidence,
                    }
                ],
            }
        ],
        "execution_results": [
            {
                "tool": "httpx",
                "status": "success",
                "findings": [{"evidence": evidence}],
            }
        ],
        "native_analyzer_results": [],
        "vulnerability_intelligence_results": [],
        "software_assessments": [],
        "stage_results": [],
        "evidence_references": [],
        "raw_evidence_references": [],
        "finding_evidence_references": [],
        "correlated_evidence_references": [],
        "generated_files": [],
        "warnings": [],
        "errors": [],
        "analysis_metadata": {},
        "summary": {},
        "vulnerability_intelligence": {},
        "report_views": {},
    }

    published_state = _sanitize_report_payload(state)
    report = _report_data_from_state(published_state)
    payload = JSONReportExporter(report).build_payload()

    violations = [
        key
        for key in _walk_keys(payload)
        if key in _FORBIDDEN
    ]

    assert violations == []

    finding_evidence = payload["findings"][0]["evidence"]

    assert finding_evidence["url"] == "https://example.test/"
    assert finding_evidence["status_code"] == 200
    assert finding_evidence["content_type"] == "text/html"
    assert finding_evidence["content_length"] == 45340
    assert finding_evidence["webserver"] == "nginx"


def test_stage6_report_state_can_be_projected_without_raw_http_material():
    now = datetime.now(timezone.utc)
    evidence = _httpx_payload()

    ctx = {
        "target": "https://example.test/",
        "profile": "fast",
        "target_type": "url",
        "workflow_start_time": now,
        "workflow_end_time": now,
        "statistics": {},
        "findings": [
            {
                "finding_id": "SF-HTTPX-001",
                "title": "WEB_SERVER",
                "category": "WEB_SERVER",
                "severity": "Informational",
                "confidence": "Informational",
                "target": "https://example.test/",
                "source_tool": "httpx",
                "detection_method": "httpx web server detection",
                "evidence": evidence,
            }
        ],
        "execution_results": [
            {
                "tool": "httpx",
                "status": "success",
                "findings": [
                    {
                        "finding_id": "SF-HTTPX-001",
                        "evidence": evidence,
                    }
                ],
                "metadata": {
                    "findings": [
                        {
                            "evidence": evidence,
                        }
                    ]
                },
            }
        ],
        "stage_results": [],
        "collector_results": [
            {
                "tool": "httpx",
                "observations": [
                    {
                        "observation_type": "HTTP_SERVICE",
                        "evidence": evidence,
                        "metadata": {
                            "body": "nested body",
                            "status_code": 200,
                        },
                    }
                ],
            }
        ],
        "native_analyzer_results": [],
        "vulnerability_intelligence_results": [],
        "software_assessments": [],
        "correlation_groups": [],
        "correlated_findings": [
            {
                "finding_id": "SF-CORRELATED-001",
                "evidence": {
                    "response": {"body": "correlated body"},
                    "url": "https://example.test/",
                },
            }
        ],
        "generated_files": [],
        "evidence_references": [],
        "raw_evidence_references": [],
        "finding_evidence_references": [],
        "correlated_evidence_references": [],
        "warnings": [],
        "errors": [],
        "analysis_metadata": {},
    }

    state = _report_state(ctx, _paths_for_test())

    # _report_state() represents runtime-derived state and may still contain
    # raw material. Stage 6's publication boundary is the sanitizer.
    assert any(
        key in _FORBIDDEN
        for key in _walk_keys(state)
    )

    published = _sanitize_report_payload(state)

    assert not (_FORBIDDEN & set(_walk_keys(published)))

    # Structured HTTPX metadata survives publication.
    finding = published["findings"][0]
    assert finding["evidence"]["url"] == "https://example.test/"
    assert finding["evidence"]["status_code"] == 200
    assert finding["evidence"]["content_type"] == "text/html"
    assert finding["evidence"]["webserver"] == "nginx"

    collector_observation = published["collector_results"][0]["observations"][0]
    assert collector_observation["evidence"]["url"] == (
        "https://example.test/"
    )
    assert collector_observation["evidence"]["status_code"] == 200
    assert collector_observation["metadata"]["status_code"] == 200

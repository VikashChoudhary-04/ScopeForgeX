from scopeforgex.intelligence import SoftwareAssessment


def test_software_assessment_represents_zero_cve_result():
    assessment = SoftwareAssessment(
        product="express",
        version="4.22.1",
        vendor="openjsf",
        cpe=(
            "cpe:2.3:a:openjsf:express:"
            "*:*:*:*:*:node.js:*:*"
        ),
        target="http://127.0.0.1:3000",
        host="127.0.0.1",
        port=3000,
        url="http://127.0.0.1:3000/api",
        source_tool="software_identity",
        detection_method="software_identity",
        confidence="High",
        nvd_checked=True,
        applicable_cve_count=0,
        kev_count=0,
    )

    assert assessment.product == "express"
    assert assessment.version == "4.22.1"
    assert assessment.vendor == "openjsf"
    assert assessment.nvd_checked is True
    assert assessment.applicable_cve_count == 0
    assert assessment.kev_count == 0


def test_software_assessment_serializes_to_dict():
    assessment = SoftwareAssessment(
        product="express",
        version="4.22.1",
        vendor="openjsf",
        cpe=(
            "cpe:2.3:a:openjsf:express:"
            "*:*:*:*:*:node.js:*:*"
        ),
        target="http://127.0.0.1:3000",
        nvd_checked=True,
        applicable_cve_count=0,
        kev_count=0,
    )

    data = assessment.as_dict()

    assert data["product"] == "express"
    assert data["version"] == "4.22.1"
    assert data["vendor"] == "openjsf"
    assert data["nvd_checked"] is True
    assert data["applicable_cve_count"] == 0
    assert data["kev_count"] == 0


def test_software_assessment_supports_positive_cve_count():
    assessment = SoftwareAssessment(
        product="log4j",
        version="2.14.1",
        vendor="apache",
        nvd_checked=True,
        applicable_cve_count=4,
        kev_count=1,
    )

    assert assessment.nvd_checked is True
    assert assessment.applicable_cve_count == 4
    assert assessment.kev_count == 1


def test_software_assessment_defaults_to_unchecked():
    assessment = SoftwareAssessment(
        product="example",
    )

    assert assessment.nvd_checked is False
    assert assessment.applicable_cve_count == 0
    assert assessment.kev_count == 0


def test_executor_retains_software_assessments_across_vi_calls(monkeypatch):
    """Executor retains assessments across real VI calls that reset the engine."""
    from scopeforgex.intelligence.models import SoftwareAssessment
    from scopeforgex.runtime.tool_executor import ToolExecutor

    executor = ToolExecutor()

    first = SoftwareAssessment(
        product="jquery",
        version="3.4.1",
        vendor="jquery",
        cpe="cpe:2.3:a:jquery:jquery:3.4.1:*:*:*:*:*:*:*",
        target="https://example.test/",
        host="example.test",
        port=443,
        url="https://example.test/",
        source_tool="scopeforgex",
        detection_method="Software / Framework Identity Analyzer",
        confidence="High",
        nvd_checked=True,
        applicable_cve_count=2,
        kev_count=1,
    )

    second = SoftwareAssessment(
        product="lodash",
        version="4.17.21",
        vendor="lodash",
        cpe="cpe:2.3:a:lodash:lodash:4.17.21:*:*:*:*:*:*:*",
        target="https://example.test/",
        host="example.test",
        port=443,
        url="https://example.test/",
        source_tool="scopeforgex",
        detection_method="Software / Framework Identity Analyzer",
        confidence="High",
        nvd_checked=True,
        applicable_cve_count=0,
        kev_count=0,
    )

    calls = iter(
        [
            [first],
            [second],
            [first],
        ]
    )

    def fake_analyze(observations):
        assessments = next(calls)

        executor.vulnerability_intelligence._software_assessments.clear()
        executor.vulnerability_intelligence._software_assessments.extend(
            assessments
        )

        return []

    monkeypatch.setattr(
        executor.vulnerability_intelligence,
        "analyze",
        fake_analyze,
    )

    context = {
        "vulnerability_intelligence_allow_network": False,
        "errors": [],
    }

    executor._run_vulnerability_intelligence(
        [{"observation_type": "software"}],
        context,
    )

    assert len(executor.software_assessments) == 1
    assert executor.software_assessments[0].product == "jquery"

    executor._run_vulnerability_intelligence(
        [{"observation_type": "software"}],
        context,
    )

    assert len(executor.software_assessments) == 2
    assert {
        item.product
        for item in executor.software_assessments
    } == {"jquery", "lodash"}

    executor._run_vulnerability_intelligence(
        [{"observation_type": "software"}],
        context,
    )

    assert len(executor.software_assessments) == 2
    assert {
        item.product
        for item in executor.software_assessments
    } == {"jquery", "lodash"}

def test_stage6_reportdata_serializes_software_assessments():
    from datetime import datetime, timezone

    from scopeforgex.intelligence.models import SoftwareAssessment
    from scopeforgex.stages.stage6_report_cleanup import (
        _report_data_from_state,
    )

    assessment = SoftwareAssessment(
        product="express",
        version="4.22.1",
        vendor="openjsf",
        cpe="cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
        target="http://127.0.0.1:3000",
        url="http://127.0.0.1:3000/api",
        source_tool="software_identity",
        detection_method="software_identity",
        confidence="High",
        nvd_checked=True,
        applicable_cve_count=0,
        kev_count=0,
    )

    report = _report_data_from_state(
        {
            "target": "http://127.0.0.1:3000",
            "profile": "standard",
            "target_type": "url",
            "start_time": datetime.now(timezone.utc),
            "end_time": datetime.now(timezone.utc),
            "statistics": {},
            "software_assessments": [assessment],
        }
    )

    assert len(report.software_assessments) == 1

    serialized = report.software_assessments[0]

    assert isinstance(serialized, dict)
    assert serialized["product"] == "express"
    assert serialized["version"] == "4.22.1"
    assert serialized["vendor"] == "openjsf"
    assert serialized["nvd_checked"] is True
    assert serialized["applicable_cve_count"] == 0
    assert serialized["kev_count"] == 0


def test_stage6_report_state_preserves_software_assessments():
    from datetime import datetime, timezone
    from pathlib import Path

    from scopeforgex.intelligence.models import SoftwareAssessment
    from scopeforgex.stages.stage6_report_cleanup import (
        _report_data_from_state,
        _report_state,
    )

    assessment = SoftwareAssessment(
        product="express",
        version="4.22.1",
        vendor="openjsf",
        cpe="cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
        target="http://127.0.0.1:3000",
        url="http://127.0.0.1:3000/api",
        source_tool="software_identity",
        detection_method="software_identity",
        confidence="High",
        nvd_checked=True,
        applicable_cve_count=0,
        kev_count=0,
    )

    ctx = {
        "target": "http://127.0.0.1:3000",
        "profile": "standard",
        "target_type": "url",
        "workflow_start_time": datetime.now(timezone.utc),
        "workflow_end_time": datetime.now(timezone.utc),
        "statistics": {},
        "software_assessments": [assessment],
        "findings": [],
        "execution_results": [],
        "stage_results": [],
        "collector_results": [],
        "native_analyzer_results": [],
        "vulnerability_intelligence_results": [],
        "correlation_groups": [],
        "correlated_findings": [],
        "generated_files": [],
        "evidence_references": [],
        "raw_evidence_references": [],
        "finding_evidence_references": [],
        "correlated_evidence_references": [],
        "warnings": [],
        "errors": [],
        "analysis_metadata": {},
    }

    paths = {
        "professional_markdown": Path(
            "/tmp/scopeforgex-test-professional.md"
        ),
        "professional_html": Path(
            "/tmp/scopeforgex-test-professional.html"
        ),
        "findings_markdown": Path(
            "/tmp/scopeforgex-test-findings.md"
        ),
        "findings_html": Path(
            "/tmp/scopeforgex-test-findings.html"
        ),
        "canonical_json": Path(
            "/tmp/scopeforgex-test-report.json"
        ),
    }

    state = _report_state(
        ctx,
        paths,
    )

    assert "software_assessments" in state
    assert len(state["software_assessments"]) == 1

    state_assessment = state["software_assessments"][0]

    assert isinstance(state_assessment, dict)
    assert state_assessment["product"] == "express"
    assert state_assessment["version"] == "4.22.1"
    assert state_assessment["vendor"] == "openjsf"
    assert state_assessment["nvd_checked"] is True
    assert state_assessment["applicable_cve_count"] == 0
    assert state_assessment["kev_count"] == 0

    report = _report_data_from_state(
        state
    )

    assert len(report.software_assessments) == 1
    assert isinstance(
        report.software_assessments[0],
        dict,
    )

    serialized = report.as_dict()

    assert "software_assessments" in serialized
    assert len(serialized["software_assessments"]) == 1
    assert serialized["software_assessments"][0]["product"] == "express"
    assert serialized["software_assessments"][0]["version"] == "4.22.1"
    assert serialized["software_assessments"][0]["nvd_checked"] is True
    assert serialized["software_assessments"][0]["applicable_cve_count"] == 0
    assert serialized["software_assessments"][0]["kev_count"] == 0


def test_report_data_derives_tool_results_from_execution_results():
    from datetime import datetime, timezone

    from scopeforgex.models.execution_result import ExecutionResult
    from scopeforgex.stages.stage6_report_cleanup import _report_data_from_state

    started = datetime.now(timezone.utc)
    finished = started

    execution_results = [
        ExecutionResult(
            tool="httpx",
            capability="web_enumeration",
            success=True,
            started_at=started,
            finished_at=finished,
        ),
        ExecutionResult(
            tool="nmap",
            capability="network_recon",
            success=False,
            started_at=started,
            finished_at=finished,
            metadata={"status": "skipped"},
        ),
        ExecutionResult(
            tool="nuclei",
            capability="vulnerability_assessment",
            success=False,
            started_at=started,
            finished_at=finished,
        ),
    ]

    ctx = {
        "target": "http://127.0.0.1:3000",
        "profile": "standard",
        "target_type": "url",
        "workflow_start_time": started,
        "workflow_end_time": finished,
        "statistics": {},
        "findings": [],
        "execution_results": execution_results,
        "stage_results": [],
        "collector_results": [],
        "native_analyzer_results": [],
        "vulnerability_intelligence_results": [],
        "software_assessments": [],
        "correlation_groups": [],
        "correlated_findings": [],
        "generated_files": [],
        "evidence_references": [],
        "raw_evidence_references": [],
        "finding_evidence_references": [],
        "correlated_evidence_references": [],
        "warnings": [],
        "errors": [],
        "analysis_metadata": {},
    }

    report = _report_data_from_state(ctx)

    assert report.tool_results == {
        "httpx": "success",
        "nmap": "skipped",
        "nuclei": "failed",
    }
    assert len(report.execution_results) == 3


def test_report_generator_renders_software_assessments(tmp_path):
    from reporting.models import ReportData, ScanStatistics
    from reporting.report_generator import ReportGenerator
    from scopeforgex.intelligence.models import SoftwareAssessment

    report = ReportData(
        target="http://127.0.0.1:3000",
        profile="fast",
        target_type="url",
        start_time="2026-09-09T00:00:00",
        end_time="2026-09-09T00:01:00",
        statistics=ScanStatistics(),
        findings=[
            {
                "finding_id": "SF-TEST-EXECUTIVE-SUMMARY",
                "title": "Test Informational Finding",
                "category": "test",
                "severity": "Informational",
                "confidence": "High",
                "target": "http://127.0.0.1:3000",
                "host": "127.0.0.1",
                "port": 3000,
                "url": "http://127.0.0.1:3000",
                "parameter": None,
                "description": "Synthetic regression-test finding.",
                "evidence": [],
                "source_tool": "scopeforgex-test",
                "detection_method": "regression_test",
                "timestamp": "2026-09-09T00:00:30",
                "cwe": None,
                "cve": None,
                "references": [],
                "impact": "Regression-test only.",
                "remediation": "Regression-test only.",
                "status": "Open",
            }
        ],
        software_assessments=[
            SoftwareAssessment(
                product="express",
                version="4.22.1",
                vendor="openjsf",
                cpe="cpe:2.3:a:openjsf:express:*:*:*:*:*:node.js:*:*",
                target="http://127.0.0.1:3000",
                url="http://127.0.0.1:3000/api",
                source_tool="software_identity",
                detection_method="explicit_framework_signature",
                confidence="High",
                nvd_checked=True,
                applicable_cve_count=0,
                kev_count=0,
            )
        ],
    )

    generator = ReportGenerator(report)

    markdown_path = tmp_path / "professional.md"
    html_path = tmp_path / "professional.html"

    generator.generate_professional_markdown(
        str(markdown_path)
    )
    generator.generate_professional_html(
        str(html_path)
    )

    markdown = markdown_path.read_text()
    html = html_path.read_text()

    assert "### Software Assessments" in markdown
    assert "express" in markdown
    assert "4.22.1" in markdown
    assert "openjsf" in markdown
    assert "0" in markdown

    assert "<h2>Executive Summary</h2>" in html
    assert "The assessment identified" in html
    assert "Target:" in html
    assert "http://127.0.0.1:3000" in html

    assert "<h2>Software Assessments</h2>" in html
    assert "express" in html
    assert "4.22.1" in html
    assert "openjsf" in html
    assert "0" in html



def test_findings_report_cve_summary_includes_all_severities(tmp_path):
    from reporting.models import ReportData, ScanStatistics
    from reporting.report_generator import ReportGenerator

    findings = []
    severities = [
        ("Critical", "CVE-TEST-CRITICAL"),
        ("High", "CVE-TEST-HIGH"),
        ("Medium", "CVE-TEST-MEDIUM"),
        ("Low", "CVE-TEST-LOW"),
        ("Informational", "CVE-TEST-INFORMATIONAL"),
    ]

    for severity, cve in severities:
        findings.append(
            {
                "finding_id": f"SF-TEST-{severity.upper()}",
                "title": f"Synthetic {severity} CVE Finding",
                "category": "test",
                "severity": severity,
                "confidence": "High",
                "target": "http://127.0.0.1:3000",
                "host": "127.0.0.1",
                "port": 3000,
                "url": "http://127.0.0.1:3000",
                "parameter": None,
                "description": "Synthetic CVE regression-test finding.",
                "evidence": [],
                "source_tool": "scopeforgex-test",
                "detection_method": "regression_test",
                "timestamp": "2026-09-09T00:00:30",
                "cwe": None,
                "cve": cve,
                "references": [],
                "impact": "Regression-test only.",
                "remediation": "Regression-test only.",
                "status": "Open",
            }
        )

    report = ReportData(
        target="http://127.0.0.1:3000",
        profile="fast",
        target_type="url",
        start_time="2026-09-09T00:00:00",
        end_time="2026-09-09T00:01:00",
        statistics=ScanStatistics(),
        findings=findings,
    )

    output = tmp_path / "findings.md"

    ReportGenerator(report).generate_findings_markdown(
        str(output)
    )

    markdown = output.read_text()

    assert "## CVE Summary" in markdown

    for severity, cve in severities:
        assert f"`{cve}`" in markdown
        assert f"| `{cve}` | {severity} |" in markdown

    assert "| CVEs | **5** |" in markdown

def test_findings_report_is_concise_without_raw_evidence(tmp_path):
    from reporting.models import ReportData, ScanStatistics
    from reporting.report_generator import ReportGenerator

    evidence = {
        "request": {
            "method": "GET",
            "url": "http://127.0.0.1:3000/admin",
        },
        "response": {
            "status_code": 200,
            "headers": {
                "X-Test-Evidence": "retained-in-canonical-report",
            },
            "body": "synthetic-evidence-payload",
        },
    }

    report = ReportData(
        target="http://127.0.0.1:3000",
        profile="fast",
        target_type="url",
        start_time="2026-09-09T00:00:00",
        end_time="2026-09-09T00:01:00",
        statistics=ScanStatistics(),
        findings=[
            {
                "finding_id": "SF-TEST-CONCISE-FINDING",
                "title": "Synthetic Evidence Finding",
                "category": "test",
                "severity": "High",
                "confidence": "High",
                "target": "http://127.0.0.1:3000",
                "host": "127.0.0.1",
                "port": 3000,
                "url": "http://127.0.0.1:3000/admin",
                "parameter": None,
                "description": "Synthetic finding description.",
                "evidence": evidence,
                "source_tool": "scopeforgex-test",
                "detection_method": "regression_test",
                "timestamp": "2026-09-09T00:00:30",
                "cwe": "CWE-200",
                "cve": None,
                "references": ["https://example.test/reference"],
                "impact": "Synthetic finding impact.",
                "remediation": "Synthetic finding remediation.",
                "status": "Open",
            }
        ],
    )

    generator = ReportGenerator(report)

    professional_md = tmp_path / "professional.md"
    professional_html = tmp_path / "professional.html"
    findings_md = tmp_path / "findings.md"
    findings_html = tmp_path / "findings.html"

    generator.generate_professional_markdown(
        str(professional_md)
    )
    generator.generate_professional_html(
        str(professional_html)
    )
    generator.generate_findings_markdown(
        str(findings_md)
    )
    generator.generate_findings_html(
        str(findings_html)
    )

    professional_markdown = professional_md.read_text()
    professional_html_text = professional_html.read_text()
    findings_markdown = findings_md.read_text()
    findings_html_text = findings_html.read_text()

    evidence_json = '"X-Test-Evidence": "retained-in-canonical-report"'

    assert "Finding-specific evidence is available in the canonical assessment artifacts and raw evidence references." in professional_markdown
    assert evidence_json not in professional_markdown
    assert "synthetic-evidence-payload" not in professional_markdown

    assert "Finding-specific evidence is available in the canonical assessment artifacts and raw evidence references." in professional_html_text
    assert evidence_json not in professional_html_text
    assert "synthetic-evidence-payload" not in professional_html_text

    assert "SF-TEST-CONCISE-FINDING" in findings_markdown
    assert "Synthetic Evidence Finding" in findings_markdown
    assert "High" in findings_markdown
    assert "Synthetic finding description." in findings_markdown
    assert "Synthetic finding impact." in findings_markdown
    assert "Synthetic finding remediation." in findings_markdown
    assert "Finding-specific evidence is available" in findings_markdown
    assert evidence_json not in findings_markdown
    assert "synthetic-evidence-payload" not in findings_markdown

    assert "SF-TEST-CONCISE-FINDING" in findings_html_text
    assert "Synthetic Evidence Finding" in findings_html_text
    assert "Synthetic finding description." in findings_html_text
    assert "Synthetic finding impact." in findings_html_text
    assert "Synthetic finding remediation." in findings_html_text
    assert "Finding-specific evidence is available" in findings_html_text
    assert evidence_json not in findings_html_text
    assert "synthetic-evidence-payload" not in findings_html_text

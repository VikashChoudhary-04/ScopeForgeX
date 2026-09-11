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

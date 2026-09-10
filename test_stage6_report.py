from pathlib import Path
from scopeforgex.stages.stage6_report_cleanup import stage6_report_cleanup


outdir = Path("/tmp/scopeforgex-stage6-test")

ctx = {
    "target": "http://127.0.0.1:3000",
    "target_type": "url",
    "profile": "fast",
    "run_id": "stage6-test-001",
    "workflow_start_time": 0,
    "workflow_end_time": 12.5,
    "workflow_duration": 12.5,

    "statistics": {
        "subdomains_found": 2,
        "alive_hosts": 1,
        "final_hosts": 1,
        "urls_discovered": 4,
    },

    "findings": [
        {
            "finding_id": "SF-001",
            "title": "Example Security Finding",
            "severity": "High",
            "confidence": "High",
            "status": "Open",
            "source_tool": "Nuclei",
            "target": "http://127.0.0.1:3000",
            "description": "Synthetic finding used to validate Stage 6 reporting.",
            "impact": "Synthetic impact.",
            "remediation": "Synthetic remediation guidance.",
            "cve": "CVE-2026-0001",
            "cwe": "CWE-79",
            "detection_method": "Synthetic test",
            "evidence": {
                "request": "GET /",
                "response": "200 OK",
            },
            "references": [
                "https://example.com/reference",
            ],
        },
    ],

    "correlation_groups": [],
    "correlated_findings": [],
    "collector_results": [],
    "execution_results": [],
    "native_analyzer_results": [],

    "vulnerability_intelligence_results": [
        {
            "observation_type": "VULNERABILITY_INTELLIGENCE",
            "cve": "CVE-2026-0001",
            "title": "CVE-2026-0001: Synthetic Vulnerability",
            "description": "Synthetic vulnerability-intelligence record.",
            "severity": "High",
            "target": "http://127.0.0.1:3000",
            "metadata": {
                "product": "Example Product",
                "version": "1.2.3",
                "cpe": "cpe:2.3:a:example:product:1.2.3:*:*:*:*:*:*:*",
                "cvss_score": 8.8,
                "cvss_version": "3.1",
                "kev": False,
                "version_based_match": True,
                "validation_status": "Pending",
                "intelligence_source": "NVD",
            },
            "references": [],
        },
    ],

    "evidence_references": [],
    "raw_evidence_references": [],
    "finding_evidence_references": [],
    "correlated_evidence_references": [],
    "warnings": [],
    "errors": [],
    "generated_files": [],
}

stage6_report_cleanup(ctx)

print(f"Reports generated in: {outdir}")

for path in sorted(outdir.rglob("*")):
    if path.is_file():
        print(path)

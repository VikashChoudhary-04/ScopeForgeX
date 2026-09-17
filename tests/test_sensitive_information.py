from __future__ import annotations

from scopeforgex.analyzers.sensitive_information import (
    INFORMATION_DISCLOSURE,
    SENSITIVE_FILE_EXPOSURE,
    SensitiveInformationAnalyzer,
)


def test_sensitive_information_analyzer_detects_all_resource_categories():
    analyzer = SensitiveInformationAnalyzer()

    evidence = {
        "target": "https://example.com/",
        "resources": [
            "https://example.com/.env",
            "https://example.com/.git/",
            "https://example.com/config.bak",
            "https://example.com/app.js.map",
            "https://example.com/settings.yaml",
            "https://example.com/actuator/env",
        ],
    }

    findings = analyzer.analyze(evidence)

    classifications = {
        finding.evidence["classification"]
        for finding in findings
    }

    assert classifications == {
        "env_file",
        "git_resource",
        "backup_file",
        "source_map",
        "configuration_file",
        "debug_endpoint",
    }

    by_classification = {
        finding.evidence["classification"]: finding
        for finding in findings
    }

    assert (
        by_classification["env_file"].finding_type
        == SENSITIVE_FILE_EXPOSURE
    )
    assert (
        by_classification["git_resource"].finding_type
        == SENSITIVE_FILE_EXPOSURE
    )
    assert (
        by_classification["backup_file"].finding_type
        == SENSITIVE_FILE_EXPOSURE
    )
    assert (
        by_classification["configuration_file"].finding_type
        == SENSITIVE_FILE_EXPOSURE
    )
    assert (
        by_classification["source_map"].finding_type
        == INFORMATION_DISCLOSURE
    )
    assert (
        by_classification["debug_endpoint"].finding_type
        == INFORMATION_DISCLOSURE
    )


def test_sensitive_information_analyzer_detects_env_variants():
    analyzer = SensitiveInformationAnalyzer()

    resources = [
        "/.env",
        "/.env.production",
        "/app/.env.local",
        "https://example.com/config/.env.test",
    ]

    for resource in resources:
        classifications = analyzer._classify_resource(resource)
        assert "env_file" in classifications


def test_sensitive_information_analyzer_detects_git_resources():
    analyzer = SensitiveInformationAnalyzer()

    assert "git_resource" in analyzer._classify_resource(
        "/.git"
    )
    assert "git_resource" in analyzer._classify_resource(
        "/.git/config"
    )
    assert "git_resource" in analyzer._classify_resource(
        "https://example.com/.git/HEAD"
    )

    assert "git_resource" not in analyzer._classify_resource(
        "/something.git"
    )


def test_sensitive_information_analyzer_detects_backup_resources():
    analyzer = SensitiveInformationAnalyzer()

    resources = [
        "/backup",
        "/backups",
        "/database.bak",
        "/database.backup",
        "/database.old",
        "/database.orig",
        "/database.save",
        "/editor.swp",
        "/editor.swo",
        "/temporary.tmp",
        "/database.backup~",
    ]

    for resource in resources:
        assert "backup_file" in analyzer._classify_resource(resource)


def test_sensitive_information_analyzer_detects_configuration_resources():
    analyzer = SensitiveInformationAnalyzer()

    resources = [
        "/app.conf",
        "/app.config",
        "/app.cfg",
        "/app.ini",
        "/app.properties",
        "/app.yaml",
        "/app.yml",
        "/app.toml",
        "/config",
        "/configuration",
        "https://example.com/etc/application.yaml?download=1",
    ]

    for resource in resources:
        assert "configuration_file" in analyzer._classify_resource(resource)


def test_sensitive_information_analyzer_detects_source_maps():
    analyzer = SensitiveInformationAnalyzer()

    assert "source_map" in analyzer._classify_resource(
        "/static/app.js.map"
    )
    assert "source_map" in analyzer._classify_resource(
        "https://example.com/app.css.map?v=1"
    )


def test_sensitive_information_analyzer_detects_debug_endpoints():
    analyzer = SensitiveInformationAnalyzer()

    resources = [
        "/debug",
        "/debug/",
        "/debugger",
        "/actuator",
        "/actuator/env",
        "/actuator/configprops",
        "/server-status",
        "/server-info",
        "/phpinfo",
        "/phpinfo.php",
    ]

    for resource in resources:
        assert "debug_endpoint" in analyzer._classify_resource(resource)


def test_sensitive_information_analyzer_does_not_treat_directory_path_as_listing():
    analyzer = SensitiveInformationAnalyzer()

    assert analyzer._is_directory_listing_path(
        "/files/"
    ) is False

    assert analyzer._classify_resource(
        "/files/"
    ) == []


def test_sensitive_information_analyzer_detects_directory_listing_response():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "responses": [
                {
                    "url": "https://example.com/files/",
                    "body": "<html><title>Index of /files/</title></html>",
                }
            ],
        }
    )

    assert len(findings) == 1
    finding = findings[0]

    assert finding.title == "Directory Listing Discovered"
    assert finding.finding_type == INFORMATION_DISCLOSURE
    assert finding.evidence == {
        "resource": "https://example.com/files/",
        "classification": "directory_listing",
    }


def test_sensitive_information_analyzer_detects_debug_content():
    analyzer = SensitiveInformationAnalyzer()

    bodies = [
        "phpinfo() output",
        "<html>PHPINFO</html>",
        "debug toolbar enabled",
        "Application is running in DEBUG MODE",
    ]

    for body in bodies:
        findings = analyzer.analyze(
            {
                "target": "https://example.com/",
                "responses": [
                    {
                        "url": "https://example.com/debug",
                        "body": body,
                    }
                ],
            }
        )

        assert len(findings) == 1
        assert findings[0].title == "Debug Information Disclosed"
        assert (
            findings[0].finding_type
            == INFORMATION_DISCLOSURE
        )
        assert (
            findings[0].evidence["classification"]
            == "debug_content"
        )


def test_sensitive_information_analyzer_accepts_explicit_listing_and_debug_evidence():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "directory_listings": [
                "https://example.com/files/"
            ],
            "debug_endpoints": [
                "https://example.com/debug"
            ],
        }
    )

    assert len(findings) == 2

    by_classification = {
        finding.evidence["classification"]: finding
        for finding in findings
    }

    assert "directory_listing" in by_classification
    assert "debug_endpoint" in by_classification

    assert (
        by_classification["directory_listing"].finding_type
        == INFORMATION_DISCLOSURE
    )
    assert (
        by_classification["debug_endpoint"].finding_type
        == INFORMATION_DISCLOSURE
    )


def test_sensitive_information_analyzer_extracts_all_resource_input_forms():
    analyzer = SensitiveInformationAnalyzer()

    evidence = {
        "resources": [
            "https://example.com/.env",
            {"url": "https://example.com/.git/"},
            {"target": "https://example.com/app.bak"},
        ],
        "urls": "https://example.com/app.js.map",
        "endpoints": [
            "https://example.com/config.yaml"
        ],
        "discovered_resources": [
            {"target": "https://example.com/debug"}
        ],
        "url": "https://example.com/config",
    }

    resources = analyzer._extract_resources(evidence)

    assert resources == [
        "https://example.com/.env",
        "https://example.com/.git/",
        "https://example.com/app.bak",
        "https://example.com/app.js.map",
        "https://example.com/config.yaml",
        "https://example.com/debug",
        "https://example.com/config",
    ]


def test_sensitive_information_analyzer_extract_values():
    analyzer = SensitiveInformationAnalyzer()

    assert analyzer._extract_values(
        "https://example.com/.env"
    ) == [
        "https://example.com/.env"
    ]

    assert analyzer._extract_values(
        [" /a ", "", "/b"]
    ) == [
        "/a",
        "/b",
    ]

    assert analyzer._extract_values(
        {
            "/enabled": True,
            "/disabled": False,
        }
    ) == [
        "/enabled"
    ]

    assert analyzer._extract_values(
        123
    ) == ["123"]

    assert analyzer._extract_values(
        None
    ) == []


def test_sensitive_information_analyzer_extracts_response_forms():
    analyzer = SensitiveInformationAnalyzer()

    evidence = {
        "target": "https://example.com/",
        "responses": [
            {
                "url": "https://example.com/a",
                "body": "body-a",
            },
            {
                "target": "https://example.com/b",
                "response": "body-b",
            },
            "ignored",
        ],
    }

    responses = analyzer._extract_responses(evidence)

    assert responses == [
        {
            "url": "https://example.com/a",
            "body": "body-a",
        },
        {
            "url": "https://example.com/b",
            "body": "body-b",
        },
    ]

    string_response = analyzer._extract_responses(
        {
            "target": "https://example.com/",
            "responses": "Index of /files/",
        }
    )

    assert string_response == [
        {
            "url": "https://example.com/",
            "body": "Index of /files/",
        }
    ]


def test_sensitive_information_analyzer_deduplicates_identical_resource_observations():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "resources": [
                "https://example.com/.env",
                "https://example.com/.env",
                {"url": "https://example.com/.env"},
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0].title == "Environment File Exposed"


def test_sensitive_information_analyzer_deduplicates_multiple_input_channels():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "resources": [
                "https://example.com/debug"
            ],
            "debug_endpoints": [
                "https://example.com/debug"
            ],
        }
    )

    assert len(findings) == 1
    assert (
        findings[0].evidence["classification"]
        == "debug_endpoint"
    )


def test_sensitive_information_analyzer_ignores_empty_or_unrelated_evidence():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "resources": [
                "",
                "https://example.com/index.html",
                "https://example.com/assets/app.js",
            ],
            "responses": [
                {
                    "url": "https://example.com/",
                    "body": "normal application response",
                }
            ],
        }
    )

    assert findings == []


def test_sensitive_information_analyzer_observation_contract():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "resources": [
                "https://example.com/.env"
            ],
        }
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.finding_type == SENSITIVE_FILE_EXPOSURE
    assert finding.title == "Environment File Exposed"
    assert finding.severity == "Informational"
    assert finding.confidence == "High"
    assert finding.target == "https://example.com/"
    assert finding.source_tool == "scopeforgex"
    assert (
        finding.detection_method
        == "Sensitive Information Analyzer"
    )
    assert finding.category == "information_disclosure"
    assert finding.remediation

    serialized = finding.as_dict()

    assert serialized["finding_type"] == SENSITIVE_FILE_EXPOSURE
    assert serialized["title"] == "Environment File Exposed"
    assert serialized["severity"] == "Informational"
    assert serialized["confidence"] == "High"
    assert serialized["target"] == "https://example.com/"
    assert serialized["evidence"] == {
        "resource": "https://example.com/.env",
        "classification": "env_file",
    }


def test_sensitive_information_analyzer_is_evidence_only():
    analyzer = SensitiveInformationAnalyzer()

    findings = analyzer.analyze(
        {
            "target": "https://example.com/",
            "resources": [
                "https://example.com/.env"
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0].evidence["resource"].endswith(
        "/.env"
    )

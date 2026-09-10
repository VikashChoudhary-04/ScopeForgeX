from scopeforgex.analyzers.software_identity import (
    SoftwareIdentityAnalyzer,
)


def test_detects_express_constraint_version():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "stdout": "OWASP Juice Shop (Express ^4.22.1)",
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["observation_type"] == "FRAMEWORK"
    assert data["value"] == "express 4.22.1"

    assert data["metadata"]["product"] == "express"
    assert data["metadata"]["vendor"] == "openjsf"
    assert data["metadata"]["version"] == "4.22.1"

    assert (
        data["metadata"]["version_raw"]
        == "Express ^4.22.1"
    )

    assert (
        data["metadata"]["version_semantics"]
        == "constraint"
    )


def test_detects_express_explicit_version():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "stdout": "Express 4.18.3",
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["observation_type"] == "FRAMEWORK"
    assert data["value"] == "express 4.18.3"

    assert data["metadata"]["product"] == "express"
    assert data["metadata"]["vendor"] == "openjsf"
    assert data["metadata"]["version"] == "4.18.3"

    assert (
        data["metadata"]["version_semantics"]
        == "explicit"
    )


def test_does_not_detect_unrelated_technology():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "stdout": (
                "OWASP Juice Shop "
                "HTML5 Node.js Angular"
            ),
        }
    )

    assert results == []


def test_preserves_detection_evidence():
    analyzer = SoftwareIdentityAnalyzer()

    stdout = (
        "OWASP Juice Shop "
        "(Express ^4.22.1)"
    )

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "stdout": stdout,
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["evidence"]["source"] == "stdout"
    assert (
        data["evidence"]["raw_version"]
        == "Express ^4.22.1"
    )

    assert (
        data["evidence"]["source_evidence"]["text"]
        == stdout
    )


def test_detects_express_from_collector_evidence():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "collector_observations": [
                {
                    "observation_type": "HTTP_SERVICE",
                    "value": "http://127.0.0.1:3000/",
                    "evidence": {
                        "body": (
                            "OWASP Juice Shop "
                            "(Express ^4.22.1)"
                        ),
                    },
                },
            ],
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["metadata"]["product"] == "express"
    assert data["metadata"]["vendor"] == "openjsf"
    assert data["metadata"]["version"] == "4.22.1"
    assert (
        data["metadata"]["version_semantics"]
        == "constraint"
    )


def test_invalid_evidence_returns_no_results():
    analyzer = SoftwareIdentityAnalyzer()

    assert analyzer.analyze(None) == []
    assert analyzer.analyze("not-a-mapping") == []
    assert analyzer.analyze({}) == []

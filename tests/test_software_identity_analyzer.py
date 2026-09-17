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

    assert "text" not in data["evidence"]["source_evidence"]


def test_stdout_raw_payload_is_not_propagated_as_text():
    """Raw stdout used for detection must not survive as report evidence."""

    stdout = (
        '{"timestamp":"2026-09-17T01:16:37.450785306-04:00",'
        '"url":"https://warrantyindia.com/about.js",'
        '"status_code":200,'
        '"body":"FULL HTTP RESPONSE BODY MUST NOT BE PROPAGATED",'
        '"request":"FULL HTTP REQUEST MUST NOT BE PROPAGATED",'
        '"response":"FULL HTTP RESPONSE MUST NOT BE PROPAGATED",'
        '"tech":["jQuery:3.4.1"]}'
    )

    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "warrantyindia.com",
            "stdout": stdout,
            "stderr": "",
        }
    )

    assert results

    data = results[0].as_dict()
    source_evidence = data["evidence"]["source_evidence"]

    assert "text" not in source_evidence
    assert "body" not in source_evidence
    assert "request" not in source_evidence
    assert "response" not in source_evidence
    assert "FULL HTTP RESPONSE BODY MUST NOT BE PROPAGATED" not in str(
        source_evidence
    )

    assert data["metadata"]["product"] == "jquery"
    assert data["metadata"]["version"] == "3.4.1"


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

def test_detects_express_from_structured_technology_evidence():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "evidence": {
                "tech": [
                    "Apache HTTP Server",
                    "Express 4.18.3",
                    "jQuery:3.4.1",
                ],
            },
        }
    )

    express_results = [
        result
        for result in results
        if result.metadata.get("product") == "express"
    ]

    assert len(express_results) == 1

    data = express_results[0].as_dict()

    assert data["value"] == "express 4.18.3"
    assert data["metadata"]["product"] == "express"
    assert data["metadata"]["vendor"] == "openjsf"
    assert data["metadata"]["version"] == "4.18.3"
    assert (
        data["metadata"]["evidence_source"]
        == "observation.evidence.tech[1]"
    )

    assert (
        data["evidence"]["source_evidence"]["observation"]["evidence"]["tech"]
        == [
            "Apache HTTP Server",
            "Express 4.18.3",
            "jQuery:3.4.1",
        ]
    )


def test_detects_express_from_runtime_collector_technology_evidence():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "collector_observations": [
                {
                    "observation_type": "HTTP_SERVICE",
                    "value": "http://127.0.0.1:3000/",
                    "evidence": {
                        "tech": [
                            "Apache HTTP Server",
                            "Express 4.18.3",
                        ],
                    },
                },
            ],
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["value"] == "express 4.18.3"
    assert data["metadata"]["product"] == "express"
    assert data["metadata"]["version"] == "4.18.3"
    assert (
        data["metadata"]["evidence_source"]
        == "collector_observation.evidence.tech[1]"
    )

def test_detects_jquery_from_structured_technology_evidence():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "https://warrantyindia.com",
            "evidence": {
                "tech": [
                    "Apache HTTP Server",
                    "Bootstrap:5.0.0",
                    "jQuery:3.4.1",
                ],
            },
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["value"] == "jquery 3.4.1"
    assert data["metadata"]["product"] == "jquery"
    assert data["metadata"]["vendor"] == "jquery"
    assert data["metadata"]["version"] == "3.4.1"
    assert (
        data["metadata"]["evidence_source"]
        == "observation.evidence.tech[2]"
    )
    assert (
        data["evidence"]["source_evidence"]["observation"]["evidence"]["tech"]
        == [
            "Apache HTTP Server",
            "Bootstrap:5.0.0",
            "jQuery:3.4.1",
        ]
    )


def test_detects_jquery_from_runtime_collector_technology_evidence():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "https://warrantyindia.com",
            "collector_observations": [
                {
                    "observation_type": "HTTP_SERVICE",
                    "value": "https://warrantyindia.com/",
                    "evidence": {
                        "tech": [
                            "Apache HTTP Server",
                            "jQuery:3.4.1",
                        ],
                    },
                },
            ],
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["value"] == "jquery 3.4.1"
    assert data["metadata"]["product"] == "jquery"
    assert data["metadata"]["vendor"] == "jquery"
    assert data["metadata"]["version"] == "3.4.1"
    assert (
        data["metadata"]["evidence_source"]
        == "collector_observation.evidence.tech[1]"
    )


def test_body_is_used_for_detection_but_not_propagated():
    analyzer = SoftwareIdentityAnalyzer()

    body = (
        "OWASP Juice Shop "
        "(Express ^4.22.1)"
    )

    results = analyzer.analyze(
        {
            "target": "http://127.0.0.1:3000",
            "collector_observations": [
                {
                    "observation_type": "HTTP_SERVICE",
                    "value": "http://127.0.0.1:3000/",
                    "evidence": {
                        "body": body,
                        "status_code": 200,
                        "url": "http://127.0.0.1:3000/",
                        "tech": [
                            "Express 4.22.1",
                        ],
                    },
                },
            ],
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()

    assert data["metadata"]["product"] == "express"
    assert data["metadata"]["version"] == "4.22.1"

    source_evidence = data["evidence"]["source_evidence"]
    propagated_observation = source_evidence["observation"]
    propagated_evidence = propagated_observation["evidence"]

    assert "body" not in propagated_evidence
    assert propagated_evidence["status_code"] == 200
    assert propagated_evidence["url"] == "http://127.0.0.1:3000/"
    assert propagated_evidence["tech"] == ["Express 4.22.1"]


def test_raw_http_material_is_not_propagated_into_software_identity():
    analyzer = SoftwareIdentityAnalyzer()

    results = analyzer.analyze(
        {
            "target": "https://warrantyindia.com",
            "collector_observations": [
                {
                    "observation_type": "HTTP_SERVICE",
                    "value": "https://warrantyindia.com/",
                    "evidence": {
                        "body": "jQuery:3.4.1",
                        "raw_header": "HTTP/1.1 200 OK\\r\\nServer: nginx",
                        "request": {
                            "method": "GET",
                            "headers": {
                                "Host": "warrantyindia.com",
                            },
                        },
                        "response": {
                            "status_code": 200,
                            "body": "jQuery:3.4.1",
                        },
                        "raw_response": "HTTP/1.1 200 OK...",
                        "tech": [
                            "jQuery:3.4.1",
                        ],
                        "url": "https://warrantyindia.com/",
                    },
                },
            ],
        }
    )

    assert len(results) == 1

    data = results[0].as_dict()
    source_evidence = data["evidence"]["source_evidence"]

    assert data["metadata"]["product"] == "jquery"
    assert data["metadata"]["version"] == "3.4.1"

    # The existing provenance structure is intentionally preserved.
    # Raw HTTP material must be removed recursively from it.
    propagated_observation = source_evidence["observation"]
    propagated_evidence = propagated_observation["evidence"]

    forbidden_keys = {
        "body",
        "raw_body",
        "raw_header",
        "raw_headers",
        "request",
        "raw_request",
        "response",
        "raw_response",
    }

    def collect_keys(value):
        keys = set()

        if isinstance(value, dict):
            for key, item in value.items():
                keys.add(str(key).strip().lower())
                keys.update(collect_keys(item))

        elif isinstance(value, (list, tuple)):
            for item in value:
                keys.update(collect_keys(item))

        return keys

    propagated_keys = collect_keys(source_evidence)

    assert not (
        forbidden_keys & propagated_keys
    ), (
        "Raw HTTP material leaked into propagated software "
        f"evidence: {sorted(forbidden_keys & propagated_keys)}"
    )

    assert propagated_evidence["tech"] == ["jQuery:3.4.1"]
    assert propagated_evidence["url"] == "https://warrantyindia.com/"

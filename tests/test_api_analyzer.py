from __future__ import annotations

from scopeforgex.analyzers.api import (
    API_DOCUMENTATION,
    API_ENDPOINT,
    API_VERSION,
    GRAPHQL_ENDPOINT,
    APIAnalyzer,
)


TARGET = "https://example.com/"


def test_api_analyzer_detects_all_resource_classifications():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "resources": [
                "https://example.com/swagger/",
                "https://example.com/graphql",
                "https://example.com/api/v1/users",
            ],
        }
    )

    classifications = {
        finding.finding_type
        for finding in findings
    }

    assert classifications == {
        API_DOCUMENTATION,
        GRAPHQL_ENDPOINT,
        API_ENDPOINT,
        API_VERSION,
    }


def test_api_analyzer_detects_documentation_paths():
    analyzer = APIAnalyzer()

    resources = [
        "/swagger",
        "/swagger/",
        "/swagger-ui",
        "/swagger-ui/",
        "/swagger-ui.html",
        "/swagger.json",
        "/swagger.yaml",
        "/swagger.yml",
        "/openapi",
        "/openapi/",
        "/openapi.json",
        "/openapi.yaml",
        "/openapi.yml",
        "/api-docs",
        "/api-docs/",
        "/apidocs",
        "/apidocs/",
        "/docs",
        "/docs/",
        "/api/docs",
        "/api/docs/",
    ]

    for resource in resources:
        classifications = analyzer._classify_resource(resource)

        assert any(
            classification == API_DOCUMENTATION
            for classification, _ in classifications
        ), resource


def test_api_analyzer_detects_documentation_prefix_paths():
    analyzer = APIAnalyzer()

    resources = [
        "/swagger-ui/index.html",
        "/openapi/v1/spec.json",
        "/swagger/v2/spec.yaml",
        "/api-docs/index.html",
        "/apidocs/reference",
    ]

    for resource in resources:
        assert analyzer._is_documentation_path(resource) is True


def test_api_analyzer_identifies_documentation_types():
    analyzer = APIAnalyzer()

    assert analyzer._documentation_type("/swagger.json") == "Swagger"
    assert analyzer._documentation_type("/swagger-ui/") == "Swagger"
    assert analyzer._documentation_type("/openapi.json") == "OpenAPI"
    assert analyzer._documentation_type("/schema.yaml") == "OpenAPI"
    assert analyzer._documentation_type("/api-docs") == "API documentation"
    assert analyzer._documentation_type("/apidocs/") == "API documentation"


def test_api_analyzer_detects_graphql_paths():
    analyzer = APIAnalyzer()

    resources = [
        "/graphql",
        "/graphql/",
        "/graphql/query",
        "/api/graphql",
        "/api/graphql/",
        "/api/graphql/query",
    ]

    for resource in resources:
        classifications = analyzer._classify_resource(resource)

        assert any(
            classification == GRAPHQL_ENDPOINT
            for classification, _ in classifications
        ), resource


def test_api_analyzer_detects_api_path_structure():
    analyzer = APIAnalyzer()

    resources = [
        "/api",
        "/api/",
        "/api/users",
        "/api/v1/users",
        "/v1/api/users",
    ]

    for resource in resources:
        assert analyzer._is_api_endpoint(resource) is True


def test_api_analyzer_conservatively_rejects_non_api_paths():
    analyzer = APIAnalyzer()

    resources = [
        "/application",
        "/users",
        "/products",
        "/my-api",
        "/apiary",
        "/something/apiary/users",
    ]

    for resource in resources:
        assert analyzer._is_api_endpoint(resource) is False


def test_api_analyzer_extracts_api_versions():
    analyzer = APIAnalyzer()

    cases = {
        "/api/v1/users": "v1",
        "/api/v2/users": "v2",
        "/v1/api/users": "v1",
        "/api/v1.2/users": "v1.2",
        "https://example.com/api/V3/users": "v3",
        "https://example.com/v4/orders?limit=10": "v4",
        "/api/v5/orders#details": "v5",
    }

    for resource, expected in cases.items():
        assert analyzer._extract_api_version(resource) == expected


def test_api_analyzer_does_not_extract_invalid_api_versions():
    analyzer = APIAnalyzer()

    resources = [
        "/api/version1/users",
        "/api/v/users",
        "/api/vx/users",
        "/api/1/users",
        "/api/users",
        "/version/v1x/users",
    ]

    for resource in resources:
        assert analyzer._extract_api_version(resource) is None


def test_api_analyzer_detects_documentation_from_content():
    analyzer = APIAnalyzer()

    assert (
        analyzer._documentation_from_content(
            '{"openapi":"3.0.0","paths":{}}'
        )
        == "OpenAPI"
    )

    assert (
        analyzer._documentation_from_content(
            '{"swagger":"2.0","paths":{}}'
        )
        == "Swagger"
    )

    assert (
        analyzer._documentation_from_content(
            "openapi: 3.0.0"
        )
        == "OpenAPI"
    )

    assert (
        analyzer._documentation_from_content(
            "swagger: '2.0'"
        )
        == "Swagger"
    )


def test_api_analyzer_does_not_classify_unrelated_content_as_documentation():
    analyzer = APIAnalyzer()

    assert (
        analyzer._documentation_from_content(
            '{"name":"example","status":"ok"}'
        )
        is None
    )


def test_api_analyzer_detects_graphql_content_indicators():
    analyzer = APIAnalyzer()

    indicators = [
        "graphql query",
        "__schema",
        "__typename",
        "IntrospectionQuery",
    ]

    for text in indicators:
        assert analyzer._contains_graphql_indicator(
            text.lower()
        ) is True


def test_api_analyzer_rejects_unrelated_graphql_content():
    analyzer = APIAnalyzer()

    assert (
        analyzer._contains_graphql_indicator(
            "normal application response"
        )
        is False
    )


def test_api_analyzer_detects_api_information_from_response_records():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "responses": [
                {
                    "url": "https://example.com/docs",
                    "body": '{"openapi":"3.0.0","paths":{}}',
                    "content_type": "application/json",
                },
                {
                    "url": "https://example.com/query",
                    "body": '{"query":"query IntrospectionQuery { __schema { queryType { name } } }"}',
                    "content_type": "application/json",
                },
                {
                    "url": "https://example.com/api/v2/users",
                    "body": "normal response",
                },
            ],
        }
    )

    classifications = {
        finding.finding_type
        for finding in findings
    }

    assert API_DOCUMENTATION in classifications
    assert GRAPHQL_ENDPOINT in classifications
    assert API_VERSION in classifications
    assert API_ENDPOINT not in classifications


def test_api_analyzer_detects_documentation_from_documents():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "documents": {
                "url": "https://example.com/openapi",
                "content": '{"openapi":"3.0.0"}',
                "mime_type": "application/json",
            },
        }
    )

    assert len(findings) == 1
    assert findings[0].finding_type == API_DOCUMENTATION
    assert findings[0].title == "API Documentation Discovered: OpenAPI"


def test_api_analyzer_accepts_http_responses():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "http_responses": [
                {
                    "target": "https://example.com/graphql",
                    "response": "__schema { queryType { name } }",
                    "mime_type": "application/json",
                }
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0].finding_type == GRAPHQL_ENDPOINT


def test_api_analyzer_accepts_explicit_evidence_channels():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "api_documentation": [
                "https://example.com/openapi.json"
            ],
            "api_endpoints": [
                "https://example.com/api/users"
            ],
            "api_routes": [
                "https://example.com/api/orders"
            ],
            "api_versions": [
                "v1",
                "v2",
            ],
        }
    )

    classifications = {
        finding.finding_type
        for finding in findings
    }

    assert classifications == {
        API_DOCUMENTATION,
        API_ENDPOINT,
        API_VERSION,
    }

    endpoints = [
        finding
        for finding in findings
        if finding.finding_type == API_ENDPOINT
    ]

    assert len(endpoints) == 2


def test_api_analyzer_extracts_all_resource_input_forms():
    analyzer = APIAnalyzer()

    evidence = {
        "resources": [
            "https://example.com/swagger/",
            {"url": "https://example.com/graphql"},
            {"target": "https://example.com/api/v1/users"},
        ],
        "urls": "https://example.com/openapi.json",
        "endpoints": [
            "https://example.com/api/orders"
        ],
        "discovered_resources": [
            {"target": "https://example.com/api/v2/items"}
        ],
        "url": "https://example.com/api/v3/products",
    }

    resources = analyzer._extract_resources(evidence)

    assert resources == [
        "https://example.com/swagger/",
        "https://example.com/graphql",
        "https://example.com/api/v1/users",
        "https://example.com/openapi.json",
        "https://example.com/api/orders",
        "https://example.com/api/v2/items",
        "https://example.com/api/v3/products",
    ]


def test_api_analyzer_extract_values_normalizes_supported_forms():
    analyzer = APIAnalyzer()

    assert analyzer._extract_values(
        " https://example.com/api "
    ) == [
        "https://example.com/api"
    ]

    assert analyzer._extract_values(
        [" /api/a ", "", "/api/b"]
    ) == [
        "/api/a",
        "/api/b",
    ]

    assert analyzer._extract_values(
        {
            "/api/enabled": True,
            "/api/disabled": False,
        }
    ) == [
        "/api/enabled"
    ]

    assert analyzer._extract_values(123) == ["123"]
    assert analyzer._extract_values(None) == []


def test_api_analyzer_extracts_response_record_forms():
    analyzer = APIAnalyzer()

    evidence = {
        "responses": {
            "url": "https://example.com/a",
            "body": "body-a",
        },
        "documents": [
            {
                "url": "https://example.com/b",
                "content": "body-b",
            }
        ],
        "http_responses": [
            {
                "target": "https://example.com/c",
                "response": "body-c",
            },
            "ignored",
        ],
    }

    records = analyzer._extract_records(evidence)

    assert records == [
        {
            "url": "https://example.com/a",
            "body": "body-a",
        },
        {
            "url": "https://example.com/b",
            "content": "body-b",
        },
        {
            "target": "https://example.com/c",
            "response": "body-c",
        },
    ]


def test_api_analyzer_deduplicates_identical_resource_observations():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "resources": [
                "https://example.com/api/v1/users",
                "https://example.com/api/v1/users",
                {"url": "https://example.com/api/v1/users"},
            ],
        }
    )

    assert len(findings) == 2

    classifications = {
        finding.finding_type
        for finding in findings
    }

    assert classifications == {
        API_ENDPOINT,
        API_VERSION,
    }


def test_api_analyzer_allows_distinct_classifications_for_same_resource():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "resources": [
                "https://example.com/api/v1/users"
            ],
        }
    )

    assert {
        (
            finding.finding_type,
            finding.evidence["value"],
        )
        for finding in findings
    } == {
        (API_ENDPOINT, "API endpoint"),
        (API_VERSION, "v1"),
    }


def test_api_analyzer_deduplicates_explicit_and_resource_evidence():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "resources": [
                "https://example.com/swagger.json",
                "https://example.com/api/v1/users",
            ],
            "api_documentation": [
                "https://example.com/swagger.json"
            ],
            "api_endpoints": [
                "https://example.com/api/v1/users"
            ],
            "api_versions": [
                "v1"
            ],
        }
    )

    assert len(findings) == 6

    assert {
        finding.finding_type
        for finding in findings
    } == {
        API_DOCUMENTATION,
        API_ENDPOINT,
        API_VERSION,
    }

    assert sum(
        finding.finding_type == API_DOCUMENTATION
        for finding in findings
    ) == 2

    assert sum(
        finding.finding_type == API_ENDPOINT
        for finding in findings
    ) == 2

    assert sum(
        finding.finding_type == API_VERSION
        for finding in findings
    ) == 2


def test_api_analyzer_ignores_empty_or_unrelated_evidence():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "resources": [
                "",
                "https://example.com/",
                "https://example.com/users",
                "https://example.com/application",
            ],
            "responses": [
                {
                    "url": TARGET,
                    "body": "normal application response",
                    "content_type": "text/html",
                }
            ],
            "api_documentation": [],
            "api_endpoints": [],
            "api_routes": [],
            "api_versions": [],
        }
    )

    assert findings == []


def test_api_analyzer_observation_contract():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "resources": [
                "https://example.com/openapi.json"
            ],
        }
    )

    assert len(findings) == 1

    finding = findings[0]

    assert finding.finding_type == API_DOCUMENTATION
    assert finding.title == "API Documentation Discovered: OpenAPI"
    assert finding.severity == "Informational"
    assert finding.confidence == "High"
    assert finding.target == TARGET
    assert finding.source_tool == "scopeforgex"
    assert (
        finding.detection_method
        == "API Attack-Surface Analyzer"
    )
    assert finding.category == "api_attack_surface"
    assert finding.remediation

    assert finding.evidence == {
        "resource": "https://example.com/openapi.json",
        "value": "OpenAPI",
    }

    serialized = finding.as_dict()

    assert serialized["finding_type"] == API_DOCUMENTATION
    assert serialized["title"] == "API Documentation Discovered: OpenAPI"
    assert serialized["severity"] == "Informational"
    assert serialized["confidence"] == "High"
    assert serialized["target"] == TARGET
    assert serialized["evidence"] == {
        "resource": "https://example.com/openapi.json",
        "value": "OpenAPI",
    }


def test_api_analyzer_is_evidence_only():
    analyzer = APIAnalyzer()

    findings = analyzer.analyze(
        {
            "target": TARGET,
            "api_endpoints": [
                "https://example.com/api/users"
            ],
        }
    )

    assert len(findings) == 1
    assert findings[0].finding_type == API_ENDPOINT
    assert findings[0].evidence["resource"].endswith(
        "/api/users"
    )

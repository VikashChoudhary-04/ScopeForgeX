"""
ScopeForgeX Native Analyzers
============================

ScopeForgeX-native analysis engines.

These analyzers operate on evidence already collected by the workflow.
They do not replace external assessment tools and do not perform network
requests themselves.

Final native analyzer capabilities
-----------------------------------

- HTTP security headers
- Cookie security
- CORS
- HTTP methods
- Sensitive information exposure
- API-specific attack-surface analysis

The NativeAnalyzerEngine coordinates these analyzers without bypassing the
workflow, execution, collection, or reporting abstractions.

The analyzers produce structured observations/findings which are subsequently
normalized, correlated, deduplicated, risk-classified, and incorporated into
the final ScopeForgeX report.

Design principle
----------------

Every analyzer has a defined assessment purpose, input, output, and place
in the workflow.

No analyzer is added merely to duplicate an external tool.

v1.2.0
"""

from scopeforgex.analyzers.api import (
    APIAnalyzer,
    APIObservation,
    API_DOCUMENTATION,
    API_ENDPOINT,
    API_VERSION,
    GRAPHQL_ENDPOINT,
)

from scopeforgex.analyzers.cookies import (
    CookieObservation,
    CookieSecurityAnalyzer,
    CookiesAnalyzer,
    INSECURE_COOKIE,
    MISSING_HTTPONLY,
    MISSING_SECURE,
    WEAK_SAMESITE,
)

from scopeforgex.analyzers.cors import (
    CORSFinding,
    CORSSecurityAnalyzer,
    CORS_MISCONFIGURATION,
)

from scopeforgex.analyzers.http_headers import (
    HeaderFinding,
    HttpSecurityHeaderAnalyzer,
    MISSING_SECURITY_HEADER,
    SECURITY_HEADER_MISCONFIGURATION,
    WEAK_SECURITY_HEADER,
)

from scopeforgex.analyzers.http_methods import (
    HTTPMethodObservation,
    HTTPMethodsAnalyzer,
    HTTP_METHOD_MISCONFIGURATION,
)

from scopeforgex.analyzers.sensitive_information import (
    SensitiveInformationAnalyzer,
    SensitiveInformationObservation,
    SENSITIVE_FILE_EXPOSURE,
    INFORMATION_DISCLOSURE,
)

from scopeforgex.analyzers.engine import (
    AnalyzerResult,
    NativeAnalyzerEngine,
)


__all__ = [
    # Native analyzer engine
    "AnalyzerResult",
    "NativeAnalyzerEngine",

    # API analyzer
    "APIAnalyzer",
    "APIObservation",
    "API_DOCUMENTATION",
    "API_ENDPOINT",
    "API_VERSION",
    "GRAPHQL_ENDPOINT",

    # Cookie analyzer
    "CookieObservation",
    "CookiesAnalyzer",
    "CookieSecurityAnalyzer",
    "INSECURE_COOKIE",
    "MISSING_HTTPONLY",
    "MISSING_SECURE",
    "WEAK_SAMESITE",

    # CORS analyzer
    "CORSFinding",
    "CORSSecurityAnalyzer",
    "CORS_MISCONFIGURATION",

    # HTTP security header analyzer
    "HeaderFinding",
    "HttpSecurityHeaderAnalyzer",
    "MISSING_SECURITY_HEADER",
    "SECURITY_HEADER_MISCONFIGURATION",
    "WEAK_SECURITY_HEADER",

    # HTTP methods analyzer
    "HTTPMethodObservation",
    "HTTPMethodsAnalyzer",
    "HTTP_METHOD_MISCONFIGURATION",

    # Sensitive information analyzer
    "SensitiveInformationAnalyzer",
    "SensitiveInformationObservation",
    "SENSITIVE_FILE_EXPOSURE",
    "INFORMATION_DISCLOSURE",
]

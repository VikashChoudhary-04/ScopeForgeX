"""
ScopeForgeX API Attack-Surface Analyzer
=======================================

ScopeForgeX-native analyzer for API-specific attack-surface discovery.

The analyzer consumes evidence that has already been collected by the
ScopeForgeX workflow and produces structured API observations.

Detection targets defined by the final ScopeForgeX plan:

- Swagger
- OpenAPI
- GraphQL
- API documentation
- API versioning
- API endpoints
- API routes

Finding types:

- API_DOCUMENTATION
- API_ENDPOINT
- API_VERSION
- GRAPHQL_ENDPOINT

The analyzer does not perform network requests and does not attempt to
authenticate to, exploit, or validate discovered API functionality.

Design Principles
-----------------
- Native ScopeForgeX capability.
- Deterministic analysis.
- No external executable dependency.
- No network access.
- Analyze collected evidence only.
- Preserve source evidence.
- Produce structured observations.
- Detection is not confirmation of a vulnerability.
- API discovery is an attack-surface observation.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


###############################################################################
# Constants
###############################################################################


API_DOCUMENTATION = "API_DOCUMENTATION"
API_ENDPOINT = "API_ENDPOINT"
API_VERSION = "API_VERSION"
GRAPHQL_ENDPOINT = "GRAPHQL_ENDPOINT"


###############################################################################
# Detection Patterns
###############################################################################


API_DOCUMENTATION_PATHS = (
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
)


GRAPHQL_PATHS = (
    "/graphql",
    "/graphql/",
    "/api/graphql",
    "/api/graphql/",
)


API_VERSION_PATTERN = re.compile(
    r"(?:^|/)(v[0-9]+(?:\.[0-9]+)?)(?:/|$)",
    re.IGNORECASE,
)


API_PATH_PATTERN = re.compile(
    r"(?:^|/)(api)(?:/|$)",
    re.IGNORECASE,
)


###############################################################################
# Observation Model
###############################################################################


@dataclass(slots=True)
class APIObservation:
    """
    Normalized API attack-surface observation.

    This represents discovered API information rather than a confirmed
    security vulnerability.
    """

    finding_type: str

    title: str

    severity: str

    confidence: str

    target: str

    description: str

    evidence: dict[str, Any] = field(
        default_factory=dict,
    )

    source_tool: str = (
        "scopeforgex"
    )

    detection_method: str = (
        "API Attack-Surface Analyzer"
    )

    remediation: str = ""

    category: str = (
        "api_attack_surface"
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the observation into a stable dictionary.
        """

        return {
            "finding_type": self.finding_type,
            "title": self.title,
            "severity": self.severity,
            "confidence": self.confidence,
            "target": self.target,
            "description": self.description,
            "evidence": dict(
                self.evidence
            ),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "remediation": self.remediation,
            "category": self.category,
        }


###############################################################################
# Analyzer
###############################################################################


class APIAnalyzer:
    """
    Analyze collected evidence for API attack-surface information.

    Supported evidence forms include:

        {
            "target": "https://example.com",
            "resources": [
                "https://example.com/swagger/",
                "https://example.com/api/v1/users",
                "https://example.com/graphql",
            ],
        }

    API documentation can also be explicitly identified:

        {
            "api_documentation": [
                "https://example.com/openapi.json",
            ],
        }

    API endpoints can be supplied directly:

        {
            "api_endpoints": [
                "https://example.com/api/v1/users",
            ],
        }

    API versions can be supplied directly:

        {
            "api_versions": [
                "v1",
                "v2",
            ],
        }

    The analyzer may also inspect already-collected response/document
    metadata for Swagger, OpenAPI or GraphQL indicators.

    It does not request or retrieve any of these resources.
    """

    name = "api"

    description = (
        "Analyze collected evidence for API documentation, API endpoints, "
        "API versions and GraphQL attack-surface information."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[APIObservation]:
        """
        Analyze collected API-related evidence.

        Returns:
            A list of normalized APIObservation objects.
        """

        target = str(
            evidence.get(
                "target",
                "",
            )
        ).strip()

        observations: list[
            APIObservation
        ] = []

        seen: set[
            tuple[str, str, str]
        ] = set()

        #######################################################################
        # Resource-based API discovery
        #######################################################################

        resources = self._extract_resources(
            evidence
        )

        for resource in resources:

            resource_classifications = (
                self._classify_resource(
                    resource
                )
            )

            for classification, value in (
                resource_classifications
            ):

                key = (
                    classification,
                    resource,
                    value,
                )

                if key in seen:
                    continue

                seen.add(
                    key
                )

                observations.append(
                    self._build_observation(
                        target=target,
                        resource=resource,
                        classification=classification,
                        value=value,
                    )
                )

        #######################################################################
        # Explicit API documentation
        #######################################################################

        for resource in self._extract_values(
            evidence.get(
                "api_documentation"
            )
        ):

            key = (
                API_DOCUMENTATION,
                resource,
                "",
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            observations.append(
                self._build_observation(
                    target=target,
                    resource=resource,
                    classification=(
                        API_DOCUMENTATION
                    ),
                    value=self._documentation_type(
                        resource
                    ),
                )
            )

        #######################################################################
        # Explicit API endpoints
        #######################################################################

        for resource in self._extract_values(
            evidence.get(
                "api_endpoints"
            )
        ):

            key = (
                API_ENDPOINT,
                resource,
                "",
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            observations.append(
                self._build_observation(
                    target=target,
                    resource=resource,
                    classification=API_ENDPOINT,
                    value="API endpoint",
                )
            )

        #######################################################################
        # Explicit API routes
        #######################################################################

        for resource in self._extract_values(
            evidence.get(
                "api_routes"
            )
        ):

            key = (
                API_ENDPOINT,
                resource,
                "",
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            observations.append(
                self._build_observation(
                    target=target,
                    resource=resource,
                    classification=API_ENDPOINT,
                    value="API route",
                )
            )

        #######################################################################
        # Explicit API versions
        #######################################################################

        for version in self._extract_values(
            evidence.get(
                "api_versions"
            )
        ):

            key = (
                API_VERSION,
                target,
                version,
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            observations.append(
                self._build_observation(
                    target=target,
                    resource=target,
                    classification=API_VERSION,
                    value=version,
                )
            )

        #######################################################################
        # Response/document evidence
        #######################################################################

        for record in self._extract_records(
            evidence
        ):

            resource = str(
                record.get(
                    "url",
                    record.get(
                        "target",
                        target,
                    ),
                )
            ).strip()

            body = str(
                record.get(
                    "body",
                    record.get(
                        "response",
                        record.get(
                            "content",
                            "",
                        ),
                    ),
                )
            )

            content_type = str(
                record.get(
                    "content_type",
                    record.get(
                        "mime_type",
                        "",
                    ),
                )
            )

            text = (
                body
                + "\n"
                + content_type
            ).lower()

            ###################################################################
            # Swagger / OpenAPI
            ###################################################################

            documentation_type = (
                self._documentation_from_content(
                    text
                )
            )

            if documentation_type:

                key = (
                    API_DOCUMENTATION,
                    resource,
                    documentation_type,
                )

                if key not in seen:

                    seen.add(
                        key
                    )

                    observations.append(
                        self._build_observation(
                            target=target,
                            resource=resource,
                            classification=(
                                API_DOCUMENTATION
                            ),
                            value=documentation_type,
                        )
                    )

            ###################################################################
            # GraphQL
            ###################################################################

            if self._contains_graphql_indicator(
                text
            ):

                key = (
                    GRAPHQL_ENDPOINT,
                    resource,
                    "",
                )

                if key not in seen:

                    seen.add(
                        key
                    )

                    observations.append(
                        self._build_observation(
                            target=target,
                            resource=resource,
                            classification=(
                                GRAPHQL_ENDPOINT
                            ),
                            value="GraphQL",
                        )
                    )

            ###################################################################
            # API version
            ###################################################################

            version = self._extract_api_version(
                resource
            )

            if version:

                key = (
                    API_VERSION,
                    resource,
                    version,
                )

                if key not in seen:

                    seen.add(
                        key
                    )

                    observations.append(
                        self._build_observation(
                            target=target,
                            resource=resource,
                            classification=(
                                API_VERSION
                            ),
                            value=version,
                        )
                    )

        return observations

    # ------------------------------------------------------------------
    # Resource Extraction
    # ------------------------------------------------------------------

    @classmethod
    def _extract_resources(
        cls,
        evidence: Mapping[str, Any],
    ) -> list[str]:
        """
        Extract resources from common collected-evidence fields.
        """

        values: list[Any] = []

        for key in (
            "resources",
            "urls",
            "endpoints",
            "discovered_resources",
        ):

            value = evidence.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                str,
            ):

                values.append(
                    value
                )

            elif isinstance(
                value,
                Iterable,
            ) and not isinstance(
                value,
                Mapping,
            ):

                values.extend(
                    value
                )

        single_url = evidence.get(
            "url"
        )

        if single_url:
            values.append(
                single_url
            )

        resources: list[str] = []

        for item in values:

            if isinstance(
                item,
                Mapping,
            ):

                resource = str(
                    item.get(
                        "url",
                        item.get(
                            "target",
                            "",
                        ),
                    )
                ).strip()

            else:

                resource = str(
                    item
                ).strip()

            if resource:
                resources.append(
                    resource
                )

        return resources

    @staticmethod
    def _extract_values(
        value: Any,
    ) -> list[str]:
        """
        Normalize evidence values into strings.
        """

        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):

            text = value.strip()

            return (
                [text]
                if text
                else []
            )

        if isinstance(
            value,
            Mapping,
        ):

            values: list[str] = []

            for key, enabled in value.items():

                if not enabled:
                    continue

                text = str(
                    key
                ).strip()

                if text:
                    values.append(
                        text
                    )

            return values

        if isinstance(
            value,
            Iterable,
        ) and not isinstance(
            value,
            (str, bytes),
        ):

            values = []

            for item in value:

                text = str(
                    item
                ).strip()

                if text:
                    values.append(
                        text
                    )

            return values

        text = str(
            value
        ).strip()

        return (
            [text]
            if text
            else []
        )

    @staticmethod
    def _extract_records(
        evidence: Mapping[str, Any],
    ) -> list[Mapping[str, Any]]:
        """
        Extract collected response/document records.
        """

        records: list[Mapping[str, Any]] = []

        for key in (
            "responses",
            "documents",
            "http_responses",
        ):

            value = evidence.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                Mapping,
            ):

                records.append(
                    value
                )

                continue

            if isinstance(
                value,
                Iterable,
            ) and not isinstance(
                value,
                (str, bytes),
            ):

                for item in value:

                    if isinstance(
                        item,
                        Mapping,
                    ):

                        records.append(
                            item
                        )

        return records

    # ------------------------------------------------------------------
    # Resource Classification
    # ------------------------------------------------------------------

    @classmethod
    def _classify_resource(
        cls,
        resource: str,
    ) -> list[tuple[str, str]]:
        """
        Classify a resource using plan-defined API categories.
        """

        parsed = urlparse(
            resource
        )

        if parsed.scheme or parsed.netloc:

            path = (
                parsed.path
                or "/"
            )

        else:

            path = (
                resource
                .split(
                    "?",
                    1,
                )[0]
                .split(
                    "#",
                    1,
                )[0]
            )

        normalized_path = (
            path
            .strip()
            .lower()
            .replace(
                "\\",
                "/",
            )
        )

        classifications: list[
            tuple[str, str]
        ] = []

        #######################################################################
        # API documentation
        #######################################################################

        if cls._is_documentation_path(
            normalized_path
        ):

            classifications.append(
                (
                    API_DOCUMENTATION,
                    cls._documentation_type(
                        normalized_path
                    ),
                )
            )

        #######################################################################
        # GraphQL
        #######################################################################

        if cls._is_graphql_path(
            normalized_path
        ):

            classifications.append(
                (
                    GRAPHQL_ENDPOINT,
                    "GraphQL",
                )
            )

        #######################################################################
        # API endpoint
        #######################################################################

        if cls._is_api_endpoint(
            normalized_path
        ):

            classifications.append(
                (
                    API_ENDPOINT,
                    "API endpoint",
                )
            )

        #######################################################################
        # API version
        #######################################################################

        version = cls._extract_api_version(
            resource
        )

        if version:

            classifications.append(
                (
                    API_VERSION,
                    version,
                )
            )

        return classifications

    @staticmethod
    def _is_documentation_path(
        path: str,
    ) -> bool:
        """
        Identify known Swagger/OpenAPI/API documentation paths.
        """

        return (
            path in API_DOCUMENTATION_PATHS
            or any(
                path.startswith(
                    prefix
                )
                for prefix in (
                    "/swagger-ui/",
                    "/openapi/",
                    "/swagger/",
                    "/api-docs/",
                    "/apidocs/",
                )
            )
        )

    @staticmethod
    def _is_graphql_path(
        path: str,
    ) -> bool:
        """
        Identify known GraphQL endpoint paths.
        """

        return (
            path in GRAPHQL_PATHS
            or path.startswith(
                "/graphql/"
            )
            or path.startswith(
                "/api/graphql/"
            )
        )

    @staticmethod
    def _is_api_endpoint(
        path: str,
    ) -> bool:
        """
        Identify API routes from explicit /api/ path structure.

        This is intentionally conservative. A generic endpoint is not treated
        as an API endpoint merely because its name looks like one.
        """

        return bool(
            API_PATH_PATTERN.search(
                path
            )
        )

    # ------------------------------------------------------------------
    # Documentation Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _documentation_type(
        resource: str,
    ) -> str:
        """
        Determine the documentation type from a resource name/path.
        """

        normalized = (
            resource
            .strip()
            .lower()
        )

        if (
            "swagger" in normalized
        ):

            return "Swagger"

        if (
            "openapi" in normalized
            or normalized.endswith(
                (
                    ".yaml",
                    ".yml",
                    ".json",
                )
            )
        ):

            return "OpenAPI"

        if (
            "api-docs" in normalized
            or "apidocs" in normalized
        ):

            return "API documentation"

        return "API documentation"

    @staticmethod
    def _documentation_from_content(
        text: str,
    ) -> str | None:
        """
        Identify Swagger/OpenAPI documentation from collected content.
        """

        if (
            '"openapi"' in text
            or "'openapi'" in text
            or "openapi:" in text
        ):

            return "OpenAPI"

        if (
            '"swagger"' in text
            or "'swagger'" in text
            or "swagger:" in text
        ):

            return "Swagger"

        return None

    # ------------------------------------------------------------------
    # GraphQL Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _contains_graphql_indicator(
        text: str,
    ) -> bool:
        """
        Identify explicit GraphQL indicators in collected evidence.
        """

        indicators = (
            "graphql",
            "__schema",
            "__typename",
            "introspectionquery",
        )

        return any(
            indicator in text
            for indicator in indicators
        )

    # ------------------------------------------------------------------
    # API Version Detection
    # ------------------------------------------------------------------

    @staticmethod
    def _extract_api_version(
        resource: str,
    ) -> str | None:
        """
        Extract a conventional API version such as v1 or v2.
        """

        parsed = urlparse(
            resource
        )

        if parsed.scheme or parsed.netloc:

            path = (
                parsed.path
                or ""
            )

        else:

            path = (
                resource
                .split(
                    "?",
                    1,
                )[0]
                .split(
                    "#",
                    1,
                )[0]
            )

        match = API_VERSION_PATTERN.search(
            path
        )

        if not match:
            return None

        return match.group(
            1
        ).lower()

    # ------------------------------------------------------------------
    # Observation Construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_observation(
        target: str,
        resource: str,
        classification: str,
        value: str,
    ) -> APIObservation:
        """
        Construct a normalized API observation.
        """

        #######################################################################
        # API documentation
        #######################################################################

        if classification == API_DOCUMENTATION:

            title = (
                f"API Documentation Discovered: {value}"
            )

            description = (
                f"{value} documentation was identified in the collected "
                "assessment evidence. API documentation can expose API "
                "routes, parameters and implementation information."
            )

            remediation = (
                "Review whether API documentation is intended to be "
                "publicly accessible. Restrict sensitive API documentation "
                "when public exposure is not required."
            )

        #######################################################################
        # API endpoint
        #######################################################################

        elif classification == API_ENDPOINT:

            title = (
                "API Endpoint Discovered"
            )

            description = (
                "An API endpoint or API route was identified in the "
                "collected assessment evidence."
            )

            remediation = (
                "Review the discovered API endpoint and ensure that "
                "authentication, authorization and intended exposure are "
                "appropriate for the application."
            )

        #######################################################################
        # API version
        #######################################################################

        elif classification == API_VERSION:

            title = (
                f"API Version Discovered: {value}"
            )

            description = (
                f"API version {value} was identified in the collected "
                "assessment evidence."
            )

            remediation = (
                "Maintain an inventory of exposed API versions and review "
                "older versions to ensure that they remain intentionally "
                "supported and appropriately protected."
            )

        #######################################################################
        # GraphQL
        #######################################################################

        elif classification == GRAPHQL_ENDPOINT:

            title = (
                "GraphQL Endpoint Discovered"
            )

            description = (
                "A GraphQL endpoint was identified in the collected "
                "assessment evidence."
            )

            remediation = (
                "Review the GraphQL endpoint and ensure that its "
                "authentication, authorization and intended exposure are "
                "appropriate."
            )

        #######################################################################
        # Defensive fallback
        #######################################################################

        else:

            title = (
                "API Attack Surface Discovered"
            )

            description = (
                "API-related attack-surface information was identified "
                "in the collected assessment evidence."
            )

            remediation = (
                "Review the discovered API resource and confirm that its "
                "exposure is intentional and appropriately protected."
            )

        return APIObservation(
            finding_type=classification,
            title=title,
            severity="Informational",
            confidence="High",
            target=target,
            description=description,
            evidence={
                "resource": resource,
                "value": value,
            },
            remediation=remediation,
        )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "API_DOCUMENTATION",
    "API_ENDPOINT",
    "API_VERSION",
    "GRAPHQL_ENDPOINT",
    "APIObservation",
    "APIAnalyzer",
]

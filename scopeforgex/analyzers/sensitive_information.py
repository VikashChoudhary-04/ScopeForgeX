"""
ScopeForgeX Sensitive Information Analyzer
==========================================

ScopeForgeX-native analyzer for sensitive information exposure.

The analyzer operates only on resources and evidence that have already been
collected by the ScopeForgeX assessment workflow.

Detection categories defined by the final ScopeForgeX plan:

- .env files
- .git resources
- backup files
- source maps
- configuration files
- debug endpoints
- directory listings

Finding types:

- SENSITIVE_FILE_EXPOSURE
- INFORMATION_DISCLOSURE

The analyzer does not perform network requests and does not attempt to
retrieve or exploit discovered resources.

Design Principles
-----------------
- Native ScopeForgeX capability.
- Deterministic analysis.
- No external executable dependency.
- No network access.
- Analyze collected evidence only.
- Preserve source evidence.
- Produce structured observations.
- Do not claim exploitation or vulnerability confirmation.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Iterable, Mapping
from urllib.parse import urlparse


###############################################################################
# Constants
###############################################################################


SENSITIVE_FILE_EXPOSURE = (
    "SENSITIVE_FILE_EXPOSURE"
)

INFORMATION_DISCLOSURE = (
    "INFORMATION_DISCLOSURE"
)


###############################################################################
# Detection Definitions
###############################################################################


ENV_INDICATORS = (
    ".env",
    "/.env",
)

GIT_INDICATORS = (
    "/.git",
    "/.git/",
)

BACKUP_SUFFIXES = (
    ".bak",
    ".backup",
    ".old",
    ".orig",
    ".save",
    ".swp",
    ".swo",
    ".tmp",
    ".backup~",
)

BACKUP_FILENAMES = (
    "backup",
    "backups",
)

SOURCE_MAP_SUFFIXES = (
    ".map",
)

CONFIGURATION_SUFFIXES = (
    ".conf",
    ".config",
    ".cfg",
    ".ini",
    ".properties",
    ".yaml",
    ".yml",
    ".toml",
)

CONFIGURATION_FILENAMES = (
    "config",
    "configuration",
)

DEBUG_ENDPOINT_INDICATORS = (
    "/debug",
    "/debug/",
    "/debugger",
    "/debugger/",
    "/actuator",
    "/actuator/",
    "/actuator/env",
    "/actuator/configprops",
    "/server-status",
    "/server-info",
    "/phpinfo",
    "/phpinfo.php",
)

DIRECTORY_LISTING_INDICATORS = (
    "index of /",
    "directory listing",
    "directory listing for",
)


###############################################################################
# Observation Model
###############################################################################


@dataclass(slots=True)
class SensitiveInformationObservation:
    """
    Normalized sensitive-information observation.

    This represents discovered assessment information. It is not an
    automatically confirmed vulnerability.
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
        "Sensitive Information Analyzer"
    )

    remediation: str = ""

    category: str = (
        "information_disclosure"
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the observation.
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


class SensitiveInformationAnalyzer:
    """
    Analyze collected resources for sensitive-information exposure.

    Expected evidence may contain:

        {
            "target": "https://example.com",
            "resources": [
                "https://example.com/.env",
                "https://example.com/.git/",
                "https://example.com/app.js.map",
                "https://example.com/debug",
            ],
        }

    Resource records are also supported:

        {
            "resources": [
                {
                    "url": "https://example.com/.env",
                    "status": 200,
                }
            ]
        }

    Directory-listing evidence can be supplied as:

        {
            "directory_listings": [
                "https://example.com/files/"
            ]
        }

    Or through response/body evidence:

        {
            "responses": [
                {
                    "url": "https://example.com/files/",
                    "body": "Index of /files/"
                }
            ]
        }

    The analyzer does not request, download or inspect remote resources.
    It only analyzes evidence supplied by earlier workflow stages.
    """

    name = "sensitive_information"

    description = (
        "Analyze collected resources and response evidence for sensitive "
        "file exposure and information disclosure."
    )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[SensitiveInformationObservation]:
        """
        Analyze collected evidence.

        Returns:
            A list of normalized sensitive-information observations.
        """

        target = str(
            evidence.get(
                "target",
                "",
            )
        ).strip()

        observations: list[
            SensitiveInformationObservation
        ] = []

        seen: set[
            tuple[str, str]
        ] = set()

        #######################################################################
        # Resource evidence
        #######################################################################

        for resource in self._extract_resources(
            evidence
        ):

            classifications = (
                self._classify_resource(
                    resource
                )
            )

            for classification in classifications:

                key = (
                    resource,
                    classification,
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
                    )
                )

        #######################################################################
        # Explicit directory-listing evidence
        #######################################################################

        for resource in self._extract_values(
            evidence.get(
                "directory_listings"
            )
        ):

            key = (
                resource,
                SENSITIVE_FILE_EXPOSURE,
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
                        "directory_listing"
                    ),
                )
            )

        #######################################################################
        # Response evidence
        #######################################################################

        for response in self._extract_responses(
            evidence
        ):

            url = response.get(
                "url",
                target,
            )

            body = response.get(
                "body",
                response.get(
                    "response",
                    "",
                ),
            )

            if not body:
                continue

            if self._is_directory_listing(
                str(body)
            ):

                key = (
                    url,
                    "directory_listing",
                )

                if key not in seen:

                    seen.add(
                        key
                    )

                    observations.append(
                        self._build_observation(
                            target=target,
                            resource=url,
                            classification=(
                                "directory_listing"
                            ),
                        )
                    )

            debug_classification = (
                self._classify_debug_content(
                    str(body)
                )
            )

            if debug_classification:

                key = (
                    url,
                    debug_classification,
                )

                if key not in seen:

                    seen.add(
                        key
                    )

                    observations.append(
                        self._build_observation(
                            target=target,
                            resource=url,
                            classification=(
                                debug_classification
                            ),
                        )
                    )

        #######################################################################
        # Explicit debug endpoints
        #######################################################################

        for resource in self._extract_values(
            evidence.get(
                "debug_endpoints"
            )
        ):

            key = (
                resource,
                "debug_endpoint",
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
                        "debug_endpoint"
                    ),
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
        Extract resource URLs/paths from collected evidence.
        """

        raw_resources: list[Any] = []

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

                raw_resources.append(
                    value
                )

            elif isinstance(
                value,
                Iterable,
            ) and not isinstance(
                value,
                Mapping,
            ):

                raw_resources.extend(
                    value
                )

        single_url = evidence.get(
            "url"
        )

        if single_url:
            raw_resources.append(
                single_url
            )

        normalized: list[str] = []

        for item in raw_resources:

            if isinstance(
                item,
                Mapping,
            ):

                url = str(
                    item.get(
                        "url",
                        item.get(
                            "target",
                            "",
                        ),
                    )
                ).strip()

            else:

                url = str(
                    item
                ).strip()

            if url:
                normalized.append(
                    url
                )

        return normalized

    @staticmethod
    def _extract_values(
        value: Any,
    ) -> list[str]:
        """
        Normalize arbitrary evidence values into strings.
        """

        if value is None:
            return []

        if isinstance(
            value,
            str,
        ):

            return (
                [value.strip()]
                if value.strip()
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

            return [
                str(
                    item
                ).strip()
                for item in value
                if str(
                    item
                ).strip()
            ]

        text = str(
            value
        ).strip()

        return (
            [text]
            if text
            else []
        )

    @staticmethod
    def _extract_responses(
        evidence: Mapping[str, Any],
    ) -> list[dict[str, str]]:
        """
        Extract response records from collected evidence.
        """

        raw_responses = evidence.get(
            "responses",
            []
        )

        if isinstance(
            raw_responses,
            Mapping,
        ):

            raw_responses = [
                raw_responses
            ]

        if isinstance(
            raw_responses,
            str,
        ):

            return [
                {
                    "url": str(
                        evidence.get(
                            "target",
                            "",
                        )
                    ),
                    "body": raw_responses,
                }
            ]

        responses: list[
            dict[str, str]
        ] = []

        if not isinstance(
            raw_responses,
            Iterable,
        ):
            return responses

        for response in raw_responses:

            if not isinstance(
                response,
                Mapping,
            ):
                continue

            responses.append(
                {
                    "url": str(
                        response.get(
                            "url",
                            response.get(
                                "target",
                                evidence.get(
                                    "target",
                                    "",
                                ),
                            ),
                        )
                    ).strip(),
                    "body": str(
                        response.get(
                            "body",
                            response.get(
                                "response",
                                "",
                            ),
                        )
                    ),
                }
            )

        return responses

    # ------------------------------------------------------------------
    # Resource Classification
    # ------------------------------------------------------------------

    @classmethod
    def _classify_resource(
        cls,
        resource: str,
    ) -> list[str]:
        """
        Classify a resource against the plan-defined categories.
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

        classifications: list[str] = []

        #######################################################################
        # .env
        #######################################################################

        if cls._is_env_resource(
            normalized_path
        ):

            classifications.append(
                "env_file"
            )

        #######################################################################
        # .git
        #######################################################################

        if cls._is_git_resource(
            normalized_path
        ):

            classifications.append(
                "git_resource"
            )

        #######################################################################
        # Backup files
        #######################################################################

        if cls._is_backup_resource(
            normalized_path
        ):

            classifications.append(
                "backup_file"
            )

        #######################################################################
        # Source maps
        #######################################################################

        if cls._is_source_map(
            normalized_path
        ):

            classifications.append(
                "source_map"
            )

        #######################################################################
        # Configuration files
        #######################################################################

        if cls._is_configuration_resource(
            normalized_path
        ):

            classifications.append(
                "configuration_file"
            )

        #######################################################################
        # Debug endpoints
        #######################################################################

        if cls._is_debug_endpoint(
            normalized_path
        ):

            classifications.append(
                "debug_endpoint"
            )

        #######################################################################
        # Directory listing
        #######################################################################

        if cls._is_directory_listing_path(
            normalized_path
        ):

            classifications.append(
                "directory_listing"
            )

        return classifications

    @staticmethod
    def _is_env_resource(
        path: str,
    ) -> bool:
        """
        Detect .env resources.
        """

        filename = path.rstrip(
            "/"
        ).rsplit(
            "/",
            1,
        )[-1]

        return (
            filename == ".env"
            or filename.startswith(
                ".env."
            )
        )

    @staticmethod
    def _is_git_resource(
        path: str,
    ) -> bool:
        """
        Detect .git resources.
        """

        return (
            path == "/.git"
            or path.startswith(
                "/.git/"
            )
        )

    @staticmethod
    def _is_backup_resource(
        path: str,
    ) -> bool:
        """
        Detect common backup files.
        """

        filename = path.rstrip(
            "/"
        ).rsplit(
            "/",
            1,
        )[-1]

        lowered_filename = (
            filename.lower()
        )

        if lowered_filename in BACKUP_FILENAMES:
            return True

        return any(
            lowered_filename.endswith(
                suffix
            )
            for suffix in BACKUP_SUFFIXES
        )

    @staticmethod
    def _is_source_map(
        path: str,
    ) -> bool:
        """
        Detect JavaScript/CSS source-map resources.
        """

        return path.endswith(
            SOURCE_MAP_SUFFIXES
        )

    @staticmethod
    def _is_configuration_resource(
        path: str,
    ) -> bool:
        """
        Detect common configuration resources.
        """

        filename = path.rstrip(
            "/"
        ).rsplit(
            "/",
            1,
        )[-1]

        lowered_filename = (
            filename.lower()
        )

        if lowered_filename in CONFIGURATION_FILENAMES:
            return True

        return any(
            lowered_filename.endswith(
                suffix
            )
            for suffix in CONFIGURATION_SUFFIXES
        )

    @staticmethod
    def _is_debug_endpoint(
        path: str,
    ) -> bool:
        """
        Detect common debug endpoints.
        """

        for indicator in DEBUG_ENDPOINT_INDICATORS:

            if (
                path == indicator
                or path.startswith(
                    indicator
                )
            ):
                return True

        return False

    @staticmethod
    def _is_directory_listing_path(
        path: str,
    ) -> bool:
        """
        Identify likely directory-listing resources.

        A path ending in '/' alone is not considered a directory listing
        because that would produce excessive false positives. Actual listing
        detection is performed from explicit listing evidence where possible.
        """

        return False

    # ------------------------------------------------------------------
    # Response Classification
    # ------------------------------------------------------------------

    @staticmethod
    def _is_directory_listing(
        body: str,
    ) -> bool:
        """
        Detect directory-listing indicators in collected response evidence.
        """

        normalized = (
            body
            .strip()
            .lower()
        )

        return any(
            indicator in normalized
            for indicator in DIRECTORY_LISTING_INDICATORS
        )

    @staticmethod
    def _classify_debug_content(
        body: str,
    ) -> str | None:
        """
        Identify debug-information disclosure from collected content.

        This remains intentionally conservative and only recognizes explicit
        debug-oriented indicators.
        """

        normalized = (
            body
            .strip()
            .lower()
        )

        debug_indicators = (
            "phpinfo()",
            "phpinfo",
            "debug toolbar",
            "debug mode",
        )

        if any(
            indicator in normalized
            for indicator in debug_indicators
        ):

            return "debug_content"

        return None

    # ------------------------------------------------------------------
    # Observation Construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_observation(
        target: str,
        resource: str,
        classification: str,
    ) -> SensitiveInformationObservation:
        """
        Build a normalized sensitive-information observation.
        """

        #######################################################################
        # Sensitive file / resource exposure
        #######################################################################

        if classification == "env_file":

            title = (
                "Environment File Exposed"
            )

            finding_type = (
                SENSITIVE_FILE_EXPOSURE
            )

            description = (
                "An environment file was identified in the collected "
                "assessment evidence. Environment files may contain "
                "configuration values or secrets."
            )

        elif classification == "git_resource":

            title = (
                "Git Resource Exposed"
            )

            finding_type = (
                SENSITIVE_FILE_EXPOSURE
            )

            description = (
                "A Git metadata resource was identified in the collected "
                "assessment evidence."
            )

        elif classification == "backup_file":

            title = (
                "Backup File Exposed"
            )

            finding_type = (
                SENSITIVE_FILE_EXPOSURE
            )

            description = (
                "A backup or temporary file was identified in the "
                "collected assessment evidence."
            )

        elif classification == "source_map":

            title = (
                "Source Map Exposed"
            )

            finding_type = (
                INFORMATION_DISCLOSURE
            )

            description = (
                "A source-map resource was identified in the collected "
                "assessment evidence. Source maps may expose source-code "
                "structure or implementation details."
            )

        elif classification == "configuration_file":

            title = (
                "Configuration File Exposed"
            )

            finding_type = (
                SENSITIVE_FILE_EXPOSURE
            )

            description = (
                "A configuration resource was identified in the collected "
                "assessment evidence."
            )

        elif classification == "debug_endpoint":

            title = (
                "Debug Endpoint Discovered"
            )

            finding_type = (
                INFORMATION_DISCLOSURE
            )

            description = (
                "A debug-oriented endpoint was identified in the collected "
                "assessment evidence."
            )

        elif classification == "directory_listing":

            title = (
                "Directory Listing Discovered"
            )

            finding_type = (
                INFORMATION_DISCLOSURE
            )

            description = (
                "Directory-listing evidence was identified in the "
                "collected assessment evidence."
            )

        elif classification == "debug_content":

            title = (
                "Debug Information Disclosed"
            )

            finding_type = (
                INFORMATION_DISCLOSURE
            )

            description = (
                "Debug-oriented information was identified in the collected "
                "response evidence."
            )

        else:

            title = (
                "Sensitive Information Exposure Identified"
            )

            finding_type = (
                SENSITIVE_FILE_EXPOSURE
            )

            description = (
                "A potentially sensitive resource was identified in the "
                "collected assessment evidence."
            )

        return SensitiveInformationObservation(
            finding_type=finding_type,
            title=title,
            severity="Informational",
            confidence="High",
            target=target,
            description=description,
            evidence={
                "resource": resource,
                "classification": classification,
            },
            remediation=(
                "Review whether the identified resource or information "
                "needs to be publicly accessible. Remove unnecessary "
                "exposure and restrict access to sensitive resources."
            ),
        )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "SENSITIVE_FILE_EXPOSURE",
    "INFORMATION_DISCLOSURE",
    "SensitiveInformationObservation",
    "SensitiveInformationAnalyzer",
]

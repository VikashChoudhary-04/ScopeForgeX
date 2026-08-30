"""
ScopeForgeX WhatWeb Collector
==============================

Parses WhatWeb output into structured ScopeForgeX observations.

WhatWeb is responsible for technology fingerprinting.

Primary observations:

    TECHNOLOGY
    FRAMEWORK
    CMS
    SERVER
    LIBRARY

Architecture
------------

WhatWeb
    ↓
ExecutionResult
    ↓
Raw Evidence
    ↓
WhatWebCollector
    ↓
CollectorObservation
    ↓
Finding Normalizer
    ↓
Universal Finding

Design Principles
-----------------

- The collector never executes WhatWeb.
- The collector never constructs WhatWeb commands.
- Raw WhatWeb output remains preserved in the ExecutionResult artifacts.
- JSON, JSONL and common plain-text WhatWeb output are supported.
- Duplicate observations are removed deterministically.
- Technology classification is normalized without assigning final risk.
- Version information is preserved when available.
- Collection failures do not destroy the original execution result.

v1.0.0
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
    read_text_file,
)


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "whatweb"

OBSERVATION_TECHNOLOGY = "TECHNOLOGY"
OBSERVATION_FRAMEWORK = "FRAMEWORK"
OBSERVATION_CMS = "CMS"
OBSERVATION_SERVER = "SERVER"
OBSERVATION_LIBRARY = "LIBRARY"


###############################################################################
# Collector
###############################################################################


class WhatWebCollector(CollectorBase):
    """
    Collect structured technology observations from WhatWeb output.

    WhatWeb can produce structured JSON as well as human-readable output.
    Structured output is preferred when available, while plain-text output
    remains supported for compatibility with common command-line usage.
    """

    name = "whatweb"
    tool = "whatweb"

    description = (
        "Parses WhatWeb fingerprinting output into technology, framework, "
        "CMS, server and library observations."
    )

    supported_input_types = (
        "execution_result",
        "raw_file",
        "text",
    )

    ###########################################################################
    # Input Validation
    ###########################################################################

    def validate_input(
        self,
        execution_result: Any,
    ) -> None:
        """
        Validate the supplied execution result.
        """

        super().validate_input(
            execution_result
        )

    ###########################################################################
    # Parsing
    ###########################################################################

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        """
        Parse WhatWeb output into structured observations.

        The parser checks:

        1. ExecutionResult stdout
        2. ExecutionResult artifacts

        Artifact content is preserved as an additional evidence source.
        """

        target = self._resolve_target(
            execution_result,
            ctx,
        )

        contents = self._collect_input_contents(
            execution_result,
            ctx,
        )

        if not contents:
            return []

        observations: list[CollectorObservation] = []

        seen: set[
            tuple[
                str,
                str,
                str | None,
                str | None,
            ]
        ] = set()

        for source, content in contents:

            for record in self._iter_records(
                content
            ):

                parsed_records = self._parse_record(
                    record
                )

                for parsed in parsed_records:

                    url = self._normalize_url(
                        parsed.get(
                            "url"
                        )
                    )

                    for technology in parsed.get(
                        "technologies",
                        [],
                    ):

                        observation_type = (
                            self._classify_technology(
                                technology.get(
                                    "name",
                                    ""
                                )
                            )
                        )

                        name = self._normalize_name(
                            technology.get(
                                "name",
                                ""
                            )
                        )

                        if not name:
                            continue

                        version = self._normalize_name(
                            technology.get(
                                "version"
                            )
                        )

                        category = self._normalize_name(
                            technology.get(
                                "category"
                            )
                        )

                        key = (
                            observation_type,
                            name.lower(),
                            version.lower()
                            if version
                            else None,
                            url,
                        )

                        if key in seen:
                            continue

                        seen.add(
                            key
                        )

                        evidence = {
                            "record": record,
                            "technology": name,
                        }

                        if version:
                            evidence[
                                "version"
                            ] = version

                        if category:
                            evidence[
                                "category"
                            ] = category

                        if url:
                            evidence[
                                "url"
                            ] = url

                        observations.append(
                            CollectorObservation(
                                observation_type=(
                                    observation_type
                                ),
                                value=(
                                    f"{name} "
                                    f"({version})"
                                    if version
                                    else name
                                ),
                                target=target,
                                host=self._extract_host(
                                    url
                                ),
                                port=self._extract_port(
                                    url
                                ),
                                url=url,
                                evidence=evidence,
                                source_tool=TOOL_NAME,
                                detection_method=(
                                    "WhatWeb technology fingerprinting"
                                ),
                                confidence="informational",
                                metadata={
                                    "source": source,
                                    "technology": name,
                                    "version": version,
                                    "whatweb_category": category,
                                },
                            )
                        )

        return observations

    ###########################################################################
    # Input Collection
    ###########################################################################

    def _collect_input_contents(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[tuple[str, str]]:
        """
        Return available WhatWeb evidence as labelled text.

        Duplicate artifact paths are processed only once.
        """

        contents: list[tuple[str, str]] = []

        stdout = getattr(
            execution_result,
            "stdout",
            "",
        )

        if stdout:
            contents.append(
                (
                    "stdout",
                    str(stdout),
                )
            )

        artifacts = ctx.get(
            "artifacts",
            [],
        )

        seen_paths: set[str] = set()

        for artifact in artifacts:

            path = self._artifact_path(
                artifact
            )

            if path is None:
                continue

            normalized_path = str(
                path
            )

            if normalized_path in seen_paths:
                continue

            seen_paths.add(
                normalized_path
            )

            content = read_text_file(
                path
            )

            if content:
                contents.append(
                    (
                        normalized_path,
                        content,
                    )
                )

        return contents

    @staticmethod
    def _artifact_path(
        artifact: Any,
    ) -> Path | None:
        """
        Resolve an artifact into a filesystem path.
        """

        if artifact is None:
            return None

        if hasattr(
            artifact,
            "path",
        ):
            value = artifact.path
        else:
            value = artifact

        if value is None:
            return None

        return Path(
            str(value)
        )

    ###########################################################################
    # Record Parsing
    ###########################################################################

    def _iter_records(
        self,
        content: str,
    ) -> list[Any]:
        """
        Convert WhatWeb output into logical records.

        Supports:

        - JSON objects
        - JSON arrays
        - JSONL objects
        - Plain-text lines
        """

        stripped_content = content.strip()

        if not stripped_content:
            return []

        parsed_json = self._try_parse_json(
            stripped_content
        )

        if parsed_json is not None:
            if isinstance(
                parsed_json,
                list,
            ):
                return list(
                    parsed_json
                )

            return [
                parsed_json
            ]

        records: list[Any] = []

        for line in content.splitlines():

            stripped = line.strip()

            if not stripped:
                continue

            parsed_line = self._try_parse_json(
                stripped
            )

            if parsed_line is not None:
                if isinstance(
                    parsed_line,
                    list,
                ):
                    records.extend(
                        parsed_line
                    )
                else:
                    records.append(
                        parsed_line
                    )

                continue

            records.append(
                stripped
            )

        return records

    @staticmethod
    def _try_parse_json(
        value: str,
    ) -> Any | None:
        """
        Attempt to decode a JSON value.
        """

        try:
            return json.loads(
                value
            )

        except (
            json.JSONDecodeError,
            TypeError,
        ):
            return None

    def _parse_record(
        self,
        record: Any,
    ) -> list[dict[str, Any]]:
        """
        Parse one WhatWeb record.

        Structured records are preferred. Plain-text records are parsed using
        conservative patterns so that arbitrary command output is not treated
        as a technology finding.
        """

        if isinstance(
            record,
            Mapping,
        ):
            return self._parse_mapping_record(
                record
            )

        if isinstance(
            record,
            str,
        ):
            return self._parse_text_record(
                record
            )

        return []

    def _parse_mapping_record(
        self,
        record: Mapping[str, Any],
    ) -> list[dict[str, Any]]:
        """
        Parse a structured WhatWeb record.
        """

        url = self._extract_url(
            record
        )

        technologies: list[dict[str, str]] = []

        plugins = record.get(
            "plugins"
        )

        if isinstance(
            plugins,
            Mapping,
        ):
            technologies.extend(
                self._plugins_to_technologies(
                    plugins
                )
            )

        elif isinstance(
            plugins,
            list,
        ):
            for plugin in plugins:

                if isinstance(
                    plugin,
                    Mapping,
                ):
                    technologies.extend(
                        self._mapping_to_technology(
                            plugin
                        )
                    )

        technologies.extend(
            self._extract_technology_fields(
                record
            )
        )

        technologies = self._deduplicate_technologies(
            technologies
        )

        if not technologies:
            return []

        return [
            {
                "url": url,
                "technologies": technologies,
            }
        ]

    def _parse_text_record(
        self,
        record: str,
    ) -> list[dict[str, Any]]:
        """
        Parse a common human-readable WhatWeb output line.

        Typical forms include:

            http://example.com [200 OK] Apache, PHP, WordPress

        The parser intentionally treats only the recognizable technology
        portion as structured data.
        """

        url_match = re.search(
            r"(https?://[^\s\[]+)",
            record,
            re.IGNORECASE,
        )

        if not url_match:
            return []

        url = url_match.group(
            1
        )

        technology_text = record[
            url_match.end():
        ]

        technology_text = re.sub(
            r"^\s*\[[^\]]*\]\s*",
            "",
            technology_text,
        ).strip()

        if not technology_text:
            return []

        technologies: list[dict[str, str]] = []

        for item in self._split_text_plugins(
            technology_text
        ):

            technology = self._parse_text_plugin(
                item
            )

            if technology is not None:
                technologies.append(
                    technology
                )

        technologies = self._deduplicate_technologies(
            technologies
        )

        if not technologies:
            return []

        return [
            {
                "url": url,
                "technologies": technologies,
            }
        ]

    @staticmethod
    def _split_text_plugins(
        value: str,
    ) -> list[str]:
        """
        Split a human-readable plugin list conservatively.

        WhatWeb commonly separates plugins using commas. Parenthesized
        version information is preserved.
        """

        return [
            item.strip()
            for item in value.split(
                ","
            )
            if item.strip()
        ]

    @staticmethod
    def _parse_text_plugin(
        value: str,
    ) -> dict[str, str] | None:
        """
        Parse one human-readable plugin name and optional version.
        """

        value = value.strip()

        if not value:
            return None

        value = re.sub(
            r"\s+",
            " ",
            value,
        )

        version_match = re.search(
            r"\b(?:version\s*)?"
            r"([0-9]+(?:\.[0-9A-Za-z_-]+)+)"
            r"\b",
            value,
            re.IGNORECASE,
        )

        version = ""

        if version_match:
            version = version_match.group(
                1
            )

            name = (
                value[:version_match.start()]
                .strip(
                    " :-"
                )
            )

        else:
            name = value

        if not name:
            return None

        return {
            "name": name,
            "version": version,
            "category": "",
        }

    ###########################################################################
    # Structured Plugin Extraction
    ###########################################################################

    def _plugins_to_technologies(
        self,
        plugins: Mapping[str, Any],
    ) -> list[dict[str, str]]:
        """
        Convert WhatWeb plugin mappings into normalized technology records.
        """

        result: list[dict[str, str]] = []

        for plugin_name, plugin_data in plugins.items():

            technology = {
                "name": str(
                    plugin_name
                ),
                "version": "",
                "category": "",
            }

            if isinstance(
                plugin_data,
                Mapping,
            ):
                version = (
                    plugin_data.get(
                        "version"
                    )
                    or plugin_data.get(
                        "versions"
                    )
                )

                if isinstance(
                    version,
                    list,
                ):
                    version = (
                        version[0]
                        if version
                        else ""
                    )

                technology[
                    "version"
                ] = self._normalize_name(
                    version
                )

                category = (
                    plugin_data.get(
                        "category"
                    )
                    or plugin_data.get(
                        "type"
                    )
                    or ""
                )

                technology[
                    "category"
                ] = self._normalize_name(
                    category
                )

            result.append(
                technology
            )

        return result

    def _mapping_to_technology(
        self,
        record: Mapping[str, Any],
    ) -> list[dict[str, str]]:
        """
        Convert an individual structured plugin record.
        """

        name = (
            record.get("name")
            or record.get("plugin")
            or record.get("technology")
        )

        if not name:
            return []

        version = (
            record.get("version")
            or record.get("versions")
            or ""
        )

        if isinstance(
            version,
            list,
        ):
            version = (
                version[0]
                if version
                else ""
            )

        category = (
            record.get("category")
            or record.get("type")
            or ""
        )

        return [
            {
                "name": self._normalize_name(
                    name
                ),
                "version": self._normalize_name(
                    version
                ),
                "category": self._normalize_name(
                    category
                ),
            }
        ]

    def _extract_technology_fields(
        self,
        record: Mapping[str, Any],
    ) -> list[dict[str, str]]:
        """
        Extract technology information from common structured field names.
        """

        result: list[dict[str, str]] = []

        for key in (
            "technologies",
            "technology",
            "frameworks",
            "framework",
            "cms",
            "server",
            "servers",
            "libraries",
            "library",
        ):

            value = record.get(
                key
            )

            if value is None:
                continue

            if isinstance(
                value,
                str,
            ):
                result.append(
                    {
                        "name": value,
                        "version": "",
                        "category": key,
                    }
                )

            elif isinstance(
                value,
                Mapping,
            ):
                name = (
                    value.get(
                        "name"
                    )
                    or value.get(
                        "technology"
                    )
                )

                if name:
                    result.append(
                        {
                            "name": self._normalize_name(
                                name
                            ),
                            "version": self._normalize_name(
                                value.get(
                                    "version"
                                )
                            ),
                            "category": key,
                        }
                    )

            elif isinstance(
                value,
                list,
            ):
                for item in value:

                    if isinstance(
                        item,
                        str,
                    ):
                        result.append(
                            {
                                "name": item,
                                "version": "",
                                "category": key,
                            }
                        )

                    elif isinstance(
                        item,
                        Mapping,
                    ):
                        name = (
                            item.get(
                                "name"
                            )
                            or item.get(
                                "technology"
                            )
                        )

                        if name:
                            result.append(
                                {
                                    "name": (
                                        self._normalize_name(
                                            name
                                        )
                                    ),
                                    "version": (
                                        self._normalize_name(
                                            item.get(
                                                "version"
                                            )
                                        )
                                    ),
                                    "category": key,
                                }
                            )

        return result

    @staticmethod
    def _deduplicate_technologies(
        technologies: list[dict[str, str]],
    ) -> list[dict[str, str]]:
        """
        Deduplicate technology records deterministically.
        """

        result: list[dict[str, str]] = []

        seen: set[
            tuple[
                str,
                str,
                str,
            ]
        ] = set()

        for technology in technologies:

            name = str(
                technology.get(
                    "name",
                    ""
                )
            ).strip()

            if not name:
                continue

            version = str(
                technology.get(
                    "version",
                    ""
                )
            ).strip()

            category = str(
                technology.get(
                    "category",
                    ""
                )
            ).strip()

            key = (
                name.lower(),
                version.lower(),
                category.lower(),
            )

            if key in seen:
                continue

            seen.add(
                key
            )

            result.append(
                {
                    "name": name,
                    "version": version,
                    "category": category,
                }
            )

        return result

    ###########################################################################
    # Technology Classification
    ###########################################################################

    @staticmethod
    def _classify_technology(
        name: str,
    ) -> str:
        """
        Classify a technology into a ScopeForgeX observation type.

        Classification is intentionally conservative and based on recognizable
        technology families rather than assigning security severity.
        """

        normalized = (
            str(
                name
            )
            .strip()
            .lower()
        )

        cms_names = {
            "wordpress",
            "drupal",
            "joomla",
            "magento",
            "shopify",
            "ghost",
            "typo3",
            "concrete cms",
            "prestashop",
        }

        framework_names = {
            "django",
            "flask",
            "laravel",
            "symfony",
            "rails",
            "ruby on rails",
            "spring",
            "spring boot",
            "express",
            "express.js",
            "next.js",
            "nextjs",
            "nuxt",
            "nuxt.js",
            "react",
            "angular",
            "vue",
            "vue.js",
            "asp.net",
            "asp.net core",
        }

        server_names = {
            "apache",
            "apache httpd",
            "nginx",
            "iis",
            "microsoft-iis",
            "caddy",
            "lighttpd",
            "gunicorn",
            "tomcat",
            "jetty",
        }

        library_names = {
            "jquery",
            "lodash",
            "bootstrap",
            "moment.js",
            "moment",
            "axios",
            "three.js",
            "webpack",
        }

        if normalized in cms_names:
            return OBSERVATION_CMS

        if normalized in framework_names:
            return OBSERVATION_FRAMEWORK

        if normalized in server_names:
            return OBSERVATION_SERVER

        if normalized in library_names:
            return OBSERVATION_LIBRARY

        if any(
            marker in normalized
            for marker in (
                "wordpress",
                "drupal",
                "joomla",
                "magento",
            )
        ):
            return OBSERVATION_CMS

        if any(
            marker in normalized
            for marker in (
                "apache",
                "nginx",
                "microsoft-iis",
                "lighttpd",
            )
        ):
            return OBSERVATION_SERVER

        if any(
            marker in normalized
            for marker in (
                "jquery",
                "bootstrap",
                "lodash",
            )
        ):
            return OBSERVATION_LIBRARY

        if any(
            marker in normalized
            for marker in (
                "django",
                "laravel",
                "symfony",
                "spring",
                "express",
                "react",
                "angular",
                "vue",
            )
        ):
            return OBSERVATION_FRAMEWORK

        return OBSERVATION_TECHNOLOGY

    ###########################################################################
    # URL Helpers
    ###########################################################################

    @staticmethod
    def _extract_url(
        record: Mapping[str, Any],
    ) -> str | None:
        """
        Extract a URL from a structured WhatWeb record.
        """

        for key in (
            "target",
            "url",
            "input",
            "host",
        ):

            value = record.get(
                key
            )

            if isinstance(
                value,
                str,
            ) and value.strip():

                candidate = value.strip()

                if (
                    candidate.startswith(
                        "http://"
                    )
                    or candidate.startswith(
                        "https://"
                    )
                ):
                    return candidate

        return None

    @staticmethod
    def _normalize_url(
        value: Any,
    ) -> str | None:
        """
        Normalize a WhatWeb target URL.
        """

        if not isinstance(
            value,
            str,
        ):
            return None

        value = value.strip()

        if not value:
            return None

        if not (
            value.startswith(
                "http://"
            )
            or value.startswith(
                "https://"
            )
        ):
            return None

        return value.rstrip(
            "/"
        ) or value

    @staticmethod
    def _extract_host(
        url: str | None,
    ) -> str | None:
        """
        Extract a hostname from a URL.
        """

        if not url:
            return None

        from urllib.parse import urlparse

        try:
            return urlparse(
                url
            ).hostname

        except ValueError:
            return None

    @staticmethod
    def _extract_port(
        url: str | None,
    ) -> int | None:
        """
        Extract the explicit or effective port from a URL.
        """

        if not url:
            return None

        from urllib.parse import urlparse

        try:
            parsed = urlparse(
                url
            )

            if parsed.port is not None:
                return parsed.port

            if parsed.scheme.lower() == "http":
                return 80

            if parsed.scheme.lower() == "https":
                return 443

        except ValueError:
            return None

        return None

    ###########################################################################
    # Normalization
    ###########################################################################

    @staticmethod
    def _normalize_name(
        value: Any,
    ) -> str:
        """
        Normalize a technology, version or category name.
        """

        if value is None:
            return ""

        if isinstance(
            value,
            list,
        ):
            if not value:
                return ""

            value = value[0]

        return re.sub(
            r"\s+",
            " ",
            str(
                value
            ).strip(),
        )

    @staticmethod
    def _resolve_target(
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> str | None:
        """
        Resolve the assessment target from collector context or execution
        metadata.
        """

        target = ctx.get(
            "target"
        )

        if target:
            return str(
                target
            ).strip()

        metadata = getattr(
            execution_result,
            "metadata",
            {},
        )

        if isinstance(
            metadata,
            Mapping,
        ):
            target = metadata.get(
                "target"
            )

            if target:
                return str(
                    target
                ).strip()

        return None


###############################################################################
# Public API
###############################################################################


__all__ = [
    "WhatWebCollector",
]

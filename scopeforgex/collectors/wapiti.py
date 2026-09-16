"""
ScopeForgeX Wapiti Collector
=============================

Parses Wapiti JSON reports into canonical CollectorObservation records.

Wapiti findings are scanner observations. They are deliberately preserved
with their native evidence and are not treated as independently confirmed
vulnerabilities.

Design principles
-----------------
- The collector never executes Wapiti.
- The collector never constructs Wapiti commands.
- The collector never performs network requests.
- Raw Wapiti evidence remains preserved.
- Operational execution failures are not converted into findings.
- Scanner observations remain Pending / scanner-observation evidence.
- Duplicate observations are removed deterministically.
"""

from __future__ import annotations

import json
import re
from pathlib import Path
from typing import Any, Mapping
from urllib.parse import urljoin

from scopeforgex.collectors.base import (
    CollectorBase,
    CollectorObservation,
)


TOOL_NAME = "wapiti"

OBSERVATION_VULNERABILITY = "VULNERABILITY"
OBSERVATION_MISCONFIGURATION = "MISCONFIGURATION"
OBSERVATION_SECURITY_ISSUE = "SECURITY_ISSUE"


class WapitiCollector(CollectorBase):
    """
    Collect structured security observations from Wapiti JSON output.
    """

    name = TOOL_NAME
    tool = TOOL_NAME

    description = (
        "Parse Wapiti web application security observations into "
        "structured ScopeForgeX observations."
    )

    supported_input_types = (
        "execution_result",
        "raw_file",
        "text",
    )

    _SEVERITY_MAP = {
        0: "informational",
        1: "low",
        2: "medium",
        3: "high",
        4: "critical",
    }

    def validate_input(
        self,
        execution_result: Any,
    ) -> None:
        """
        Validate the supplied execution result using the canonical
        collector contract.
        """
        super().validate_input(execution_result)

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        """
        Parse Wapiti JSON output into canonical observations.

        Only successful executions with a readable JSON report are parsed.
        """
        if not getattr(execution_result, "success", False):
            return []

        report_path = self._find_report(
            execution_result,
            ctx,
        )

        if report_path is None:
            return []

        try:
            data = json.loads(
                report_path.read_text(
                    encoding="utf-8",
                    errors="ignore",
                )
            )
        except (
            OSError,
            ValueError,
            TypeError,
        ):
            return []

        if not isinstance(data, dict):
            return []

        target = self._resolve_target(
            execution_result,
            ctx,
        )

        observations: list[CollectorObservation] = []
        seen: set[tuple[str, str, str, str, str]] = set()

        sections = (
            (
                "vulnerabilities",
                OBSERVATION_VULNERABILITY,
            ),
            (
                "anomalies",
                OBSERVATION_SECURITY_ISSUE,
            ),
            (
                "additionals",
                OBSERVATION_MISCONFIGURATION,
            ),
        )

        for section, observation_type in sections:
            categories = data.get(section, {})

            if not isinstance(categories, dict):
                continue

            for category, records in categories.items():
                if not isinstance(records, list):
                    continue

                for record in records:
                    if not isinstance(record, dict):
                        continue

                    observation = self._normalize_record(
                        category=str(category),
                        record=record,
                        observation_type=observation_type,
                        target=target,
                    )

                    if observation is None:
                        continue

                    key = (
                        observation.observation_type,
                        observation.title,
                        observation.url or "",
                        observation.parameter or "",
                        observation.description,
                    )

                    if key in seen:
                        continue

                    seen.add(key)
                    observations.append(observation)

        return observations

    def _find_report(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> Path | None:
        """
        Locate the Wapiti JSON report from canonical execution artifacts
        or collector context.
        """
        artifacts = getattr(
            execution_result,
            "artifacts",
            [],
        ) or []

        for artifact in artifacts:
            path = getattr(
                artifact,
                "path",
                artifact,
            )

            if not path:
                continue

            candidate = Path(str(path))

            if (
                candidate.is_file()
                and candidate.suffix.lower() == ".json"
            ):
                return candidate

        metadata = getattr(
            execution_result,
            "metadata",
            {},
        ) or {}

        if isinstance(metadata, Mapping):
            output_file = metadata.get("output_file")

            if output_file:
                candidate = Path(str(output_file))

                if candidate.is_file():
                    return candidate

        context_artifacts = ctx.get(
            "artifacts",
            [],
        ) or []

        for artifact in context_artifacts:
            path = getattr(
                artifact,
                "path",
                artifact,
            )

            if not path:
                continue

            candidate = Path(str(path))

            if (
                candidate.is_file()
                and candidate.suffix.lower() == ".json"
            ):
                return candidate

        return None

    def _normalize_record(
        self,
        *,
        category: str,
        record: dict[str, Any],
        observation_type: str,
        target: str | None,
    ) -> CollectorObservation | None:
        """
        Convert one Wapiti JSON record into a canonical observation.
        """
        info = str(
            record.get("info")
            or category
            or "Wapiti security observation"
        ).strip()

        if not info:
            return None

        path = str(
            record.get("path")
            or ""
        ).strip()

        url = self._extract_url(
            record=record,
            target=target,
            path=path,
        )

        parameter_value = record.get("parameter")
        parameter = (
            str(parameter_value)
            if parameter_value is not None
            else None
        )

        severity = self._severity(
            record.get("level")
        )

        cve = self._first_identifier(
            category,
            info,
            "CVE",
        )

        cwe = self._first_identifier(
            category,
            info,
            "CWE",
        )

        evidence = {
            "module": record.get("module"),
            "method": record.get("method"),
            "path": path,
            "parameter": parameter_value,
            "referer": record.get("referer"),
            "http_request": record.get("http_request"),
            "curl_command": record.get("curl_command"),
            "wstg": record.get("wstg"),
            "category": category,
            "raw_record": record,
        }

        return CollectorObservation(
            observation_type=observation_type,
            title=category,
            description=info,
            severity=severity,
            confidence="Scanner Observation",
            status="Pending",
            target=target,
            host=target,
            url=url,
            parameter=parameter,
            evidence=evidence,
            source_tool=TOOL_NAME,
            detection_method="Wapiti",
            cve=cve,
            cwe=cwe,
            references=self._references(
                record.get("wstg")
            ),
        )

    @classmethod
    def _severity(
        cls,
        value: Any,
    ) -> str:
        """
        Map Wapiti's numeric severity level to the canonical severity names.
        """
        try:
            level = int(value)
        except (
            TypeError,
            ValueError,
        ):
            return "informational"

        return cls._SEVERITY_MAP.get(
            level,
            "informational",
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
        target = ctx.get("target")

        if target:
            return str(target).strip() or None

        metadata = getattr(
            execution_result,
            "metadata",
            {},
        ) or {}

        if isinstance(metadata, Mapping):
            target = metadata.get("target")

            if target:
                return str(target).strip() or None

        return None

    @staticmethod
    def _extract_url(
        *,
        record: dict[str, Any],
        target: str | None,
        path: str,
    ) -> str | None:
        """
        Resolve the affected URL without interpreting arbitrary evidence
        strings as URLs.
        """
        raw_url = record.get("url")

        if isinstance(raw_url, str) and raw_url.strip():
            return raw_url.strip()

        if target and target.startswith(
            (
                "http://",
                "https://",
            )
        ):
            if path:
                return urljoin(
                    target.rstrip("/") + "/",
                    path.lstrip("/"),
                )

            return target.rstrip("/")

        return None

    @staticmethod
    def _first_identifier(
        category: str,
        info: str,
        prefix: str,
    ) -> str | None:
        """
        Return the first CVE/CWE identifier present in the Wapiti text.
        """
        pattern = re.compile(
            rf"\b{prefix}-?\d+(?:-\d+)?\b",
            re.IGNORECASE,
        )

        match = pattern.search(
            f"{category} {info}"
        )

        if match is None:
            return None

        return match.group(0)

    @staticmethod
    def _references(
        value: Any,
    ) -> list[str]:
        """
        Normalize Wapiti WSTG references.
        """
        if not isinstance(value, list):
            return []

        return [
            str(reference)
            for reference in value
            if reference is not None
            and str(reference).strip()
        ]


__all__ = [
    "WapitiCollector",
]

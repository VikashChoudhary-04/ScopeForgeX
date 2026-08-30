"""
ScopeForgeX SSTImap Collector
=============================

Collector adapter for SSTImap.

SSTImap is used by ScopeForgeX for authorized server-side template
injection (SSTI) detection and validation.

Responsibilities
----------------

- Build deterministic SSTImap commands.
- Support URL and request-based testing.
- Preserve raw stdout and stderr.
- Extract meaningful SSTI observations.
- Preserve affected parameter, engine, payload and evidence.
- Produce normalized observations for the universal Finding pipeline.

The collector does not:

- Decide whether exploitation is authorized.
- Treat every SSTImap informational message as a vulnerability.
- Perform cross-tool correlation.
- Deduplicate findings globally.
- Perform final risk classification.

Architecture
------------

Authorized Target
        |
        v
SSTImap Collector
        |
        v
Tool Executor
        |
        v
SSTImap
        |
        +--> Raw Output
        |
        +--> Parsed Observations
                    |
                    v
             Finding Normalizer
                    |
                    v
          Correlation / Risk Engine
                    |
                    v
                  Report

v1.2.0
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from scopeforgex.collectors.base import BaseCollector


###############################################################################
# Constants
###############################################################################


SSTI_CATEGORY = "server_side_template_injection"

SSTI_CWE = "CWE-1336"

DEFAULT_CONFIDENCE = "Medium"

SECURITY_MARKERS = (
    "vulnerable",
    "vulnerability",
    "ssti",
    "server-side template injection",
    "template injection",
    "jinja",
    "jinja2",
    "twig",
    "freemarker",
    "mako",
    "smarty",
    "tornado",
    "velocity",
    "payload",
    "injection",
)

CONFIRMATION_MARKERS = (
    "vulnerable",
    "confirmed",
    "detected",
    "success",
    "successfully",
    "is vulnerable",
)

NON_FINDING_MARKERS = (
    "starting",
    "checking",
    "testing",
    "scanning",
    "requesting",
    "loading",
    "finished",
    "complete",
)


###############################################################################
# Collector
###############################################################################


class SSTImapCollector(BaseCollector):
    """
    Collect server-side template injection observations from SSTImap.

    The parser is intentionally conservative. Normal scanner progress,
    template-engine identification, and other informational output are
    retained as raw evidence but are not automatically promoted to
    confirmed vulnerabilities.
    """

    name = "sstimap"

    description = (
        "Detect and validate server-side template injection "
        "vulnerabilities in authorized applications."
    )

    category = "validation"

    binary = "sstimap"

    ###########################################################################
    # Command Construction
    ###########################################################################

    def build_command(
        self,
        target: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[str]:
        """
        Build a deterministic SSTImap command.

        Supported options include:

        - url
        - data
        - parameter
        - request
        - method
        - cookie
        - header
        - headers
        - engine
        - proxy
        - timeout
        - delay
        - level
        - risk
        - tamper
        - batch
        - crawl
        - depth
        - verify_ssl
        - output
        - additional_args

        additional_args can be used for SSTImap options that are specific
        to the installed SSTImap version.
        """

        options = dict(
            options or {}
        )

        command = [
            self.binary,
        ]

        #######################################################################
        # Target
        #######################################################################

        request_target = (
            options.get(
                "url"
            )
            or target
        )

        request_file = options.get(
            "request"
        )

        if request_file:
            command.extend(
                [
                    "-r",
                    str(
                        request_file
                    ),
                ]
            )

        elif request_target:
            normalized_target = str(
                request_target
            ).strip()

            if not normalized_target:
                raise ValueError(
                    "SSTImap target cannot be empty."
                )

            command.extend(
                [
                    "-u",
                    normalized_target,
                ]
            )

        else:
            raise ValueError(
                "SSTImap requires a target URL or request file."
            )

        #######################################################################
        # Request Configuration
        #######################################################################

        data = options.get(
            "data"
        )

        if data:
            command.extend(
                [
                    "--data",
                    str(
                        data
                    ),
                ]
            )

        parameter = options.get(
            "parameter"
        )

        if parameter:
            command.extend(
                [
                    "-p",
                    str(
                        parameter
                    ),
                ]
            )

        method = options.get(
            "method"
        )

        if method:
            command.extend(
                [
                    "--method",
                    str(
                        method
                    ).upper(),
                ]
            )

        cookie = options.get(
            "cookie"
        )

        if cookie:
            command.extend(
                [
                    "--cookie",
                    str(
                        cookie
                    ),
                ]
            )

        #######################################################################
        # Headers
        #######################################################################

        header = options.get(
            "header"
        )

        headers = options.get(
            "headers"
        )

        header_values: list[str] = []

        if header:
            if isinstance(
                header,
                (list, tuple),
            ):
                header_values.extend(
                    str(
                        value
                    )
                    for value in header
                )
            else:
                header_values.append(
                    str(
                        header
                    )
                )

        if headers:
            if isinstance(
                headers,
                (list, tuple),
            ):
                header_values.extend(
                    str(
                        value
                    )
                    for value in headers
                )
            else:
                header_values.append(
                    str(
                        headers
                    )
                )

        for value in header_values:

            normalized_header = value.strip()

            if not normalized_header:
                continue

            command.extend(
                [
                    "--headers",
                    normalized_header,
                ]
            )

        #######################################################################
        # Template Engine
        #######################################################################

        engine = options.get(
            "engine"
        )

        if engine:
            command.extend(
                [
                    "--engine",
                    str(
                        engine
                    ),
                ]
            )

        #######################################################################
        # Runtime / Request Controls
        #######################################################################

        proxy = options.get(
            "proxy"
        )

        if proxy:
            command.extend(
                [
                    "--proxy",
                    str(
                        proxy
                    ),
                ]
            )

        timeout = options.get(
            "timeout"
        )

        if timeout is not None:
            timeout_value = self._integer_option(
                timeout,
                "timeout",
                minimum=1,
            )

            command.extend(
                [
                    "--timeout",
                    str(
                        timeout_value
                    ),
                ]
            )

        delay = options.get(
            "delay"
        )

        if delay is not None:
            delay_value = self._integer_option(
                delay,
                "delay",
                minimum=0,
            )

            command.extend(
                [
                    "--delay",
                    str(
                        delay_value
                    ),
                ]
            )

        level = options.get(
            "level"
        )

        if level is not None:
            level_value = self._integer_option(
                level,
                "level",
                minimum=1,
            )

            command.extend(
                [
                    "--level",
                    str(
                        level_value
                    ),
                ]
            )

        risk = options.get(
            "risk"
        )

        if risk is not None:
            risk_value = self._integer_option(
                risk,
                "risk",
                minimum=1,
            )

            command.extend(
                [
                    "--risk",
                    str(
                        risk_value
                    ),
                ]
            )

        #######################################################################
        # Scanning Options
        #######################################################################

        if options.get(
            "batch",
            False,
        ):
            command.append(
                "--batch"
            )

        if options.get(
            "crawl",
            False,
        ):
            command.append(
                "--crawl"
            )

        depth = options.get(
            "depth"
        )

        if depth is not None:
            depth_value = self._integer_option(
                depth,
                "depth",
                minimum=1,
            )

            command.extend(
                [
                    "--depth",
                    str(
                        depth_value
                    ),
                ]
            )

        tamper = options.get(
            "tamper"
        )

        if tamper:
            if isinstance(
                tamper,
                (list, tuple),
            ):
                for value in tamper:
                    if str(
                        value
                    ).strip():
                        command.extend(
                            [
                                "--tamper",
                                str(
                                    value
                                ),
                            ]
                        )
            else:
                command.extend(
                    [
                        "--tamper",
                        str(
                            tamper
                        ),
                    ]
                )

        #######################################################################
        # TLS
        #######################################################################

        if options.get(
            "verify_ssl",
            True,
        ) is False:
            command.append(
                "--disable-ssl-check"
            )

        #######################################################################
        # Output
        #######################################################################

        output = options.get(
            "output"
        )

        if output:
            command.extend(
                [
                    "--output",
                    str(
                        output
                    ),
                ]
            )

        #######################################################################
        # Additional Arguments
        #######################################################################

        additional_args = options.get(
            "additional_args",
            [],
        )

        if additional_args is None:
            additional_args = []

        if not isinstance(
            additional_args,
            (list, tuple),
        ):
            raise TypeError(
                "SSTImap additional_args must be a list or tuple."
            )

        command.extend(
            str(argument)
            for argument in additional_args
            if str(argument).strip()
        )

        return command

    ###########################################################################
    # Collection
    ###########################################################################

    def collect(
        self,
        target: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute SSTImap and return normalized collector evidence.
        """

        options = dict(
            options or {}
        )

        command = self.build_command(
            target,
            options,
        )

        result = self.execute(
            command
        )

        return self.parse_result(
            target=(
                target
                or options.get(
                    "url",
                    "",
                )
            ),
            result=result,
            command=command,
            options=options,
        )

    ###########################################################################
    # Result Parsing
    ###########################################################################

    def parse_result(
        self,
        target: str,
        result: Any,
        command: list[str] | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Parse SSTImap stdout/stderr into normalized observations.

        Raw stdout and stderr are always preserved.
        """

        stdout = self._result_value(
            result,
            "stdout",
        ) or ""

        stderr = self._result_value(
            result,
            "stderr",
        ) or ""

        returncode = self._result_value(
            result,
            "returncode",
        )

        if returncode is None:
            returncode = self._result_value(
                result,
                "return_code",
            )

        combined = "\n".join(
            part
            for part in (
                str(
                    stdout
                ),
                str(
                    stderr
                ),
            )
            if part
        )

        observations = self._parse_output(
            combined,
            target,
        )

        return {
            "collector": self.name,
            "category": self.category,
            "target": str(
                target
            ).strip(),
            "success": self._result_success(
                result
            ),
            "observations": observations,
            "observation_count": len(
                observations
            ),
            "raw": {
                "stdout": str(
                    stdout
                ),
                "stderr": str(
                    stderr
                ),
            },
            "execution": {
                "returncode": returncode,
            },
            "command": list(
                command or []
            ),
            "options": dict(
                options or {}
            ),
        }

    ###########################################################################
    # Output Parsing
    ###########################################################################

    @classmethod
    def _parse_output(
        cls,
        output: str,
        target: str,
    ) -> list[dict[str, Any]]:
        """
        Parse SSTImap output into normalized observations.
        """

        text = str(
            output
        )

        if not text.strip():
            return []

        observations: list[dict[str, Any]] = []

        for line in text.splitlines():

            normalized = line.strip()

            if not normalized:
                continue

            if not cls._looks_like_security_observation(
                normalized
            ):
                continue

            observation = cls._parse_security_line(
                normalized,
                target,
            )

            if observation is not None:
                observations.append(
                    observation
                )

        return cls._deduplicate_observations(
            observations
        )

    @staticmethod
    def _looks_like_security_observation(
        line: str,
    ) -> bool:
        """
        Determine whether an output line contains SSTI-related evidence.
        """

        normalized = line.lower()

        if not any(
            marker in normalized
            for marker in SECURITY_MARKERS
        ):
            return False

        if (
            any(
                marker in normalized
                for marker in NON_FINDING_MARKERS
            )
            and not any(
                marker in normalized
                for marker in (
                    "vulnerable",
                    "vulnerability",
                    "ssti",
                    "injection",
                )
            )
        ):
            return False

        return True

    @classmethod
    def _parse_security_line(
        cls,
        line: str,
        target: str,
    ) -> dict[str, Any] | None:
        """
        Convert an SSTImap output line into a normalized observation.
        """

        normalized = line.lower()

        category = cls._classify_category(
            normalized
        )

        if category is None:
            return None

        parameter = cls._extract_parameter(
            line
        )

        engine = cls._extract_engine(
            line
        )

        payload = cls._extract_payload(
            line
        )

        confidence = (
            "High"
            if any(
                marker in normalized
                for marker in CONFIRMATION_MARKERS
            )
            else DEFAULT_CONFIDENCE
        )

        severity = (
            "High"
            if confidence == "High"
            else "Medium"
        )

        effective_url = (
            target
            if cls._is_url(
                target
            )
            else None
        )

        description_parts = [
            "SSTImap identified a potentially exploitable "
            "server-side template injection condition."
        ]

        if parameter:
            description_parts.append(
                f"Affected parameter: {parameter}."
            )

        if engine:
            description_parts.append(
                f"Template engine: {engine}."
            )

        return {
            "type": "vulnerability",
            "category": SSTI_CATEGORY,
            "title": (
                "Server-Side Template Injection"
            ),
            "target": str(
                target
            ).strip(),
            "host": cls._extract_host(
                target
            ),
            "port": cls._extract_port(
                target
            ),
            "url": effective_url,
            "parameter": parameter,
            "severity": severity,
            "confidence": confidence,
            "description": " ".join(
                description_parts
            ),
            "evidence": {
                "raw_line": line,
                "engine": engine,
                "payload": payload,
            },
            "source_tool": "sstimap",
            "detection_method": (
                "Server-Side Template Injection Detection "
                "and Validation"
            ),
            "cwe": SSTI_CWE,
            "cve": None,
            "references": [
                "https://cwe.mitre.org/data/definitions/1336.html",
            ],
            "impact": (
                "Server-side template injection may allow attacker-"
                "controlled template expressions to execute on the server, "
                "potentially leading to sensitive data exposure, "
                "application compromise, or remote code execution."
            ),
            "remediation": (
                "Avoid evaluating untrusted input as template source. "
                "Use safe template APIs, strict input handling, sandboxing "
                "where appropriate, and separate template code from "
                "user-controlled data."
            ),
            "metadata": {
                "template_engine": engine,
                "payload": payload,
                "sstimap_line": line,
                "detection_category": category,
            },
        }

    ###########################################################################
    # Classification
    ###########################################################################

    @staticmethod
    def _classify_category(
        line: str,
    ) -> str | None:
        """
        Classify an SSTImap security observation.
        """

        if (
            "remote code execution" in line
            or "rce" in line
        ):
            return "ssti_rce"

        if (
            "server-side template injection" in line
            or "ssti" in line
            or "template injection" in line
        ):
            return "ssti_detected"

        if (
            "vulnerable" in line
            or "vulnerability" in line
        ):
            return "ssti_security_issue"

        if any(
            engine in line
            for engine in (
                "jinja",
                "jinja2",
                "twig",
                "freemarker",
                "mako",
                "smarty",
                "tornado",
                "velocity",
            )
        ) and (
            "inject" in line
            or "payload" in line
            or "exploit" in line
        ):
            return "ssti_detected"

        return None

    ###########################################################################
    # Extraction Helpers
    ###########################################################################

    @staticmethod
    def _extract_parameter(
        line: str,
    ) -> str | None:
        """
        Extract an affected parameter from common SSTImap output forms.
        """

        patterns = (
            r"(?:parameter|param)\s*[:=]\s*[\"']?"
            r"([A-Za-z0-9_.\-\[\]]+)",
            r"(?:parameter|param)\s+[\"']"
            r"([A-Za-z0-9_.\-\[\]]+)[\"']",
        )

        for pattern in patterns:

            match = re.search(
                pattern,
                line,
                re.IGNORECASE,
            )

            if match:
                return match.group(
                    1
                ).strip()

        url_match = re.search(
            r"https?://[^\s]+",
            line,
            re.IGNORECASE,
        )

        if url_match:
            query_match = re.search(
                r"[?&]([^=&\s]+)=",
                url_match.group(
                    0
                ),
            )

            if query_match:
                return query_match.group(
                    1
                )

        return None

    @staticmethod
    def _extract_engine(
        line: str,
    ) -> str | None:
        """
        Extract a known template engine name.
        """

        engines = (
            "Jinja2",
            "Jinja",
            "Twig",
            "FreeMarker",
            "Mako",
            "Smarty",
            "Tornado",
            "Velocity",
        )

        normalized = line.lower()

        for engine in engines:

            if engine.lower() in normalized:
                return engine

        match = re.search(
            r"(?:engine|template engine)\s*[:=]\s*"
            r"([A-Za-z0-9_.-]+)",
            line,
            re.IGNORECASE,
        )

        if match:
            return match.group(
                1
            ).strip()

        return None

    @staticmethod
    def _extract_payload(
        line: str,
    ) -> str | None:
        """
        Extract a template injection payload when present.
        """

        patterns = (
            r"payload\s*[:=]\s*(.+)$",
            r"payload\s+[\"'](.+?)[\"']",
            r"using\s+[\"'](.+?)[\"']",
        )

        for pattern in patterns:

            match = re.search(
                pattern,
                line,
                re.IGNORECASE,
            )

            if match:

                value = match.group(
                    1
                ).strip()

                if value:
                    return value

        return None

    ###########################################################################
    # Target Helpers
    ###########################################################################

    @staticmethod
    def _extract_host(
        target: str | None,
    ) -> str | None:
        """
        Extract hostname from an HTTP(S) target.
        """

        if not target:
            return None

        match = re.match(
            r"https?://([^/:?#]+)",
            str(
                target
            ),
            re.IGNORECASE,
        )

        if not match:
            return None

        return match.group(
            1
        )

    @staticmethod
    def _extract_port(
        target: str | None,
    ) -> int | None:
        """
        Extract an explicitly specified target port.
        """

        if not target:
            return None

        match = re.match(
            r"https?://[^/:?#]+:(\d+)",
            str(
                target
            ),
            re.IGNORECASE,
        )

        if not match:
            return None

        try:
            return int(
                match.group(
                    1
                )
            )
        except ValueError:
            return None

    @staticmethod
    def _is_url(
        value: str | None,
    ) -> bool:
        """
        Determine whether a value is an HTTP(S) URL.
        """

        if not value:
            return False

        return bool(
            re.match(
                r"^https?://",
                str(
                    value
                ).strip(),
                re.IGNORECASE,
            )
        )

    ###########################################################################
    # Generic Helpers
    ###########################################################################

    @staticmethod
    def _deduplicate_observations(
        observations: list[dict[str, Any]],
    ) -> list[dict[str, Any]]:
        """
        Remove duplicate parser observations.
        """

        unique: list[dict[str, Any]] = []
        seen: set[str] = set()

        for observation in observations:

            evidence = observation.get(
                "evidence",
                {},
            )

            fingerprint = "|".join(
                (
                    str(
                        observation.get(
                            "category",
                            "",
                        )
                    ),
                    str(
                        observation.get(
                            "target",
                            "",
                        )
                    ),
                    str(
                        observation.get(
                            "parameter",
                            "",
                        )
                    ),
                    str(
                        evidence.get(
                            "raw_line",
                            "",
                        )
                    ).lower(),
                )
            )

            if fingerprint in seen:
                continue

            seen.add(
                fingerprint
            )

            unique.append(
                observation
            )

        return unique

    @staticmethod
    def _integer_option(
        value: Any,
        name: str,
        minimum: int,
        maximum: int | None = None,
    ) -> int:
        """
        Validate an integer SSTImap option.
        """

        try:
            normalized = int(
                value
            )
        except (
            TypeError,
            ValueError,
        ) as exc:
            raise ValueError(
                f"SSTImap {name} must be an integer."
            ) from exc

        if normalized < minimum:
            raise ValueError(
                f"SSTImap {name} must be >= {minimum}."
            )

        if (
            maximum is not None
            and normalized > maximum
        ):
            raise ValueError(
                f"SSTImap {name} must be <= {maximum}."
            )

        return normalized

    @staticmethod
    def _result_value(
        result: Any,
        field_name: str,
    ) -> Any:
        """
        Retrieve a result field from either a mapping or object.
        """

        if isinstance(
            result,
            Mapping,
        ):
            return result.get(
                field_name
            )

        return getattr(
            result,
            field_name,
            None,
        )

    @classmethod
    def _result_success(
        cls,
        result: Any,
    ) -> bool:
        """
        Determine whether SSTImap execution completed successfully.
        """

        explicit_success = cls._result_value(
            result,
            "success",
        )

        if isinstance(
            explicit_success,
            bool,
        ):
            return explicit_success

        returncode = cls._result_value(
            result,
            "returncode",
        )

        if returncode is None:
            returncode = cls._result_value(
                result,
                "return_code",
            )

        if returncode is None:
            return True

        try:
            return int(
                returncode
            ) == 0
        except (
            TypeError,
            ValueError,
        ):
            return False


###############################################################################
# Public API
###############################################################################


__all__ = [
    "SSTImapCollector",
]

"""
ScopeForgeX Dalfox Collector
============================

Collector adapter for Dalfox.

Dalfox is used by ScopeForgeX for authorized reflected, stored, and DOM-based
XSS detection and validation.

Responsibilities
----------------

- Build deterministic Dalfox commands.
- Support URL and parameter-focused scanning.
- Preserve raw stdout and stderr.
- Extract XSS observations from Dalfox output.
- Preserve affected parameter, payload, type, evidence and target.
- Maintain source-tool traceability.
- Produce normalized observations for the universal Finding pipeline.

The collector does not:

- Decide whether exploitation is authorized.
- Perform cross-tool correlation.
- Deduplicate findings.
- Perform final risk classification.
- Replace raw tool evidence with parsed data.

Architecture
------------

Authorized Target
        |
        v
Dalfox Collector
        |
        v
Tool Executor
        |
        v
Dalfox
        |
        +--> Raw Output
        |
        +--> Parsed Observations
                    |
                    v
             Finding Normalizer
                    |
                    v
             Correlation / Risk
                    |
                    v
                  Report

v1.2.0
"""

from __future__ import annotations

import re
from typing import Any, Mapping

from scopeforgex.collectors.base import BaseCollector, CollectorObservation


###############################################################################
# Constants
###############################################################################


DEFAULT_CONFIDENCE = "Medium"

XSS_CATEGORY = "cross_site_scripting"

XSS_CWE = "CWE-79"

DALFOX_MARKERS = (
    "vulnerable",
    "verified",
    "reflected",
    "stored",
    "dom",
    "payload",
    "[poc]",
    "[found]",
    "[v]",
)


###############################################################################
# Collector
###############################################################################


class DalfoxCollector(BaseCollector):
    """
    Collect XSS observations from Dalfox.

    The parser is deliberately conservative and only creates observations
    when Dalfox output contains recognizable vulnerability or proof-of-
    concept information.
    """

    name = "dalfox"

    description = (
        "Detect and validate reflected, stored, and DOM-based XSS "
        "in authorized web applications using Dalfox."
    )

    category = "validation"

    binary = "dalfox"

    ###########################################################################
    # Command Construction
    ###########################################################################

    def parse(
        self,
        execution_result: Any,
        ctx: Mapping[str, Any],
    ) -> list[CollectorObservation]:
        context = dict(ctx or {})

        target = str(
            context.get("target", "") or ""
        ).strip()

        options = dict(
            context.get(
                "tool_options",
                context.get("options", {}),
            ) or {}
        )

        command = list(
            context.get("command", []) or []
        )

        parsed = self.parse_result(
            target=target,
            result=execution_result,
            command=[str(value) for value in command],
            options=options,
        )

        raw_observations = (
            parsed.get("observations", [])
            if isinstance(parsed, Mapping)
            else []
        )

        return self._coerce_canonical_observations(
            raw_observations,
            target=target,
        )

    @staticmethod
    def _coerce_canonical_observations(
        observations: Any,
        *,
        target: str,
    ) -> list[CollectorObservation]:
        result: list[CollectorObservation] = []

        for item in observations or []:
            data = (
                item.as_dict()
                if hasattr(item, "as_dict")
                else item
            )

            if not isinstance(data, Mapping):
                continue

            data = dict(data)

            result.append(
                CollectorObservation(
                    observation_type=str(
                        data.get(
                            "observation_type",
                            data.get(
                                "category",
                                data.get(
                                    "type",
                                    "observation",
                                ),
                            ),
                        )
                    ),
                    value=data.get("value"),
                    title=str(data.get("title", "")),
                    description=str(
                        data.get("description", "")
                    ),
                    impact=str(data.get("impact", "")),
                    remediation=str(
                        data.get("remediation", "")
                    ),
                    severity=str(
                        data.get(
                            "severity",
                            "Informational",
                        )
                    ),
                    confidence=str(
                        data.get(
                            "confidence",
                            "Informational",
                        )
                    ),
                    status=str(
                        data.get(
                            "status",
                            "Pending",
                        )
                    ),
                    target=data.get(
                        "target",
                        target,
                    ),
                    host=data.get("host"),
                    port=data.get("port"),
                    url=data.get("url"),
                    parameter=data.get(
                        "parameter"
                    ),
                    evidence=data.get(
                        "evidence"
                    ),
                    source_tool=str(
                        data.get(
                            "source_tool",
                            "dalfox",
                        )
                    ),
                    detection_method=str(
                        data.get(
                            "detection_method",
                            "",
                        )
                    ),
                    cwe=data.get("cwe"),
                    cve=data.get("cve"),
                    references=list(
                        data.get(
                            "references",
                            [],
                        )
                        or []
                    ),
                    metadata=dict(
                        data.get(
                            "metadata",
                            {},
                        )
                        or {}
                    ),
                )
            )

        return result

    def build_command(
        self,
        target: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> list[str]:
        """
        Build a deterministic Dalfox command.

        Supported options include:

        - url
        - pipe
        - data
        - cookie
        - header
        - headers
        - parameter
        - params
        - method
        - mining_dom
        - mining_dic
        - blind
        - custom_payload
        - custom_alert_type
        - timeout
        - worker
        - delay
        - follow_redirects
        - skip_bav
        - skip_discovery
        - only_discovery
        - ignore_return
        - silient
        - format
        - output
        - report
        - proxy
        - remote_payloads
        - additional_args
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

        request_target = options.get(
            "url"
        ) or target

        if request_target:
            normalized_target = str(
                request_target
            ).strip()

            if not normalized_target:
                raise ValueError(
                    "Dalfox target cannot be empty."
                )

            command.extend(
                [
                    "url",
                    normalized_target,
                ]
            )

        elif options.get(
            "pipe",
            False,
        ):
            command.append(
                "pipe"
            )

        else:
            raise ValueError(
                "Dalfox requires a target URL or pipe mode."
            )

        #######################################################################
        # HTTP Configuration
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
            if value.strip():
                command.extend(
                    [
                        "--header",
                        value,
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

        #######################################################################
        # Parameter Configuration
        #######################################################################

        parameter = options.get(
            "parameter"
        )

        if parameter:
            command.extend(
                [
                    "--param",
                    str(
                        parameter
                    ),
                ]
            )

        params = options.get(
            "params"
        )

        if params:
            if isinstance(
                params,
                (list, tuple),
            ):
                params_value = ",".join(
                    str(
                        value
                    )
                    for value in params
                )
            else:
                params_value = str(
                    params
                )

            command.extend(
                [
                    "--param",
                    params_value,
                ]
            )

        #######################################################################
        # Mining / Discovery
        #######################################################################

        if options.get(
            "mining_dom",
            False,
        ):
            command.append(
                "--mining-dom"
            )

        if options.get(
            "mining_dic",
            False,
        ):
            command.append(
                "--mining-dict"
            )

        if options.get(
            "skip_discovery",
            False,
        ):
            command.append(
                "--skip-discovery"
            )

        if options.get(
            "only_discovery",
            False,
        ):
            command.append(
                "--only-discovery"
            )

        #######################################################################
        # XSS Testing
        #######################################################################

        blind = options.get(
            "blind"
        )

        if blind:
            command.extend(
                [
                    "--blind",
                    str(
                        blind
                    ),
                ]
            )

        custom_payload = options.get(
            "custom_payload"
        )

        if custom_payload:
            command.extend(
                [
                    "--payload",
                    str(
                        custom_payload
                    ),
                ]
            )

        custom_alert_type = options.get(
            "custom_alert_type"
        )

        if custom_alert_type:
            command.extend(
                [
                    "--custom-alert-type",
                    str(
                        custom_alert_type
                    ),
                ]
            )

        remote_payloads = options.get(
            "remote_payloads"
        )

        if remote_payloads:
            command.extend(
                [
                    "--remote-payloads",
                    str(
                        remote_payloads
                    ),
                ]
            )

        #######################################################################
        # Runtime
        #######################################################################

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

        worker = options.get(
            "worker"
        )

        if worker is not None:
            worker_value = self._integer_option(
                worker,
                "worker",
                minimum=1,
            )

            command.extend(
                [
                    "--worker",
                    str(
                        worker_value
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

        #######################################################################
        # Request Handling
        #######################################################################

        if options.get(
            "follow_redirects",
            False,
        ):
            command.append(
                "--follow-redirects"
            )

        if options.get(
            "skip_bav",
            False,
        ):
            command.append(
                "--skip-bav"
            )

        if options.get(
            "ignore_return",
            False,
        ):
            command.append(
                "--ignore-return"
            )

        #######################################################################
        # Output
        #######################################################################

        if options.get(
            "silient",
            False,
        ):
            command.append(
                "--silence"
            )

        output_format = options.get(
            "format"
        )

        if output_format:
            command.extend(
                [
                    "--format",
                    str(
                        output_format
                    ),
                ]
            )

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

        report = options.get(
            "report"
        )

        if report:
            command.extend(
                [
                    "--report",
                    str(
                        report
                    ),
                ]
            )

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
                "Dalfox additional_args must be a list or tuple."
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
        Execute Dalfox and return normalized collector evidence.
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
            target=target or options.get(
                "url",
                "",
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
        Parse Dalfox stdout/stderr into normalized observations.

        Raw stdout and stderr are always retained.
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
        Parse Dalfox console output into XSS observations.

        Dalfox output can differ between versions and output modes. The
        parser therefore recognizes several common patterns rather than
        relying on a single exact line format.
        """

        text = str(
            output
        )

        if not text.strip():
            return []

        observations: list[dict[str, Any]] = []

        #######################################################################
        # Line-based findings
        #######################################################################

        for line in text.splitlines():

            normalized = line.strip()

            if not normalized:
                continue

            if not cls._looks_like_finding(
                normalized
            ):
                continue

            observation = cls._parse_finding_line(
                normalized,
                target,
            )

            if observation is not None:
                observations.append(
                    observation
                )

        #######################################################################
        # Deduplicate observations generated from multiple matching lines.
        #######################################################################

        unique: list[dict[str, Any]] = []
        fingerprints: set[str] = set()

        for observation in observations:

            fingerprint = cls._observation_fingerprint(
                observation
            )

            if fingerprint in fingerprints:
                continue

            fingerprints.add(
                fingerprint
            )

            unique.append(
                observation
            )

        return unique

    @classmethod
    def _parse_finding_line(
        cls,
        line: str,
        target: str,
    ) -> dict[str, Any] | None:
        """
        Parse a single Dalfox finding line.

        The parser attempts to recover:

        - URL
        - Parameter
        - Payload
        - XSS type
        - Evidence
        """

        url = cls._extract_url(
            line
        )

        parameter = cls._extract_parameter(
            line
        )

        payload = cls._extract_payload(
            line
        )

        xss_type = cls._extract_xss_type(
            line
        )

        if not (
            url
            or parameter
            or payload
            or xss_type
        ):
            return None

        if xss_type:
            title = (
                f"Cross-Site Scripting - {xss_type}"
            )
        else:
            title = (
                "Cross-Site Scripting"
            )

        confidence = (
            "High"
            if (
                payload
                or "verified" in line.lower()
                or "[poc]" in line.lower()
            )
            else DEFAULT_CONFIDENCE
        )

        effective_url = (
            url
            or str(
                target
            ).strip()
        )

        description_parts = [
            "Dalfox identified a potential "
            "cross-site scripting issue."
        ]

        if parameter:
            description_parts.append(
                f"Affected parameter: {parameter}."
            )

        if xss_type:
            description_parts.append(
                f"Detected type: {xss_type}."
            )

        evidence = {
            "raw_line": line,
            "url": effective_url or None,
            "parameter": parameter,
            "payload": payload,
            "xss_type": xss_type,
        }

        evidence = {
            key: value
            for key, value in evidence.items()
            if value not in (
                None,
                "",
            )
        }

        return {
            "type": "vulnerability",
            "category": XSS_CATEGORY,
            "title": title,
            "target": str(
                target
            ).strip(),
            "host": cls._extract_host(
                effective_url
            ),
            "port": cls._extract_port(
                effective_url
            ),
            "url": effective_url or None,
            "parameter": parameter,
            "severity": "High",
            "confidence": confidence,
            "description": " ".join(
                description_parts
            ),
            "evidence": evidence,
            "source_tool": "dalfox",
            "detection_method": (
                "Cross-Site Scripting Detection and Validation"
            ),
            "cwe": XSS_CWE,
            "cve": None,
            "references": [
                "https://cwe.mitre.org/data/definitions/79.html",
            ],
            "impact": (
                "Cross-site scripting may allow attacker-controlled "
                "JavaScript or markup to execute in a victim's browser, "
                "potentially enabling session compromise, unauthorized "
                "actions, data exposure, or phishing."
            ),
            "remediation": (
                "Apply context-aware output encoding, validate untrusted "
                "input where appropriate, use safe templating APIs, and "
                "deploy an appropriate Content Security Policy."
            ),
            "metadata": {
                "xss_type": xss_type,
                "payload": payload,
                "dalfox_line": line,
            },
        }

    ###########################################################################
    # Detection Helpers
    ###########################################################################

    @staticmethod
    def _looks_like_finding(
        line: str,
    ) -> bool:
        """
        Determine whether a line appears to contain a Dalfox finding.

        Generic informational/status lines are excluded where possible.
        """

        normalized = line.lower()

        finding_markers = (
            "[poc]",
            "[found]",
            "[v]",
            "verified",
            "vulnerable",
            "reflected",
            "stored",
            "dom",
        )

        if not any(
            marker in normalized
            for marker in finding_markers
        ):
            return False

        non_finding_markers = (
            "starting",
            "running",
            "scanning",
            "requesting",
            "checking",
            "waiting",
            "finished",
            "complete",
        )

        if (
            any(
                marker in normalized
                for marker in non_finding_markers
            )
            and not any(
                marker in normalized
                for marker in (
                    "payload",
                    "[poc]",
                    "[found]",
                    "vulnerable",
                    "verified",
                )
            )
        ):
            return False

        return True

    @staticmethod
    def _extract_url(
        line: str,
    ) -> str | None:
        """
        Extract the first HTTP(S) URL from a Dalfox output line.
        """

        match = re.search(
            r"https?://[^\s\]\[<>\"']+",
            line,
            re.IGNORECASE,
        )

        if not match:
            return None

        return match.group(
            0
        ).rstrip(
            ".,;)"
        )

    @staticmethod
    def _extract_parameter(
        line: str,
    ) -> str | None:
        """
        Extract a parameter from common Dalfox output forms.
        """

        patterns = (
            r"(?:parameter|param)\s*[:=]\s*[\"']?([A-Za-z0-9_.\-\[\]]+)",
            r"(?:parameter|param)\s+[\"']([A-Za-z0-9_.\-\[\]]+)[\"']",
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
            url = url_match.group(
                0
            )

            query_match = re.search(
                r"[?&]([^=&\s]+)=",
                url,
            )

            if query_match:
                return query_match.group(
                    1
                )

        return None

    @staticmethod
    def _extract_payload(
        line: str,
    ) -> str | None:
        """
        Extract a payload from common Dalfox output forms.
        """

        patterns = (
            r"payload\s*[:=]\s*(.+)$",
            r"\[poc\]\s*(.+)$",
            r"\[found\]\s*(.+)$",
        )

        for pattern in patterns:

            match = re.search(
                pattern,
                line,
                re.IGNORECASE,
            )

            if not match:
                continue

            value = match.group(
                1
            ).strip()

            if value:
                return value

        return None

    @staticmethod
    def _extract_xss_type(
        line: str,
    ) -> str | None:
        """
        Extract a likely XSS classification.
        """

        normalized = line.lower()

        if "stored" in normalized:
            return "Stored"

        if "dom" in normalized:
            return "DOM-Based"

        if "reflected" in normalized:
            return "Reflected"

        return None

    @staticmethod
    def _extract_host(
        url: str | None,
    ) -> str | None:
        """
        Extract hostname from a URL without introducing a URL dependency.
        """

        if not url:
            return None

        match = re.match(
            r"https?://([^/:?#]+)",
            url,
            re.IGNORECASE,
        )

        if not match:
            return None

        return match.group(
            1
        )

    @staticmethod
    def _extract_port(
        url: str | None,
    ) -> int | None:
        """
        Extract an explicit URL port.
        """

        if not url:
            return None

        match = re.match(
            r"https?://[^/:?#]+:(\d+)",
            url,
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

    ###########################################################################
    # Generic Helpers
    ###########################################################################

    @staticmethod
    def _observation_fingerprint(
        observation: Mapping[str, Any],
    ) -> str:
        """
        Build a local parser fingerprint.

        This is only used to remove duplicate parser output. The universal
        deduplication engine remains responsible for cross-tool correlation.
        """

        components = (
            str(
                observation.get(
                    "category",
                    "",
                )
            ),
            str(
                observation.get(
                    "url",
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
                observation.get(
                    "metadata",
                    {},
                ).get(
                    "payload",
                    "",
                )
            ),
        )

        return "|".join(
            component.strip().lower()
            for component in components
        )

    @staticmethod
    def _integer_option(
        value: Any,
        name: str,
        minimum: int,
        maximum: int | None = None,
    ) -> int:
        """
        Validate an integer command-line option.
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
                f"Dalfox {name} must be an integer."
            ) from exc

        if normalized < minimum:
            raise ValueError(
                f"Dalfox {name} must be >= {minimum}."
            )

        if (
            maximum is not None
            and normalized > maximum
        ):
            raise ValueError(
                f"Dalfox {name} must be <= {maximum}."
            )

        return normalized

    @staticmethod
    def _result_value(
        result: Any,
        field_name: str,
    ) -> Any:
        """
        Retrieve a result field from a mapping or object.
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
        Determine whether Dalfox execution completed successfully.
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
    "DalfoxCollector",
]

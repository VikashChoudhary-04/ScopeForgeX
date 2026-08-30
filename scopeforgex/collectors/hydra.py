"""
ScopeForgeX Hydra Collector
============================

Collector adapter for Hydra.

Hydra is used by ScopeForgeX for explicitly authorized online credential
assessment. It is not part of the default assessment pipeline.

Responsibilities
----------------

- Parse Hydra execution results.
- Preserve raw stdout and stderr.
- Extract explicitly reported valid credentials.
- Preserve host, port, service, and username information.
- Redact passwords from normalized evidence.
- Produce normalized observations for the universal Finding pipeline.
- Keep parsing independent from command construction and execution.

The collector does not:

- Construct Hydra commands.
- Execute Hydra.
- Decide whether credential testing is authorized.
- Treat ambiguous Hydra output as a valid credential.
- Perform global finding deduplication.
- Perform cross-tool correlation.
- Perform final risk classification.

Architecture
------------

Authorized Target
        |
        v
Hydra Tool Adapter
        |
        v
Tool Executor
        |
        v
Hydra
        |
        +--> Raw stdout/stderr
        |
        v
Hydra Collector
        |
        v
Normalized Observations
        |
        v
Finding Normalizer
        |
        v
Correlation / Risk Engine
        |
        v
Report

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import re
from typing import Any, Iterable, Mapping

from scopeforgex.collectors.base import BaseCollector


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "hydra"

CATEGORY_CREDENTIAL = "credential_assessment"

CREDENTIAL_FINDING = "PASSWORD_SECURITY"

DETECTION_METHOD = "Hydra Credential Validation"

DEFAULT_SEVERITY = "High"
DEFAULT_CONFIDENCE = "Confirmed"

_PASSWORD_FIELD_PATTERN = re.compile(
    r"(\bpassword\s*:\s*)(.*?)(?=\s+\b(?:login|host)\s*:|$)",
    re.IGNORECASE,
)

_HOST_PATTERN = re.compile(
    r"\bhost\s*:\s*(\S+)",
    re.IGNORECASE,
)

_LOGIN_PATTERN = re.compile(
    r"\blogin\s*:\s*(.*?)(?=\s+\b(?:password|host)\s*:|$)",
    re.IGNORECASE,
)

_PASSWORD_PATTERN = re.compile(
    r"\bpassword\s*:\s*(.*?)(?=\s+\b(?:login|host)\s*:|$)",
    re.IGNORECASE,
)

_SERVICE_PATTERN = re.compile(
    r"\[\d+\]\[([^\]]+)\]",
    re.IGNORECASE,
)

_PORT_PATTERN = re.compile(
    r"\[(\d+)\]\[[^\]]+\]",
    re.IGNORECASE,
)

_FAILURE_MARKERS = (
    "0 valid password",
    "0 valid passwords",
    "0 valid",
    "no valid password",
    "no valid passwords",
)


###############################################################################
# Generic Helpers
###############################################################################


def _text(value: Any) -> str:
    """Return a normalized string representation."""

    if value is None:
        return ""

    return str(value).strip()


def _optional_text(value: Any) -> str | None:
    """Return normalized text or None for an empty value."""

    normalized = _text(value)

    return normalized or None


def _safe_int(value: Any) -> int | None:
    """Convert a value to an integer when possible."""

    if value is None:
        return None

    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def _lines(output: Any) -> list[str]:
    """
    Convert output into normalized non-empty lines.

    Supports strings, bytes, and iterable output values.
    """

    if output is None:
        return []

    if isinstance(output, bytes):
        output = output.decode(
            "utf-8",
            errors="replace",
        )

    if isinstance(output, str):
        return [
            line.rstrip()
            for line in output.splitlines()
            if line.strip()
        ]

    if isinstance(output, Iterable):
        result: list[str] = []

        for item in output:
            line = _text(item)

            if line:
                result.append(line)

        return result

    normalized = _text(output)

    return [normalized] if normalized else []


def _is_failure_output(output: str) -> bool:
    """
    Determine whether Hydra explicitly reports no valid credentials.

    This is intentionally conservative. Absence of a success record is
    already sufficient to produce no credential observation; failure markers
    are only used as an additional guard.
    """

    lowered = output.lower()

    return any(
        marker in lowered
        for marker in _FAILURE_MARKERS
    )


def _result_value(
    result: Any,
    field_name: str,
) -> Any:
    """
    Retrieve a field from either a mapping or an execution-result object.
    """

    if isinstance(result, Mapping):
        return result.get(field_name)

    return getattr(
        result,
        field_name,
        None,
    )


def _result_success(result: Any) -> bool:
    """
    Determine whether the underlying Hydra execution succeeded.

    A successful execution does not imply a successful credential attack.
    This value only describes process execution.
    """

    explicit_success = _result_value(
        result,
        "success",
    )

    if isinstance(
        explicit_success,
        bool,
    ):
        return explicit_success

    returncode = _result_value(
        result,
        "returncode",
    )

    if returncode is None:
        returncode = _result_value(
            result,
            "return_code",
        )

    if returncode is None:
        return True

    try:
        return int(returncode) == 0
    except (TypeError, ValueError):
        return False


###############################################################################
# Observation
###############################################################################


class HydraObservation:
    """
    Structured Hydra observation.

    The universal Finding model remains the canonical representation after
    normalization. This object only represents collector-level evidence.
    """

    def __init__(
        self,
        *,
        title: str,
        description: str,
        target: str = "",
        host: str | None = None,
        port: int | None = None,
        service: str | None = None,
        username: str | None = None,
        credential: str | None = None,
        severity: str = DEFAULT_SEVERITY,
        confidence: str = DEFAULT_CONFIDENCE,
        evidence: str = "",
        metadata: Mapping[str, Any] | None = None,
    ) -> None:
        self.title = title
        self.description = description
        self.target = target
        self.host = host
        self.port = port
        self.service = service
        self.username = username
        self.credential = credential
        self.severity = severity
        self.confidence = confidence
        self.source_tool = TOOL_NAME
        self.detection_method = DETECTION_METHOD
        self.evidence = evidence
        self.metadata = dict(
            metadata or {}
        )

    def as_dict(
        self,
        *,
        include_credential: bool = False,
    ) -> dict[str, Any]:
        """
        Convert the observation into a normalized mapping.

        Password material is excluded by default.
        """

        metadata = dict(
            self.metadata
        )

        if self.service:
            metadata.setdefault(
                "service",
                self.service,
            )

        if self.username:
            metadata.setdefault(
                "username",
                self.username,
            )

        metadata.setdefault(
            "credential_present",
            self.credential is not None,
        )

        observation = {
            "type": "vulnerability",
            "category": CREDENTIAL_FINDING,
            "title": self.title,
            "target": self.target,
            "host": self.host,
            "port": self.port,
            "url": None,
            "parameter": None,
            "severity": self.severity,
            "confidence": self.confidence,
            "description": self.description,
            "evidence": {
                "raw_line": self.evidence,
                "service": self.service,
                "username": self.username,
                "credential_present": (
                    self.credential is not None
                ),
            },
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "cwe": None,
            "cve": None,
            "references": [],
            "impact": (
                "A valid credential was reported by Hydra during an "
                "authorized online authentication assessment. The exposed "
                "credential may permit unauthorized access if the account "
                "remains active and the credential is usable."
            ),
            "remediation": (
                "Disable or remove unnecessary accounts, enforce strong "
                "unique passwords, implement multi-factor authentication, "
                "apply account lockout or rate-limiting controls where "
                "appropriate, and rotate any credential confirmed as "
                "compromised."
            ),
            "metadata": metadata,
        }

        if include_credential:
            observation["evidence"]["credential"] = self.credential

        return observation

    def __repr__(self) -> str:
        """
        Return a representation that never exposes the credential.
        """

        return (
            "HydraObservation("
            f"title={self.title!r}, "
            f"target={self.target!r}, "
            f"host={self.host!r}, "
            f"port={self.port!r}, "
            f"service={self.service!r}, "
            f"username={self.username!r}, "
            "credential=[REDACTED]"
            ")"
        )


###############################################################################
# Collector
###############################################################################


class HydraCollector(BaseCollector):
    """
    Parse Hydra execution results into normalized ScopeForgeX evidence.

    The collector does not invoke Hydra and does not construct commands.
    """

    name = TOOL_NAME

    tool_name = TOOL_NAME

    description = (
        "Parse authorized Hydra credential-assessment output "
        "into normalized observations."
    )

    category = "validation"

    binary = TOOL_NAME

    ###########################################################################
    # Collection
    ###########################################################################

    def collect(
        self,
        target: str | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Execute-independent collector interface.

        The actual process execution is delegated to BaseCollector.execute(),
        consistent with the other ScopeForgeX collectors.
        """

        options = dict(
            options or {}
        )

        output_result = options.get(
            "result"
        )

        if output_result is None:
            raise ValueError(
                "HydraCollector.collect() requires an execution "
                "result in options['result']."
            )

        command = options.get(
            "command",
            [],
        )

        if command is None:
            command = []

        if not isinstance(
            command,
            (list, tuple),
        ):
            raise TypeError(
                "Hydra collector command must be a list or tuple."
            )

        return self.parse_result(
            target=(
                target
                or options.get(
                    "target",
                    "",
                )
            ),
            result=output_result,
            command=[
                str(argument)
                for argument in command
            ],
            options=options,
        )

    ###########################################################################
    # Result Parsing
    ###########################################################################

    def parse_result(
        self,
        target: str | None,
        result: Any,
        command: list[str] | None = None,
        options: Mapping[str, Any] | None = None,
    ) -> dict[str, Any]:
        """
        Parse Hydra stdout/stderr into normalized collector evidence.

        Raw output is always preserved.

        Passwords are never placed into normalized evidence by default.
        """

        stdout = _result_value(
            result,
            "stdout",
        )

        stderr = _result_value(
            result,
            "stderr",
        )

        stdout_text = (
            stdout.decode(
                "utf-8",
                errors="replace",
            )
            if isinstance(stdout, bytes)
            else _text(stdout)
        )

        stderr_text = (
            stderr.decode(
                "utf-8",
                errors="replace",
            )
            if isinstance(stderr, bytes)
            else _text(stderr)
        )

        combined = "\n".join(
            part
            for part in (
                stdout_text,
                stderr_text,
            )
            if part
        )

        execution_success = _result_success(
            result
        )

        returncode = _result_value(
            result,
            "returncode",
        )

        if returncode is None:
            returncode = _result_value(
                result,
                "return_code",
            )

        observations = self._parse_output(
            combined,
            target or "",
            options=options,
        )

        return {
            "collector": self.name,
            "category": self.category,
            "target": _text(target),
            "success": execution_success,
            "observations": [
                observation.as_dict()
                for observation in observations
            ],
            "observation_count": len(
                observations
            ),
            "raw": {
                "stdout": stdout_text,
                "stderr": stderr_text,
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

    def _parse_output(
        self,
        output: str,
        target: str,
        *,
        options: Mapping[str, Any] | None = None,
    ) -> list[HydraObservation]:
        """
        Parse Hydra output into structured observations.

        Only explicit Hydra success records are accepted.
        """

        lines = _lines(
            output
        )

        if not lines:
            return []

        if _is_failure_output(
            "\n".join(lines)
        ):
            return []

        parsed = self._parse_successes(
            lines
        )

        default_host = _optional_text(
            (options or {}).get(
                "host"
            )
        )

        default_port = _safe_int(
            (options or {}).get(
                "port"
            )
        )

        default_service = _optional_text(
            (options or {}).get(
                "service"
            )
        )

        observations: list[HydraObservation] = []

        seen: set[tuple[Any, ...]] = set()

        for item in parsed:

            host = (
                item.get("host")
                or default_host
            )

            port = (
                item.get("port")
                if item.get("port") is not None
                else default_port
            )

            service = (
                item.get("service")
                or default_service
            )

            username = item.get(
                "username"
            )

            credential = item.get(
                "credential"
            )

            if not username and credential is None:
                continue

            fingerprint = (
                host,
                port,
                service,
                username,
                credential,
            )

            if fingerprint in seen:
                continue

            seen.add(
                fingerprint
            )

            description_parts = [
                "Hydra explicitly reported a valid credential "
                "during authorized credential assessment."
            ]

            if service:
                description_parts.append(
                    f"Service: {service}."
                )

            if host:
                description_parts.append(
                    f"Host: {host}."
                )

            if port is not None:
                description_parts.append(
                    f"Port: {port}."
                )

            observations.append(
                HydraObservation(
                    title=self._build_title(
                        service=service,
                        host=host,
                    ),
                    description=" ".join(
                        description_parts
                    ),
                    target=(
                        _text(target)
                        or host
                        or ""
                    ),
                    host=host,
                    port=port,
                    service=service,
                    username=username,
                    credential=credential,
                    evidence=self._redact_evidence(
                        item.get(
                            "raw",
                            "",
                        )
                    ),
                    metadata={
                        "parser": TOOL_NAME,
                        "finding_type": CREDENTIAL_FINDING,
                        "credential_validated": True,
                    },
                )
            )

        return observations

    ###########################################################################
    # Success Parsing
    ###########################################################################

    @staticmethod
    def _parse_successes(
        lines: list[str],
    ) -> list[dict[str, Any]]:
        """
        Parse explicit Hydra valid-credential records.

        Typical Hydra output resembles:

            [22][ssh] host: 192.0.2.10
            login: admin
            password: secret

        The parser also supports the common single-line form:

            [22][ssh] host: 192.0.2.10 login: admin password: secret

        Field order is intentionally flexible.
        """

        results: list[dict[str, Any]] = []

        for line in lines:

            lowered = line.lower()

            if (
                "login:" not in lowered
                and "password:" not in lowered
            ):
                continue

            host_match = _HOST_PATTERN.search(
                line
            )

            login_match = _LOGIN_PATTERN.search(
                line
            )

            password_match = _PASSWORD_PATTERN.search(
                line
            )

            service_match = _SERVICE_PATTERN.search(
                line
            )

            port_match = _PORT_PATTERN.search(
                line
            )

            username = _optional_text(
                login_match.group(1)
                if login_match
                else None
            )

            credential = None

            if password_match:
                credential = password_match.group(
                    1
                ).strip()

                if not credential:
                    credential = None

            item = {
                "host": (
                    _optional_text(
                        host_match.group(1)
                    )
                    if host_match
                    else None
                ),
                "port": (
                    _safe_int(
                        port_match.group(1)
                    )
                    if port_match
                    else None
                ),
                "service": (
                    _optional_text(
                        service_match.group(1)
                    )
                    if service_match
                    else None
                ),
                "username": username,
                "credential": credential,
                "raw": line,
            }

            results.append(
                item
            )

        return results

    ###########################################################################
    # Formatting
    ###########################################################################

    @staticmethod
    def _build_title(
        *,
        service: str | None,
        host: str | None,
    ) -> str:
        """Build a concise finding title."""

        if service and host:
            return (
                f"Valid {service} credential on {host}"
            )

        if service:
            return (
                f"Valid {service} credential discovered"
            )

        if host:
            return (
                f"Valid credential discovered on {host}"
            )

        return "Valid credential discovered"

    @staticmethod
    def _redact_evidence(
        raw_line: Any,
    ) -> str:
        """
        Redact password material from normalized evidence.

        Raw stdout/stderr remain available under the raw result section.
        """

        raw = _text(
            raw_line
        )

        if not raw:
            return ""

        return _PASSWORD_FIELD_PATTERN.sub(
            r"\1[REDACTED]",
            raw,
        )


###############################################################################
# Compatibility
###############################################################################


Collector = HydraCollector


###############################################################################
# Public API
###############################################################################


__all__ = [
    "HydraCollector",
    "HydraObservation",
    "Collector",
    "TOOL_NAME",
    "CATEGORY_CREDENTIAL",
    "CREDENTIAL_FINDING",
    "DETECTION_METHOD",
]

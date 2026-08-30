"""
ScopeForgeX Hashcat Collector
==============================

Collector for parsing Hashcat credential-assessment output into normalized
ScopeForgeX observations.

Hashcat is an explicitly selectable credential-assessment capability.
It is not part of the default assessment pipeline.

Architecture
------------

Tool Adapter
    |
    v
Hashcat Execution
    |
    v
Raw Hashcat Output
    |
    v
HashcatCollector
    |
    v
Normalized Observations
    |
    v
Finding Normalizer
    |
    v
Universal Finding Model

Design Principles
-----------------

- Preserve raw execution output.
- Do not execute Hashcat from the collector.
- Do not construct Hashcat commands here.
- Treat confirmed recovered credentials as assessment observations.
- Do not expose recovered plaintext credentials in normalized evidence.
- Preserve hash material only when explicitly reported.
- Preserve hash type when supplied by the caller.
- Ignore Hashcat status, progress, benchmark, and informational output.
- Keep parsing independent from execution and command construction.
- Produce observations compatible with the universal Finding model.

The tool adapter owns command construction and the runtime owns process
execution. This module is responsible only for parsing and normalization.

ScopeForgeX 3.0.0
"""

from __future__ import annotations

import re
from dataclasses import dataclass, field
from typing import Any, Iterable

from .base import BaseCollector


###############################################################################
# Constants
###############################################################################


TOOL_NAME = "hashcat"

CATEGORY_CREDENTIAL = "PASSWORD_SECURITY"

DETECTION_METHOD = "Hashcat Credential Recovery"

DEFAULT_SEVERITY = "High"
DEFAULT_CONFIDENCE = "Confirmed"


###############################################################################
# Helpers
###############################################################################


def _text(value: Any) -> str:
    """Return a normalized string representation."""

    if value is None:
        return ""

    return str(value).strip()


def _optional_text(value: Any) -> str | None:
    """Return normalized text or None when empty."""

    normalized = _text(value)

    return normalized or None


def _lines(output: Any) -> list[str]:
    """
    Convert supported output representations into normalized lines.
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

    value = _text(output)

    return [value] if value else []


def _redact_secret(value: str) -> str:
    """
    Replace sensitive recovered credential material with a redaction marker.
    """

    return "[REDACTED]" if value else value


###############################################################################
# Observation
###############################################################################


@dataclass(slots=True)
class HashcatObservation:
    """
    Structured credential-recovery observation.

    The plaintext credential is intentionally not retained in the normalized
    observation. Hashcat has already established that the supplied hash can
    be recovered, which is the security-relevant assessment result.
    """

    title: str

    description: str

    target: str = ""

    hash_value: str | None = None

    hash_type: str | None = None

    severity: str = DEFAULT_SEVERITY

    confidence: str = DEFAULT_CONFIDENCE

    source_tool: str = TOOL_NAME

    detection_method: str = DETECTION_METHOD

    evidence: str = ""

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the observation into the universal Finding pipeline.
        """

        metadata = dict(
            self.metadata
        )

        if self.hash_type:
            metadata.setdefault(
                "hash_type",
                self.hash_type,
            )

        if self.hash_value:
            metadata.setdefault(
                "hash_present",
                True,
            )

        metadata.setdefault(
            "credential_recovered",
            True,
        )

        return {
            "title": self.title,
            "category": CATEGORY_CREDENTIAL,
            "description": self.description,
            "target": self.target,
            "severity": self.severity,
            "confidence": self.confidence,
            "evidence": self.evidence,
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "metadata": metadata,
        }


###############################################################################
# Collector
###############################################################################


class HashcatCollector(BaseCollector):
    """
    Parse Hashcat output into ScopeForgeX observations.

    The collector does not execute Hashcat and does not construct commands.
    """

    name = TOOL_NAME

    tool_name = TOOL_NAME

    ###########################################################################
    # Public Interface
    ###########################################################################

    def collect(
        self,
        output: Any,
        *,
        target: str = "",
        hash_type: str | None = None,
        **kwargs: Any,
    ) -> list[HashcatObservation]:
        """
        Parse Hashcat output.

        Parameters
        ----------
        output:
            Raw Hashcat stdout/stderr or equivalent output.

        target:
            Optional target associated with the credential assessment.

        hash_type:
            Optional Hashcat mode/type supplied by the execution layer.

        Returns
        -------
        list[HashcatObservation]
            Confirmed credential-recovery observations.
        """

        lines = _lines(output)

        if not lines:
            return []

        observations: list[HashcatObservation] = []

        for line in lines:

            parsed = self._parse_recovery_line(
                line
            )

            if parsed is None:
                continue

            item_hash = parsed.get(
                "hash"
            )

            item_hash_type = (
                parsed.get("hash_type")
                or hash_type
            )

            if not item_hash:
                continue

            description = (
                "Hashcat recovered a credential from a supplied password "
                "hash during authorized credential assessment."
            )

            if item_hash_type:
                description += (
                    f" Hash type: {item_hash_type}."
                )

            observations.append(
                HashcatObservation(
                    title=self._build_title(
                        hash_type=item_hash_type
                    ),
                    description=description,
                    target=target,
                    hash_value=item_hash,
                    hash_type=item_hash_type,
                    evidence=self._safe_evidence(
                        line
                    ),
                    metadata={
                        "parser": "hashcat",
                        "credential_recovered": True,
                    },
                )
            )

        return self._deduplicate(
            observations
        )

    ###########################################################################
    # Parsing
    ###########################################################################

    @classmethod
    def _parse_recovery_line(
        cls,
        line: str,
    ) -> dict[str, str | None] | None:
        """
        Parse a confirmed Hashcat recovery line.

        The most useful machine-readable Hashcat representation is the
        --show-style:

            hash:plaintext

        Explicit key/value representations are also supported:

            hash: <hash> password: <password>

        The plaintext is parsed only to establish that recovery occurred.
        It is never returned to the normalized observation.
        """

        normalized = _text(line)

        if not normalized:
            return None

        if cls._is_status_line(
            normalized
        ):
            return None

        key_value = cls._parse_key_value_line(
            normalized
        )

        if key_value is not None:
            return key_value

        if ":" not in normalized:
            return None

        hash_value, plaintext = normalized.split(
            ":",
            1,
        )

        hash_value = hash_value.strip()
        plaintext = plaintext.strip()

        if not hash_value or not plaintext:
            return None

        if not cls._looks_like_hash(
            hash_value
        ):
            return None

        return {
            "hash": hash_value,
            "hash_type": None,
        }

    @staticmethod
    def _parse_key_value_line(
        line: str,
    ) -> dict[str, str | None] | None:
        """
        Parse explicit Hashcat key/value recovery output.
        """

        hash_match = re.search(
            r"\bhash\s*:\s*(.*?)(?=\s+\b(?:password|plaintext)\s*:|$)",
            line,
            flags=re.IGNORECASE,
        )

        password_match = re.search(
            r"\b(?:password|plaintext)\s*:\s*(.+)$",
            line,
            flags=re.IGNORECASE,
        )

        if not hash_match or not password_match:
            return None

        hash_value = hash_match.group(
            1
        ).strip()

        plaintext = password_match.group(
            1
        ).strip()

        if not hash_value or not plaintext:
            return None

        return {
            "hash": hash_value,
            "hash_type": None,
        }

    @staticmethod
    def _is_status_line(
        line: str,
    ) -> bool:
        """
        Identify Hashcat status/progress/informational output.
        """

        lowered = line.lower()

        status_markers = (
            "session..........:",
            "status...........:",
            "hash.mode........:",
            "hash.target......:",
            "time.start.......:",
            "time.estimated...:",
            "guess.base.......:",
            "guess.queue......:",
            "speed.#",
            "recovered........:",
            "progress.........:",
            "restore.point....:",
            "candidates.#",
            "hardware.mon.#",
            "device.#",
            "started:",
            "stopped:",
            "approaching final",
            "dictionary cache",
            "hashcat (",
        )

        return any(
            marker in lowered
            for marker in status_markers
        )

    @staticmethod
    def _looks_like_hash(
        value: str,
    ) -> bool:
        """
        Apply conservative validation to a Hashcat --show hash field.

        This intentionally accepts common hash formats without attempting to
        identify the exact hash algorithm. Hash type belongs to the execution
        configuration and/or upstream detection layer.
        """

        normalized = value.strip()

        if not normalized:
            return False

        if len(normalized) < 8:
            return False

        if any(
            character.isspace()
            for character in normalized
        ):
            return False

        return bool(
            re.search(
                r"[0-9a-fA-F]",
                normalized,
            )
        )

    ###########################################################################
    # Formatting / Evidence
    ###########################################################################

    @staticmethod
    def _build_title(
        *,
        hash_type: str | None,
    ) -> str:
        """Build a concise observation title."""

        if hash_type:
            return (
                f"Password recovered from {hash_type} hash"
            )

        return "Password recovered from password hash"

    @staticmethod
    def _safe_evidence(
        line: str,
    ) -> str:
        """
        Return evidence with recovered plaintext redacted.
        """

        normalized = _text(line)

        if not normalized:
            return ""

        explicit = re.search(
            r"(\b(?:password|plaintext)\s*:\s*)(.+)$",
            normalized,
            flags=re.IGNORECASE,
        )

        if explicit:
            return (
                normalized[:explicit.start(2)]
                + _redact_secret(
                    explicit.group(2)
                )
            )

        if ":" in normalized:
            hash_part, plaintext = normalized.split(
                ":",
                1,
            )

            if (
                hash_part.strip()
                and plaintext.strip()
            ):
                return (
                    f"{hash_part.strip()}:[REDACTED]"
                )

        return normalized

    ###########################################################################
    # Deduplication
    ###########################################################################

    @staticmethod
    def _deduplicate(
        observations: list[HashcatObservation],
    ) -> list[HashcatObservation]:
        """
        Remove duplicate recovery observations.
        """

        unique: list[HashcatObservation] = []
        seen: set[tuple[str, str, str]] = set()

        for observation in observations:

            fingerprint = (
                observation.target,
                observation.hash_value or "",
                observation.hash_type or "",
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


###############################################################################
# Compatibility Alias
###############################################################################


Collector = HashcatCollector


###############################################################################
# Public API
###############################################################################


__all__ = [
    "HashcatCollector",
    "HashcatObservation",
    "Collector",
    "TOOL_NAME",
    "CATEGORY_CREDENTIAL",
    "DETECTION_METHOD",
]

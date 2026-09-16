"""
ScopeForgeX Software / Framework Identity Analyzer
===================================================

ScopeForgeX-native analyzer for identifying software and framework
implementations from evidence already collected by the workflow.

The analyzer is passive and evidence-driven:

- It does not perform network requests.
- It does not execute external tools.
- It does not query NVD or CISA KEV directly.
- It does not claim that software is vulnerable.
- It preserves the original evidence used for identification.

The resulting observations are consumed by the existing
VulnerabilityIntelligenceEngine, which performs CPE resolution and
NVD/CVE/KEV correlation.

v1.0.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
import re
from typing import Any, Iterable, Mapping


###############################################################################
# Constants
###############################################################################


SOFTWARE_IDENTITY = "SOFTWARE_IDENTITY"


###############################################################################
# Signature Definitions
###############################################################################


@dataclass(frozen=True, slots=True)
class SoftwareSignature:
    """
    Deterministic software/framework identification signature.
    """

    product: str
    vendor: str
    patterns: tuple[re.Pattern[str], ...]
    observation_type: str = "FRAMEWORK"


EXPRESS_SIGNATURE = SoftwareSignature(
    product="express",
    vendor="openjsf",
    patterns=(
        re.compile(
            r"\bExpress\s*\^?\s*"
            r"(?P<version>[0-9][A-Za-z0-9._+-]*)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bExpress(?:\.js)?\s+"
            r"[v=]?\s*(?P<version>[0-9][A-Za-z0-9._+-]*)\b",
            re.IGNORECASE,
        ),
    ),
)


JQUERY_SIGNATURE = SoftwareSignature(
    product="jquery",
    vendor="jquery",
    patterns=(
        re.compile(
            r"\bjQuery\s*:\s*"
            r"(?P<version>[0-9][A-Za-z0-9._+-]*)\b",
            re.IGNORECASE,
        ),
        re.compile(
            r"\bjQuery(?:\.js)?\s+"
            r"[v=]?\s*(?P<version>[0-9][A-Za-z0-9._+-]*)\b",
            re.IGNORECASE,
        ),
    ),
)


DEFAULT_SIGNATURES = (
    EXPRESS_SIGNATURE,
    JQUERY_SIGNATURE,
)


###############################################################################
# Observation Model
###############################################################################


@dataclass(slots=True)
class SoftwareIdentityObservation:
    """
    Normalized software/framework identity observation.

    This represents detected software identity, not a vulnerability.
    """

    observation_type: str

    title: str

    value: str

    target: str

    description: str

    evidence: dict[str, Any] = field(
        default_factory=dict,
    )

    source_tool: str = "scopeforgex"

    detection_method: str = (
        "Software / Framework Identity Analyzer"
    )

    confidence: str = "High"

    category: str = "software_identity"

    metadata: dict[str, Any] = field(
        default_factory=dict,
    )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Serialize the observation into a stable dictionary.
        """

        return {
            "observation_type": self.observation_type,
            "title": self.title,
            "value": self.value,
            "target": self.target,
            "description": self.description,
            "evidence": dict(self.evidence),
            "source_tool": self.source_tool,
            "detection_method": self.detection_method,
            "confidence": self.confidence,
            "category": self.category,
            "metadata": dict(self.metadata),
        }


###############################################################################
# Analyzer
###############################################################################


class SoftwareIdentityAnalyzer:
    """
    Analyze already-collected evidence for explicit software/framework
    identity.

    The analyzer currently contains only signatures for identities that can
    be detected deterministically from collected evidence. It intentionally
    avoids speculative technology inference.
    """

    name = "software_identity"

    description = (
        "Identify software and framework products and versions from "
        "already-collected assessment evidence."
    )

    def __init__(
        self,
        signatures: Iterable[
            SoftwareSignature
        ] | None = None,
    ) -> None:
        self.signatures = tuple(
            signatures
            if signatures is not None
            else DEFAULT_SIGNATURES
        )

    def analyze(
        self,
        evidence: Mapping[str, Any],
    ) -> list[SoftwareIdentityObservation]:
        """
        Analyze collected evidence for software/framework identity.
        """

        if not isinstance(
            evidence,
            Mapping,
        ):
            return []

        target = self._text(
            evidence.get("target")
        )

        if not target:
            target = self._text(
                evidence.get("url")
            )

        candidates = list(
            self._iter_text_evidence(
                evidence
            )
        )

        if not candidates:
            return []

        observations: list[
            SoftwareIdentityObservation
        ] = []

        seen: set[
            tuple[str, str, str]
        ] = set()

        for signature in self.signatures:

            for text, source, source_evidence in candidates:

                for pattern in signature.patterns:

                    match = pattern.search(
                        text
                    )

                    if not match:
                        continue

                    version = self._text(
                        match.groupdict().get(
                            "version"
                        )
                    )

                    if not version:
                        continue

                    raw_version = (
                        match.group(0)
                    )

                    key = (
                        signature.product,
                        version.lower(),
                        target.lower(),
                    )

                    if key in seen:
                        continue

                    seen.add(key)

                    observation = (
                        self._build_observation(
                            target=target,
                            signature=signature,
                            version=version,
                            raw_version=raw_version,
                            source=source,
                            source_evidence=source_evidence,
                        )
                    )

                    observations.append(
                        observation
                    )

                    break

        return observations

    # ------------------------------------------------------------------
    # Evidence extraction
    # ------------------------------------------------------------------

    def _iter_text_evidence(
        self,
        evidence: Mapping[str, Any],
    ) -> Iterable[
        tuple[str, str, dict[str, Any]]
    ]:
        """
        Yield searchable text together with its evidence source.

        Only already-collected evidence is inspected.

        Supported evidence shapes include:

        - direct stdout evidence
        - serialized CollectorObservation dictionaries
        - runtime collector_observations collections
        - structured HTTP response evidence
        """

        yielded: set[
            tuple[str, str]
        ] = set()

        stdout = self._text(
            evidence.get("stdout")
        )

        if stdout:
            key = ("stdout", stdout)

            if key not in yielded:
                yielded.add(key)

                yield (
                    stdout,
                    "stdout",
                    {
                        "source": "stdout",
                        "text": stdout,
                    },
                )

        # --------------------------------------------------------------
        # Direct serialized CollectorObservation support
        #
        # CollectorObservation.as_dict() produces:
        #
        # {
        #     ...
        #     "evidence": {
        #         "body": "...",
        #         "header": "...",
        #         ...
        #     }
        # }
        #
        # This is distinct from the runtime shape:
        #
        # {
        #     "collector_observations": [
        #         {
        #             "evidence": {...}
        #         }
        #     ]
        # }
        # --------------------------------------------------------------

        direct_observation_evidence = evidence.get(
            "evidence",
            {},
        )

        if isinstance(
            direct_observation_evidence,
            Mapping,
        ):

            for field_name in (
                "body",
                "raw_header",
                "header",
                "request",
                "title",
                "url",
                "value",
            ):

                value = direct_observation_evidence.get(
                    field_name
                )

                text = self._text(
                    value
                )

                if not text:
                    continue

                key = (
                    f"direct_observation:{field_name}",
                    text,
                )

                if key in yielded:
                    continue

                yielded.add(key)

                yield (
                    text,
                    f"observation.evidence.{field_name}",
                    {
                        "source": (
                            f"observation.evidence.{field_name}"
                        ),
                        "observation": dict(
                            evidence
                        ),
                    },
                )

            for text, source in self._iter_nested_text(
                direct_observation_evidence.get("tech"),
                prefix="observation.evidence.tech",
            ):

                key = (
                    source,
                    text,
                )

                if key in yielded:
                    continue

                yielded.add(key)

                yield (
                    text,
                    source,
                    {
                        "source": source,
                        "observation": dict(
                            evidence
                        ),
                    },
                )

        # --------------------------------------------------------------
        # Runtime collector observations
        # --------------------------------------------------------------

        for observation in (
            evidence.get(
                "collector_observations",
                [],
            )
            or []
        ):

            if not isinstance(
                observation,
                Mapping,
            ):
                continue

            observation_evidence = (
                observation.get(
                    "evidence",
                    {},
                )
            )

            if not isinstance(
                observation_evidence,
                Mapping,
            ):
                observation_evidence = {}

            for field_name in (
                "body",
                "raw_header",
                "header",
                "request",
                "title",
                "url",
                "value",
            ):

                value = observation_evidence.get(
                    field_name
                )

                text = self._text(
                    value
                )

                if not text:
                    continue

                key = (
                    f"collector:{field_name}",
                    text,
                )

                if key in yielded:
                    continue

                yielded.add(key)

                yield (
                    text,
                    f"collector_observation.{field_name}",
                    {
                        "source": (
                            f"collector_observation.{field_name}"
                        ),
                        "observation": dict(
                            observation
                        ),
                    },
                )

            for text, source in self._iter_nested_text(
                observation_evidence.get("tech"),
                prefix="collector_observation.evidence.tech",
            ):

                key = (
                    source,
                    text,
                )

                if key in yielded:
                    continue

                yielded.add(key)

                yield (
                    text,
                    source,
                    {
                        "source": source,
                        "observation": dict(
                            observation
                        ),
                    },
                )

            value = self._text(
                observation.get(
                    "value"
                )
            )

            if value:
                key = (
                    "collector:value",
                    value,
                )

                if key not in yielded:
                    yielded.add(key)

                    yield (
                        value,
                        "collector_observation.value",
                        {
                            "source": (
                                "collector_observation.value"
                            ),
                            "observation": dict(
                                observation
                            ),
                        },
                    )

        # --------------------------------------------------------------
        # Structured HTTP response evidence
        # --------------------------------------------------------------

        for key in (
            "http_response",
            "http_responses",
        ):

            value = evidence.get(
                key
            )

            for text, source in self._iter_nested_text(
                value,
                prefix=key,
            ):

                dedup_key = (
                    source,
                    text,
                )

                if dedup_key in yielded:
                    continue

                yielded.add(
                    dedup_key
                )

                yield (
                    text,
                    source,
                    {
                        "source": source,
                        "value": value,
                    },
                )

    @classmethod
    def _iter_nested_text(
        cls,
        value: Any,
        *,
        prefix: str,
    ) -> Iterable[
        tuple[str, str]
    ]:
        """
        Recursively extract useful text from existing structured evidence.
        """

        if isinstance(
            value,
            str,
        ):

            text = value.strip()

            if text:
                yield (
                    text,
                    prefix,
                )

            return

        if isinstance(
            value,
            Mapping,
        ):

            for key, item in value.items():

                yield from cls._iter_nested_text(
                    item,
                    prefix=f"{prefix}.{key}",
                )

            return

        if isinstance(
            value,
            (list, tuple),
        ):

            for index, item in enumerate(
                value
            ):

                yield from cls._iter_nested_text(
                    item,
                    prefix=f"{prefix}[{index}]",
                )

    # ------------------------------------------------------------------
    # Evidence normalization
    # ------------------------------------------------------------------

    @staticmethod
    def _compact_source_evidence(
        value: Any,
    ) -> Any:
        """
        Return compact provenance evidence suitable for propagation.

        Raw response/request material is intentionally consumed by the
        analyzer when detecting software identity, but it must not be
        propagated into structured software-intelligence evidence.

        Raw scanner artifacts remain responsible for retaining complete
        forensic material when required.
        """

        if isinstance(value, Mapping):
            compact: dict[str, Any] = {}

            for key, item in value.items():
                key_text = str(key).strip().lower()

                if key_text in {
                    "body",
                    "raw_body",
                    "raw_header",
                    "raw_headers",
                    "request",
                    "raw_request",
                    "response",
                    "raw_response",
                }:
                    continue

                compact[key] = SoftwareIdentityAnalyzer._compact_source_evidence(item)

            return compact

        if isinstance(value, list):
            return [
                SoftwareIdentityAnalyzer._compact_source_evidence(item)
                for item in value
            ]

        if isinstance(value, tuple):
            return tuple(
                SoftwareIdentityAnalyzer._compact_source_evidence(item)
                for item in value
            )

        return value

    # ------------------------------------------------------------------
    # Observation construction
    # ------------------------------------------------------------------

    @staticmethod
    def _build_observation(
        *,
        target: str,
        signature: SoftwareSignature,
        version: str,
        raw_version: str,
        source: str,
        source_evidence: Mapping[str, Any],
    ) -> SoftwareIdentityObservation:
        """
        Construct a normalized software identity observation.
        """

        value = (
            f"{signature.product} {version}"
        )

        return SoftwareIdentityObservation(
            observation_type=(
                signature.observation_type
            ),
            title=(
                f"Software / Framework Identified: "
                f"{signature.product} {version}"
            ),
            value=value,
            target=target,
            description=(
                f"The collected assessment evidence explicitly "
                f"identified {signature.product} version {version}."
            ),
            evidence={
                "source": source,
                "raw_version": raw_version,
                "source_evidence": (
                    SoftwareIdentityAnalyzer._compact_source_evidence(
                        source_evidence
                    )
                ),
            },
            source_tool="scopeforgex",
            detection_method=(
                "Software / Framework Identity Analyzer"
            ),
            confidence="High",
            category="software_identity",
            metadata={
                "product": signature.product,
                "vendor": signature.vendor,
                "version": version,
                "version_raw": raw_version,
                "version_semantics": (
                    "constraint"
                    if "^" in raw_version
                    else "explicit"
                ),
                "observation_type": (
                    signature.observation_type
                ),
                "evidence_source": source,
            },
        )

    @staticmethod
    def _text(
        value: Any,
    ) -> str:
        if value is None:
            return ""

        return str(
            value
        ).strip()


__all__ = [
    "DEFAULT_SIGNATURES",
    "EXPRESS_SIGNATURE",
    "SOFTWARE_IDENTITY",
    "SoftwareIdentityAnalyzer",
    "SoftwareIdentityObservation",
    "SoftwareSignature",
]

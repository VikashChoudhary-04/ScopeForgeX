"""
ScopeForgeX Configuration Package
=================================

Canonical configuration layer for ScopeForgeX.

The configuration system is responsible for:

- Assessment profile selection
- Target configuration
- Target type
- Scope restrictions
- Authorization metadata
- Allowed tools
- Excluded tools
- Per-tool enablement
- Per-tool options
- Rate limits
- Authentication information
- Profile defaults
- User overrides
- Configuration validation

The configuration layer does NOT:

- Execute tools
- Construct tool-specific commands
- Parse tool output
- Generate findings
- Correlate findings
- Generate reports

Those responsibilities belong to their respective architecture layers.

Final architecture principle:

    Scope
        ↓
    Profile
        ↓
    Tool Selection
        ↓
    Tool Configuration
        ↓
    Workflow Engine
        ↓
    Tool Adapter

Supported assessment profiles:

- FAST
- STANDARD
- FULL

The profile determines defaults, not permanent limits. Individual tool
enablement and options may be overridden by the assessment configuration.

Final ScopeForgeX core toolset:

Reconnaissance:
    - amass
    - subhunt
    - nmap
    - dig

Enumeration:
    - httpx
    - katana
    - ffuf
    - whatweb
    - kiterunner
    - jsluice

Vulnerability Assessment:
    - nuclei
    - nikto
    - testssl.sh

Vulnerability Validation:
    - sqlmap
    - dalfox
    - jwt_tool
    - sstimap

Credential Assessment:
    - hydra
    - hashcat

The configuration layer deliberately excludes tools removed from the final
architecture, including:

- subfinder
- gobuster
- naabu
- rustscan
- sslscan
- sslyze
- metasploit

ScopeForgeX 3.0.0
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from typing import Any, Mapping


###############################################################################
# Profile Constants
###############################################################################


PROFILE_FAST = "fast"
PROFILE_STANDARD = "standard"
PROFILE_FULL = "full"

SUPPORTED_PROFILES = (
    PROFILE_FAST,
    PROFILE_STANDARD,
    PROFILE_FULL,
)


###############################################################################
# Final Core Tool Set
###############################################################################


RECONNAISSANCE_TOOLS = (
    "amass",
    "subhunt",
    "nmap",
    "dig",
)

ENUMERATION_TOOLS = (
    "httpx",
    "katana",
    "ffuf",
    "whatweb",
    "kiterunner",
    "jsluice",
)

VULNERABILITY_ASSESSMENT_TOOLS = (
    "nuclei",
    "nikto",
    "testssl.sh",
)

VULNERABILITY_VALIDATION_TOOLS = (
    "sqlmap",
    "dalfox",
    "jwt_tool",
    "sstimap",
)

CREDENTIAL_ASSESSMENT_TOOLS = (
    "hydra",
    "hashcat",
)

CORE_TOOLS = (
    *RECONNAISSANCE_TOOLS,
    *ENUMERATION_TOOLS,
    *VULNERABILITY_ASSESSMENT_TOOLS,
    *VULNERABILITY_VALIDATION_TOOLS,
    *CREDENTIAL_ASSESSMENT_TOOLS,
)

CORE_TOOL_SET = frozenset(
    CORE_TOOLS
)


###############################################################################
# Assessment Phases
###############################################################################


PHASE_RECONNAISSANCE = "reconnaissance"
PHASE_ENUMERATION = "enumeration"
PHASE_VULNERABILITY_ASSESSMENT = (
    "vulnerability_assessment"
)
PHASE_VULNERABILITY_VALIDATION = (
    "vulnerability_validation"
)
PHASE_CREDENTIAL_ASSESSMENT = (
    "credential_assessment"
)


###############################################################################
# Exceptions
###############################################################################


class ConfigurationError(ValueError):
    """
    Raised when ScopeForgeX configuration is invalid.
    """


###############################################################################
# Tool Configuration
###############################################################################


@dataclass(slots=True)
class ToolConfiguration:
    """
    Configuration for one ScopeForgeX tool.

    Attributes:
        enabled:
            Whether the tool is selected for execution.

        options:
            Tool-specific options. These are passed to the tool adapter.
            The configuration layer does not construct commands.

        requires_confirmation:
            Whether execution requires explicit confirmation.

        safe:
            Whether the configuration represents a safe/default execution
            mode.
    """

    enabled: bool = True

    options: dict[str, Any] = field(
        default_factory=dict
    )

    requires_confirmation: bool = False

    safe: bool = True

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a serializable representation.
        """

        return {
            "enabled": self.enabled,
            "options": deepcopy(
                self.options
            ),
            "requires_confirmation": (
                self.requires_confirmation
            ),
            "safe": self.safe,
        }


###############################################################################
# Assessment Profile
###############################################################################


@dataclass(slots=True)
class AssessmentProfile:
    """
    Default configuration for one assessment profile.

    Profiles provide defaults. They do not permanently restrict what the
    assessment may execute.

    Individual tool enablement and options can be overridden in the resolved
    assessment configuration.
    """

    name: str

    description: str = ""

    tools: dict[
        str,
        ToolConfiguration,
    ] = field(
        default_factory=dict
    )

    global_options: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    def tool(
        self,
        name: str,
    ) -> ToolConfiguration:
        """
        Return the profile configuration for a tool.

        Tools outside the final ScopeForgeX core set are rejected.
        """

        normalized = normalize_tool_name(
            name
        )

        if normalized not in CORE_TOOL_SET:
            raise ConfigurationError(
                f"Tool is not part of the ScopeForgeX core toolset: "
                f"{name!r}"
            )

        configuration = self.tools.get(
            normalized
        )

        if configuration is None:
            return ToolConfiguration(
                enabled=False
            )

        return configuration

    def is_enabled(
        self,
        name: str,
    ) -> bool:
        """
        Return whether a tool is enabled by this profile.
        """

        return self.tool(
            name
        ).enabled

    def options(
        self,
        name: str,
    ) -> dict[str, Any]:
        """
        Return a copy of the configured options for a tool.
        """

        return deepcopy(
            self.tool(
                name
            ).options
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a serializable profile representation.
        """

        return {
            "name": self.name,
            "description": self.description,
            "tools": {
                name: configuration.as_dict()
                for name, configuration
                in self.tools.items()
            },
            "global_options": deepcopy(
                self.global_options
            ),
        }


###############################################################################
# Resolved ScopeForgeX Configuration
###############################################################################


@dataclass(slots=True)
class ScopeForgeXConfig:
    """
    Complete resolved ScopeForgeX assessment configuration.

    This is the configuration boundary between the CLI/configuration layer
    and the workflow engine.
    """

    profile: AssessmentProfile

    target: str = ""

    target_type: str = ""

    scope_restrictions: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    authorization: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    allowed_tools: tuple[
        str,
        ...,
    ] = CORE_TOOLS

    excluded_tools: tuple[
        str,
        ...,
    ] = ()

    tools: dict[
        str,
        ToolConfiguration,
    ] = field(
        default_factory=dict
    )

    rate_limits: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    authentication: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    global_options: dict[
        str,
        Any,
    ] = field(
        default_factory=dict
    )

    def get_tool(
        self,
        name: str,
    ) -> ToolConfiguration:
        """
        Return the resolved configuration for one tool.
        """

        normalized = normalize_tool_name(
            name
        )

        if normalized not in CORE_TOOL_SET:
            raise ConfigurationError(
                f"Tool is not part of the ScopeForgeX core toolset: "
                f"{name!r}"
            )

        if normalized in self.tools:
            return self.tools[
                normalized
            ]

        return self.profile.tool(
            normalized
        )

    def is_tool_allowed(
        self,
        name: str,
    ) -> bool:
        """
        Return whether the tool is allowed by the resolved assessment scope.
        """

        normalized = normalize_tool_name(
            name
        )

        if normalized not in CORE_TOOL_SET:
            return False

        if normalized in self.excluded_tools:
            return False

        if normalized not in self.allowed_tools:
            return False

        return True

    def is_tool_enabled(
        self,
        name: str,
    ) -> bool:
        """
        Return whether a tool is both allowed and enabled.
        """

        normalized = normalize_tool_name(
            name
        )

        if not self.is_tool_allowed(
            normalized
        ):
            return False

        return self.get_tool(
            normalized
        ).enabled

    def tool_options(
        self,
        name: str,
    ) -> dict[str, Any]:
        """
        Return resolved options for one tool.
        """

        return deepcopy(
            self.get_tool(
                name
            ).options
        )

    def enabled_tools(
        self,
    ) -> tuple[str, ...]:
        """
        Return enabled tools in canonical tool order.
        """

        return tuple(
            name
            for name in CORE_TOOLS
            if self.is_tool_enabled(
                name
            )
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a serializable configuration representation.
        """

        return {
            "profile": self.profile.as_dict(),
            "target": self.target,
            "target_type": self.target_type,
            "scope_restrictions": deepcopy(
                self.scope_restrictions
            ),
            "authorization": deepcopy(
                self.authorization
            ),
            "allowed_tools": list(
                self.allowed_tools
            ),
            "excluded_tools": list(
                self.excluded_tools
            ),
            "tools": {
                name: configuration.as_dict()
                for name, configuration
                in self.tools.items()
            },
            "rate_limits": deepcopy(
                self.rate_limits
            ),
            "authentication": deepcopy(
                self.authentication
            ),
            "global_options": deepcopy(
                self.global_options
            ),
        }


###############################################################################
# Normalization Helpers
###############################################################################


def normalize_tool_name(
    name: str,
) -> str:
    """
    Normalize and validate a tool name.
    """

    normalized = str(
        name
    ).strip().lower()

    if not normalized:
        raise ConfigurationError(
            "Tool name cannot be empty."
        )

    return normalized


def normalize_tool_names(
    names: Mapping[str, Any] | list[str] | tuple[str, ...] | set[str],
) -> tuple[str, ...]:
    """
    Normalize a collection of tool names.

    Duplicate names are removed while preserving the original order.
    """

    result: list[str] = []

    for name in names:
        normalized = normalize_tool_name(
            name
        )

        if normalized not in CORE_TOOL_SET:
            raise ConfigurationError(
                f"Tool is not part of the ScopeForgeX core toolset: "
                f"{name!r}"
            )

        if normalized not in result:
            result.append(
                normalized
            )

    return tuple(
        result
    )


###############################################################################
# Tool Configuration Constructor
###############################################################################


def _tool(
    *,
    enabled: bool = True,
    options: Mapping[str, Any] | None = None,
    requires_confirmation: bool = False,
    safe: bool = True,
) -> ToolConfiguration:
    """
    Construct a tool configuration.
    """

    return ToolConfiguration(
        enabled=enabled,
        options=dict(
            options or {}
        ),
        requires_confirmation=(
            requires_confirmation
        ),
        safe=safe,
    )


###############################################################################
# FAST Profile
###############################################################################


def build_fast_profile() -> AssessmentProfile:
    """
    Build the FAST profile.

    FAST provides:

    - Quick attack-surface discovery
    - Low request volume
    - Minimal high-value checks
    - Critical/high vulnerability detection

    Specialized validation and credential assessment remain disabled by
    default. They may be explicitly enabled through tool overrides when
    relevant to the discovered attack surface.
    """

    return AssessmentProfile(
        name=PROFILE_FAST,
        description=(
            "Minimal high-value assessment with low request volume."
        ),
        tools={
            "amass": _tool(
                options={
                    "passive": True,
                    "active": False,
                }
            ),
            "subhunt": _tool(
                options={
                    "threads": 10,
                }
            ),
            "nmap": _tool(
                options={
                    "ports": "default",
                    "service_detection": True,
                    "os_detection": False,
                    "timing": "T3",
                    "nse_profile": "safe",
                }
            ),
            "dig": _tool(
                options={
                    "record_types": (
                        "A",
                        "AAAA",
                        "CNAME",
                        "MX",
                        "NS",
                        "TXT",
                        "SOA",
                    ),
                }
            ),
            "httpx": _tool(
                options={
                    "status_code": True,
                    "title": True,
                    "server": True,
                    "technology": True,
                }
            ),
            "katana": _tool(
                options={
                    "depth": 2,
                }
            ),
            "ffuf": _tool(
                enabled=False,
            ),
            "whatweb": _tool(
                enabled=True,
            ),
            "kiterunner": _tool(
                enabled=False,
            ),
            "jsluice": _tool(
                enabled=False,
            ),
            "nuclei": _tool(
                options={
                    "severity": (
                        "critical",
                        "high",
                    ),
                }
            ),
            "nikto": _tool(
                enabled=False,
            ),
            "testssl.sh": _tool(
                enabled=False,
            ),
            "sqlmap": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "dalfox": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "jwt_tool": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "sstimap": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "hydra": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "hashcat": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
        },
        global_options={
            "request_rate_limit": 10,
            "timeout": 300,
        },
    )


###############################################################################
# STANDARD Profile
###############################################################################


def build_standard_profile() -> AssessmentProfile:
    """
    Build the STANDARD profile.

    STANDARD provides normal professional assessment coverage:

    - Full reconnaissance
    - Full enumeration
    - Broad vulnerability assessment
    - TLS assessment

    Specialized validation tools remain disabled by default because they are
    selected based on discovered attack surface rather than blindly executed
    against every target.

    Credential assessment also remains disabled by default.
    """

    return AssessmentProfile(
        name=PROFILE_STANDARD,
        description=(
            "Normal professional assessment with full enumeration, "
            "vulnerability assessment and relevant validation support."
        ),
        tools={
            "amass": _tool(
                options={
                    "passive": True,
                    "active": True,
                }
            ),
            "subhunt": _tool(
                options={
                    "threads": 25,
                }
            ),
            "nmap": _tool(
                options={
                    "ports": "default",
                    "service_detection": True,
                    "os_detection": False,
                    "timing": "T3",
                    "nse_profile": "safe",
                }
            ),
            "dig": _tool(
                options={
                    "record_types": (
                        "A",
                        "AAAA",
                        "CNAME",
                        "MX",
                        "NS",
                        "TXT",
                        "SOA",
                    ),
                }
            ),
            "httpx": _tool(
                options={
                    "status_code": True,
                    "title": True,
                    "server": True,
                    "technology": True,
                }
            ),
            "katana": _tool(
                options={
                    "depth": 3,
                }
            ),
            "ffuf": _tool(
                enabled=True,
            ),
            "whatweb": _tool(
                enabled=True,
            ),
            "kiterunner": _tool(
                enabled=True,
            ),
            "jsluice": _tool(
                enabled=True,
            ),
            "nuclei": _tool(
                options={
                    "severity": (
                        "critical",
                        "high",
                        "medium",
                    ),
                }
            ),
            "nikto": _tool(
                enabled=True,
            ),
            "testssl.sh": _tool(
                enabled=True,
            ),
            "sqlmap": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "dalfox": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "jwt_tool": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "sstimap": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "hydra": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "hashcat": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
        },
        global_options={
            "request_rate_limit": 25,
            "timeout": 600,
        },
    )


###############################################################################
# FULL Profile
###############################################################################


def build_full_profile() -> AssessmentProfile:
    """
    Build the FULL profile.

    FULL provides maximum configured coverage:

    - Extended reconnaissance
    - Extended enumeration
    - Critical/high/medium/low vulnerability checks
    - Relevant informational vulnerability checks
    - Target-dependent validation support

    Specialized tools remain disabled until the relevant attack surface is
    identified and the user explicitly selects them.

    Credential assessment remains opt-in.
    """

    return AssessmentProfile(
        name=PROFILE_FULL,
        description=(
            "Maximum configured coverage with extended enumeration, "
            "lower-severity checks and target-dependent validation."
        ),
        tools={
            "amass": _tool(
                options={
                    "passive": True,
                    "active": True,
                    "bruteforce": True,
                }
            ),
            "subhunt": _tool(
                options={
                    "threads": 50,
                }
            ),
            "nmap": _tool(
                options={
                    "ports": "default",
                    "service_detection": True,
                    "os_detection": True,
                    "timing": "T4",
                    "nse_profile": "default",
                }
            ),
            "dig": _tool(
                options={
                    "record_types": (
                        "A",
                        "AAAA",
                        "CNAME",
                        "MX",
                        "NS",
                        "TXT",
                        "SOA",
                    ),
                }
            ),
            "httpx": _tool(
                options={
                    "status_code": True,
                    "title": True,
                    "server": True,
                    "technology": True,
                }
            ),
            "katana": _tool(
                options={
                    "depth": 5,
                }
            ),
            "ffuf": _tool(
                enabled=True,
            ),
            "whatweb": _tool(
                enabled=True,
            ),
            "kiterunner": _tool(
                enabled=True,
            ),
            "jsluice": _tool(
                enabled=True,
            ),
            "nuclei": _tool(
                options={
                    "severity": (
                        "critical",
                        "high",
                        "medium",
                        "low",
                        "info",
                    ),
                }
            ),
            "nikto": _tool(
                enabled=True,
            ),
            "testssl.sh": _tool(
                enabled=True,
            ),
            "sqlmap": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "dalfox": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "jwt_tool": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "sstimap": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "hydra": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
            "hashcat": _tool(
                enabled=False,
                requires_confirmation=True,
                safe=False,
            ),
        },
        global_options={
            "request_rate_limit": 50,
            "timeout": 1200,
        },
    )


###############################################################################
# Profile Registry
###############################################################################


def build_profiles() -> dict[
    str,
    AssessmentProfile,
]:
    """
    Build all supported assessment profiles.
    """

    return {
        PROFILE_FAST: build_fast_profile(),
        PROFILE_STANDARD: build_standard_profile(),
        PROFILE_FULL: build_full_profile(),
    }


def get_profile(
    name: str,
) -> AssessmentProfile:
    """
    Return an assessment profile by name.
    """

    normalized = str(
        name
    ).strip().lower()

    profiles = build_profiles()

    try:
        return profiles[
            normalized
        ]

    except KeyError as exc:
        supported = ", ".join(
            SUPPORTED_PROFILES
        )

        raise ConfigurationError(
            f"Unknown assessment profile: {name!r}. "
            f"Supported profiles: {supported}."
        ) from exc


###############################################################################
# Tool Configuration Resolution
###############################################################################


def merge_tool_options(
    base: Mapping[str, Any],
    override: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Merge profile options with explicit user options.

    User-provided values override profile defaults.

    The merge is intentionally shallow because option semantics belong to the
    individual tool adapter.
    """

    merged = dict(
        base
    )

    if override:
        merged.update(
            override
        )

    return merged


def resolve_tool_configuration(
    profile: AssessmentProfile,
    tool_name: str,
    *,
    enabled: bool | None = None,
    options: Mapping[str, Any] | None = None,
) -> ToolConfiguration:
    """
    Resolve one tool configuration.

    The profile supplies the defaults. Explicit enablement and options are
    applied afterward.
    """

    normalized = normalize_tool_name(
        tool_name
    )

    if normalized not in CORE_TOOL_SET:
        raise ConfigurationError(
            f"Tool is not part of the ScopeForgeX core toolset: "
            f"{tool_name!r}"
        )

    base = profile.tool(
        normalized
    )

    return ToolConfiguration(
        enabled=(
            base.enabled
            if enabled is None
            else bool(enabled)
        ),
        options=merge_tool_options(
            base.options,
            options,
        ),
        requires_confirmation=(
            base.requires_confirmation
        ),
        safe=base.safe,
    )


###############################################################################
# Assessment Configuration Builder
###############################################################################


def build_config(
    profile: str = PROFILE_STANDARD,
    *,
    target: str = "",
    target_type: str = "",
    scope_restrictions: Mapping[
        str,
        Any,
    ] | None = None,
    authorization: Mapping[
        str,
        Any,
    ] | None = None,
    allowed_tools: (
        tuple[str, ...]
        | list[str]
        | set[str]
        | None
    ) = None,
    excluded_tools: (
        tuple[str, ...]
        | list[str]
        | set[str]
        | None
    ) = None,
    tool_overrides: Mapping[
        str,
        Mapping[str, Any],
    ] | None = None,
    tool_enablement: Mapping[
        str,
        bool,
    ] | None = None,
    rate_limits: Mapping[
        str,
        Any,
    ] | None = None,
    authentication: Mapping[
        str,
        Any,
    ] | None = None,
    global_options: Mapping[
        str,
        Any,
    ] | None = None,
) -> ScopeForgeXConfig:
    """
    Build a complete resolved ScopeForgeX configuration.

    Args:
        profile:
            Assessment profile.

        target:
            Assessment target.

        target_type:
            Target classification.

        scope_restrictions:
            Scope restrictions such as included/excluded hosts, domains,
            ports or paths.

        authorization:
            Authorization metadata establishing that the assessment is
            permitted.

        allowed_tools:
            Explicitly allowed tools for this assessment.

        excluded_tools:
            Explicitly excluded tools.

        tool_overrides:
            Per-tool option overrides.

        tool_enablement:
            Explicit per-tool enable/disable overrides.

        rate_limits:
            Assessment and tool rate-limit configuration.

        authentication:
            Authentication information required by the assessment.

        global_options:
            Global execution options.

    Returns:
        A validated resolved ScopeForgeXConfig.
    """

    selected_profile = get_profile(
        profile
    )

    explicit_allowed = (
        CORE_TOOLS
        if allowed_tools is None
        else normalize_tool_names(
            allowed_tools
        )
    )

    explicit_excluded = (
        ()
        if excluded_tools is None
        else normalize_tool_names(
            excluded_tools
        )
    )

    allowed_set = set(
        explicit_allowed
    )

    excluded_set = set(
        explicit_excluded
    )

    if allowed_set.intersection(
        excluded_set
    ):
        overlap = sorted(
            allowed_set.intersection(
                excluded_set
            )
        )

        raise ConfigurationError(
            "A tool cannot be both allowed and excluded: "
            + ", ".join(overlap)
        )

    overrides = (
        tool_overrides or {}
    )

    enablement = (
        tool_enablement or {}
    )

    resolved_tools: dict[
        str,
        ToolConfiguration,
    ] = {}

    for tool_name in CORE_TOOLS:

        option_override = overrides.get(
            tool_name,
            {},
        )

        explicit_enabled = enablement.get(
            tool_name
        )

        configuration = (
            resolve_tool_configuration(
                selected_profile,
                tool_name,
                enabled=explicit_enabled,
                options=option_override,
            )
        )

        if tool_name not in allowed_set:
            configuration.enabled = False

        if tool_name in excluded_set:
            configuration.enabled = False

        resolved_tools[
            tool_name
        ] = configuration

    for name in overrides:
        normalized = normalize_tool_name(
            name
        )

        if normalized not in CORE_TOOL_SET:
            raise ConfigurationError(
                f"Tool override references a tool outside the "
                f"ScopeForgeX core toolset: {name!r}"
            )

    for name in enablement:
        normalized = normalize_tool_name(
            name
        )

        if normalized not in CORE_TOOL_SET:
            raise ConfigurationError(
                f"Tool enablement references a tool outside the "
                f"ScopeForgeX core toolset: {name!r}"
            )

    resolved_rate_limits = {
        "request_rate_limit": (
            selected_profile.global_options.get(
                "request_rate_limit"
            )
        ),
    }

    if rate_limits:
        resolved_rate_limits.update(
            deepcopy(
                dict(rate_limits)
            )
        )

    resolved_global_options = deepcopy(
        selected_profile.global_options
    )

    if global_options:
        resolved_global_options.update(
            deepcopy(
                dict(global_options)
            )
        )

    configuration = ScopeForgeXConfig(
        profile=selected_profile,
        target=str(target).strip(),
        target_type=str(
            target_type
        ).strip(),
        scope_restrictions=deepcopy(
            dict(
                scope_restrictions or {}
            )
        ),
        authorization=deepcopy(
            dict(
                authorization or {}
            )
        ),
        allowed_tools=tuple(
            explicit_allowed
        ),
        excluded_tools=tuple(
            explicit_excluded
        ),
        tools=resolved_tools,
        rate_limits=resolved_rate_limits,
        authentication=deepcopy(
            dict(
                authentication or {}
            )
        ),
        global_options=resolved_global_options,
    )

    validate_config(
        configuration
    )

    return configuration


###############################################################################
# Configuration Validation
###############################################################################


def validate_config(
    config: ScopeForgeXConfig,
) -> None:
    """
    Validate a resolved ScopeForgeX configuration.

    Validation occurs before workflow execution.
    """

    profile_name = str(
        config.profile.name
    ).strip().lower()

    if profile_name not in SUPPORTED_PROFILES:
        raise ConfigurationError(
            f"Unsupported assessment profile: "
            f"{config.profile.name!r}"
        )

    if not config.target:
        raise ConfigurationError(
            "Assessment target is required."
        )

    if not config.target_type:
        raise ConfigurationError(
            "Assessment target type is required."
        )

    allowed = set(
        config.allowed_tools
    )

    excluded = set(
        config.excluded_tools
    )

    if not allowed.issubset(
        CORE_TOOL_SET
    ):
        invalid = sorted(
            allowed.difference(
                CORE_TOOL_SET
            )
        )

        raise ConfigurationError(
            "Allowed tools contain tools outside the final core toolset: "
            + ", ".join(invalid)
        )

    if not excluded.issubset(
        CORE_TOOL_SET
    ):
        invalid = sorted(
            excluded.difference(
                CORE_TOOL_SET
            )
        )

        raise ConfigurationError(
            "Excluded tools contain tools outside the final core toolset: "
            + ", ".join(invalid)
        )

    overlap = allowed.intersection(
        excluded
    )

    if overlap:
        raise ConfigurationError(
            "A tool cannot be both allowed and excluded: "
            + ", ".join(
                sorted(overlap)
            )
        )

    if set(
        config.tools
    ) != CORE_TOOL_SET:
        missing = sorted(
            CORE_TOOL_SET.difference(
                config.tools
            )
        )

        extra = sorted(
            set(config.tools).difference(
                CORE_TOOL_SET
            )
        )

        message = (
            "Resolved tool configuration must contain exactly "
            "the final ScopeForgeX core toolset."
        )

        if missing:
            message += (
                f" Missing: {', '.join(missing)}."
            )

        if extra:
            message += (
                f" Extra: {', '.join(extra)}."
            )

        raise ConfigurationError(
            message
        )

    for name, tool in config.tools.items():

        if name not in CORE_TOOL_SET:
            raise ConfigurationError(
                f"Unknown ScopeForgeX tool: {name!r}"
            )

        if not isinstance(
            tool.enabled,
            bool,
        ):
            raise ConfigurationError(
                f"Invalid enabled value for tool {name!r}."
            )

        if not isinstance(
            tool.options,
            dict,
        ):
            raise ConfigurationError(
                f"Invalid options for tool {name!r}."
            )

        if not isinstance(
            tool.requires_confirmation,
            bool,
        ):
            raise ConfigurationError(
                f"Invalid confirmation setting for tool {name!r}."
            )

        if not isinstance(
            tool.safe,
            bool,
        ):
            raise ConfigurationError(
                f"Invalid safety setting for tool {name!r}."
            )

        if (
            tool.requires_confirmation
            and tool.safe
        ):
            raise ConfigurationError(
                f"Tool {name!r} cannot simultaneously require "
                "confirmation and be marked safe."
            )

        if (
            tool.enabled
            and not config.is_tool_allowed(
                name
            )
        ):
            raise ConfigurationError(
                f"Tool {name!r} is enabled but is not allowed "
                "by the assessment configuration."
            )

    for value_name, value in (
        config.rate_limits.items()
    ):
        if value is None:
            continue

        if isinstance(
            value,
            bool,
        ):
            raise ConfigurationError(
                f"Rate limit {value_name!r} must be numeric."
            )

        if not isinstance(
            value,
            (int, float),
        ):
            raise ConfigurationError(
                f"Rate limit {value_name!r} must be numeric."
            )

        if value <= 0:
            raise ConfigurationError(
                f"Rate limit {value_name!r} must be greater than zero."
            )


###############################################################################
# Default Configuration
###############################################################################


def get_default_configuration() -> ScopeForgeXConfig:
    """
    Return the default STANDARD configuration.

    A target must be supplied before execution. Therefore this helper builds
    the configuration with an empty target only for inspection and is not
    suitable for workflow execution until a target is provided.
    """

    profile = get_profile(
        PROFILE_STANDARD
    )

    tools = {
        name: deepcopy(
            configuration
        )
        for name, configuration
        in profile.tools.items()
    }

    return ScopeForgeXConfig(
        profile=profile,
        target="",
        target_type="",
        scope_restrictions={},
        authorization={},
        allowed_tools=CORE_TOOLS,
        excluded_tools=(),
        tools=tools,
        rate_limits={
            "request_rate_limit": profile.global_options.get(
                "request_rate_limit"
            ),
        },
        authentication={},
        global_options=deepcopy(
            profile.global_options
        ),
    )


###############################################################################
# Public API
###############################################################################


__all__ = [
    # Profiles
    "PROFILE_FAST",
    "PROFILE_STANDARD",
    "PROFILE_FULL",
    "SUPPORTED_PROFILES",

    # Tool groups
    "RECONNAISSANCE_TOOLS",
    "ENUMERATION_TOOLS",
    "VULNERABILITY_ASSESSMENT_TOOLS",
    "VULNERABILITY_VALIDATION_TOOLS",
    "CREDENTIAL_ASSESSMENT_TOOLS",
    "CORE_TOOLS",
    "CORE_TOOL_SET",

    # Phases
    "PHASE_RECONNAISSANCE",
    "PHASE_ENUMERATION",
    "PHASE_VULNERABILITY_ASSESSMENT",
    "PHASE_VULNERABILITY_VALIDATION",
    "PHASE_CREDENTIAL_ASSESSMENT",

    # Exceptions
    "ConfigurationError",

    # Models
    "ToolConfiguration",
    "AssessmentProfile",
    "ScopeForgeXConfig",

    # Helpers
    "normalize_tool_name",
    "normalize_tool_names",

    # Profiles
    "build_fast_profile",
    "build_standard_profile",
    "build_full_profile",
    "build_profiles",
    "get_profile",

    # Resolution
    "merge_tool_options",
    "resolve_tool_configuration",
    "build_config",

    # Validation
    "validate_config",

    # Defaults
    "get_default_configuration",
]

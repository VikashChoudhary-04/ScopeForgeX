"""
ScopeForgeX Configuration Package
=================================

Canonical configuration interfaces for ScopeForgeX.

The configuration layer defines:

- Assessment profiles
- Per-tool configuration
- Profile defaults
- User overrides
- Configuration validation
- Configuration merging

Configuration is intentionally independent from:

- CLI/UI
- Workflow execution
- Tool command construction
- Reporting

The workflow consumes resolved configuration. Tool adapters consume only
their own resolved options.

Final architecture principle:

    Profile
        ↓
    Tool Configuration
        ↓
    Resolved Execution Context
        ↓
    Tool Adapter
        ↓
    Command

Supported assessment profiles:

- FAST
- STANDARD
- FULL

v1.3.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any, Mapping


###############################################################################
# Constants
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
    Resolved configuration for one ScopeForgeX tool.

    Attributes:
        enabled:
            Whether the tool may execute.

        options:
            Tool-specific options passed to the tool adapter.

        requires_confirmation:
            Whether execution requires explicit user confirmation.

        safe:
            Whether the selected configuration is considered safe for the
            active assessment profile.
    """

    enabled: bool = True

    options: dict[str, Any] = field(
        default_factory=dict
    )

    requires_confirmation: bool = False

    safe: bool = True

    def as_dict(self) -> dict[str, Any]:
        """
        Return a serializable representation.
        """

        return {
            "enabled": self.enabled,
            "options": dict(self.options),
            "requires_confirmation": self.requires_confirmation,
            "safe": self.safe,
        }


###############################################################################
# Assessment Profile
###############################################################################


@dataclass(slots=True)
class AssessmentProfile:
    """
    Configuration for one assessment profile.

    A profile determines defaults and enabled capabilities. It does not
    prevent individual tool or option overrides.
    """

    name: str

    description: str = ""

    tools: dict[str, ToolConfiguration] = field(
        default_factory=dict
    )

    global_options: dict[str, Any] = field(
        default_factory=dict
    )

    def tool(
        self,
        name: str,
    ) -> ToolConfiguration:
        """
        Return configuration for a specific tool.

        Unknown tools receive a default configuration so that the profile
        remains extensible.
        """

        normalized = str(name).strip().lower()

        if not normalized:
            raise ConfigurationError(
                "Tool name cannot be empty."
            )

        return self.tools.get(
            normalized,
            ToolConfiguration(),
        )

    def as_dict(self) -> dict[str, Any]:
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
            "global_options": dict(
                self.global_options
            ),
        }


###############################################################################
# Configuration
###############################################################################


@dataclass(slots=True)
class ScopeForgeXConfig:
    """
    Complete resolved ScopeForgeX configuration.

    This object is the configuration boundary between the CLI/configuration
    layer and the workflow engine.
    """

    profile: AssessmentProfile

    target: str = ""

    target_type: str = ""

    scope: dict[str, Any] = field(
        default_factory=dict
    )

    tools: dict[str, ToolConfiguration] = field(
        default_factory=dict
    )

    global_options: dict[str, Any] = field(
        default_factory=dict
    )

    def get_tool(
        self,
        name: str,
    ) -> ToolConfiguration:
        """
        Return the resolved configuration for one tool.
        """

        normalized = str(name).strip().lower()

        if not normalized:
            raise ConfigurationError(
                "Tool name cannot be empty."
            )

        if normalized in self.tools:
            return self.tools[normalized]

        return self.profile.tool(
            normalized
        )

    def is_tool_enabled(
        self,
        name: str,
    ) -> bool:
        """
        Return whether a tool is enabled.
        """

        return self.get_tool(
            name
        ).enabled

    def tool_options(
        self,
        name: str,
    ) -> dict[str, Any]:
        """
        Return resolved options for one tool.
        """

        return dict(
            self.get_tool(
                name
            ).options
        )

    def as_dict(self) -> dict[str, Any]:
        """
        Return a serializable configuration representation.
        """

        return {
            "profile": self.profile.as_dict(),
            "target": self.target,
            "target_type": self.target_type,
            "scope": dict(self.scope),
            "tools": {
                name: configuration.as_dict()
                for name, configuration
                in self.tools.items()
            },
            "global_options": dict(
                self.global_options
            ),
        }


###############################################################################
# Profile Constructors
###############################################################################


def _tool(
    *,
    enabled: bool = True,
    options: Mapping[str, Any] | None = None,
    requires_confirmation: bool = False,
    safe: bool = True,
) -> ToolConfiguration:
    """
    Internal helper for constructing tool configuration.
    """

    return ToolConfiguration(
        enabled=enabled,
        options=dict(
            options or {}
        ),
        requires_confirmation=requires_confirmation,
        safe=safe,
    )


def build_fast_profile() -> AssessmentProfile:
    """
    Build the FAST assessment profile.

    FAST is intended to provide minimal, high-value coverage with low request
    volume and short execution time.

    Default vulnerability severity:

        critical, high
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
                }
            ),
            "subhunt": _tool(
                options={
                    "threads": 50,
                }
            ),
            "nmap": _tool(
                options={
                    "service_detection": True,
                    "os_detection": False,
                    "timing": "T3",
                    "nse_profile": "safe",
                }
            ),
            "dig": _tool(),
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
            "whatweb": _tool(),
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
                    "rate_limit": 30,
                    "timeout": 5,
                    "retries": 1,
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
            "request_rate_limit": 30,
            "timeout": 600,
        },
    )


def build_standard_profile() -> AssessmentProfile:
    """
    Build the STANDARD assessment profile.

    STANDARD represents normal professional assessment coverage while
    retaining conservative defaults for potentially intrusive validation.
    """

    return AssessmentProfile(
        name=PROFILE_STANDARD,
        description=(
            "Normal professional assessment with full enumeration and "
            "broad vulnerability assessment."
        ),
        tools={
            "amass": _tool(
                options={
                    "passive": True,
                }
            ),
            "subhunt": _tool(
                options={
                    "threads": 50,
                }
            ),
            "nmap": _tool(
                options={
                    "service_detection": True,
                    "os_detection": False,
                    "timing": "T3",
                    "nse_profile": "safe",
                }
            ),
            "dig": _tool(),
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
            "ffuf": _tool(),
            "whatweb": _tool(),
            "kiterunner": _tool(),
            "jsluice": _tool(),
            "nuclei": _tool(
                options={
                    "severity": (
                        "critical",
                        "high",
                        "medium",
                        "low",
                    ),
                    "rate_limit": 30,
                    "timeout": 5,
                    "retries": 1,
                }
            ),
            "nikto": _tool(),
            "testssl.sh": _tool(),
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
            "request_rate_limit": 60,
            "timeout": 900,
        },
    )


def build_full_profile() -> AssessmentProfile:
    """
    Build the FULL assessment profile.

    FULL enables maximum configured coverage. Potentially intrusive or
    validation-oriented tools remain confirmation-gated.
    """

    profile = build_standard_profile()

    profile.name = PROFILE_FULL

    profile.description = (
        "Maximum configured assessment coverage with extended enumeration "
        "and target-dependent validation."
    )

    profile.global_options.update(
        {
            "request_rate_limit": 100,
            "timeout": 1800,
        }
    )

    return profile


###############################################################################
# Profile Registry
###############################################################################


def build_profiles() -> dict[str, AssessmentProfile]:
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

    normalized = str(name).strip().lower()

    profiles = build_profiles()

    try:
        return profiles[normalized]
    except KeyError as exc:
        supported = ", ".join(
            SUPPORTED_PROFILES
        )

        raise ConfigurationError(
            f"Unknown assessment profile: {name!r}. "
            f"Supported profiles: {supported}."
        ) from exc


###############################################################################
# Configuration Resolution
###############################################################################


def merge_tool_options(
    base: Mapping[str, Any],
    override: Mapping[str, Any] | None,
) -> dict[str, Any]:
    """
    Merge tool options.

    User-provided values override profile defaults.

    The merge is intentionally shallow because tool options are owned by the
    individual adapter and may have tool-specific semantics.
    """

    merged = dict(base)

    if override:
        merged.update(
            override
        )

    return merged


def resolve_tool_configuration(
    profile: AssessmentProfile,
    tool_name: str,
    override: Mapping[str, Any] | None = None,
) -> ToolConfiguration:
    """
    Resolve one tool's configuration from a profile and optional override.
    """

    normalized = str(
        tool_name
    ).strip().lower()

    if not normalized:
        raise ConfigurationError(
            "Tool name cannot be empty."
        )

    base = profile.tool(
        normalized
    )

    return ToolConfiguration(
        enabled=base.enabled,
        options=merge_tool_options(
            base.options,
            override,
        ),
        requires_confirmation=base.requires_confirmation,
        safe=base.safe,
    )


def build_config(
    profile: str = PROFILE_STANDARD,
    *,
    target: str = "",
    target_type: str = "",
    scope: Mapping[str, Any] | None = None,
    tool_overrides: Mapping[
        str,
        Mapping[str, Any],
    ] | None = None,
    global_options: Mapping[str, Any] | None = None,
) -> ScopeForgeXConfig:
    """
    Build a complete resolved ScopeForgeX configuration.

    Args:
        profile:
            Assessment profile name.

        target:
            Assessment target.

        target_type:
            Target classification.

        scope:
            Scope restrictions and authorization metadata.

        tool_overrides:
            Per-tool option overrides.

        global_options:
            Global execution overrides.
    """

    selected_profile = get_profile(
        profile
    )

    overrides = (
        tool_overrides or {}
    )

    resolved_tools: dict[
        str,
        ToolConfiguration,
    ] = {}

    for name, configuration in (
        selected_profile.tools.items()
    ):
        override = overrides.get(
            name,
            {},
        )

        resolved_tools[name] = (
            resolve_tool_configuration(
                selected_profile,
                name,
                override,
            )
        )

    for name, override in overrides.items():
        normalized = str(
            name
        ).strip().lower()

        if normalized not in resolved_tools:
            resolved_tools[normalized] = (
                resolve_tool_configuration(
                    selected_profile,
                    normalized,
                    override,
                )
            )

    resolved_global_options = dict(
        selected_profile.global_options
    )

    if global_options:
        resolved_global_options.update(
            global_options
        )

    configuration = ScopeForgeXConfig(
        profile=selected_profile,
        target=target,
        target_type=target_type,
        scope=dict(
            scope or {}
        ),
        tools=resolved_tools,
        global_options=resolved_global_options,
    )

    validate_config(
        configuration
    )

    return configuration


###############################################################################
# Validation
###############################################################################


def validate_config(
    config: ScopeForgeXConfig,
) -> None:
    """
    Validate a resolved ScopeForgeX configuration.

    Raises:
        ConfigurationError:
            When configuration violates the configuration contract.
    """

    profile_name = config.profile.name.lower()

    if profile_name not in SUPPORTED_PROFILES:
        raise ConfigurationError(
            f"Unsupported profile: {config.profile.name!r}"
        )

    for name, tool in config.tools.items():

        if not str(name).strip():
            raise ConfigurationError(
                "Tool configuration contains an empty tool name."
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

        if (
            tool.requires_confirmation
            and tool.safe
        ):
            raise ConfigurationError(
                f"Tool {name!r} cannot simultaneously require "
                "confirmation and be marked safe."
            )


###############################################################################
# Public API
###############################################################################


__all__ = [
    "PROFILE_FAST",
    "PROFILE_STANDARD",
    "PROFILE_FULL",
    "SUPPORTED_PROFILES",
    "ConfigurationError",
    "ToolConfiguration",
    "AssessmentProfile",
    "ScopeForgeXConfig",
    "build_fast_profile",
    "build_standard_profile",
    "build_full_profile",
    "build_profiles",
    "get_profile",
    "merge_tool_options",
    "resolve_tool_configuration",
    "build_config",
    "validate_config",
]

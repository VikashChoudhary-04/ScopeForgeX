"""
ScopeForgeX Configuration System
================================

Canonical configuration model for ScopeForgeX assessment execution.

The configuration system defines:

- FAST assessment profile
- STANDARD assessment profile
- FULL assessment profile
- Per-tool enablement
- Per-tool options
- Global execution settings
- Safe defaults
- Configuration validation

Design Principles
-----------------
- Profiles define defaults, not hard limits.
- Individual tool settings can override profile defaults.
- Tool-specific command construction remains inside tool adapters.
- The workflow engine consumes configuration but does not construct commands.
- Configuration is independent of CLI/UI.
- Configuration values are validated before execution.

Assessment Profiles
-------------------
FAST
    Minimal high-value assessment with low request volume.

STANDARD
    Normal professional assessment coverage.

FULL
    Maximum configured coverage, including lower-severity checks.

v1.2.0
"""

from __future__ import annotations

from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Mapping

import yaml


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
class ToolConfig:
    """
    Configuration for one assessment tool.
    """

    enabled: bool = True

    options: dict[str, Any] = field(
        default_factory=dict
    )

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize tool configuration.
        """

        return {
            "enabled": self.enabled,
            "options": dict(
                self.options
            ),
        }


###############################################################################
# Profile Configuration
###############################################################################


@dataclass(slots=True)
class ProfileConfig:
    """
    Configuration for one ScopeForgeX assessment profile.
    """

    name: str

    description: str

    tools: dict[str, ToolConfig] = field(
        default_factory=dict
    )

    settings: dict[str, Any] = field(
        default_factory=dict
    )

    def is_tool_enabled(
        self,
        tool_name: str,
    ) -> bool:
        """
        Return whether a tool is enabled in this profile.
        """

        config = self.tools.get(
            tool_name.strip().lower()
        )

        if config is None:
            return False

        return config.enabled

    def get_tool_options(
        self,
        tool_name: str,
    ) -> dict[str, Any]:
        """
        Return a copy of a tool's configured options.
        """

        config = self.tools.get(
            tool_name.strip().lower()
        )

        if config is None:
            return {}

        return dict(
            config.options
        )

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize profile configuration.
        """

        return {
            "name": self.name,
            "description": self.description,
            "tools": {
                name: config.as_dict()
                for name, config in self.tools.items()
            },
            "settings": dict(
                self.settings
            ),
        }


###############################################################################
# Global Configuration
###############################################################################


@dataclass(slots=True)
class ScopeForgeXConfig:
    """
    Complete ScopeForgeX execution configuration.
    """

    default_profile: str = PROFILE_STANDARD

    output_base_dir: Path = Path(
        "outputs"
    )

    request_rate_limit: int | None = None

    command_timeout: int = 600

    continue_on_error: bool = True

    require_confirmation_for_aggressive: bool = True

    profiles: dict[str, ProfileConfig] = field(
        default_factory=dict
    )

    def get_profile(
        self,
        name: str | None = None,
    ) -> ProfileConfig:
        """
        Return the requested profile.

        If no name is supplied, the configured default profile is returned.
        """

        profile_name = (
            name
            or self.default_profile
        ).strip().lower()

        try:
            return self.profiles[
                profile_name
            ]

        except KeyError as exc:
            raise ConfigurationError(
                f"Unknown ScopeForgeX profile: {profile_name}"
            ) from exc

    def get_tool_config(
        self,
        tool_name: str,
        profile_name: str | None = None,
    ) -> ToolConfig:
        """
        Return a tool configuration from a profile.

        Unknown tools are disabled by default.
        """

        profile = self.get_profile(
            profile_name
        )

        normalized = (
            tool_name.strip().lower()
        )

        return profile.tools.get(
            normalized,
            ToolConfig(
                enabled=False
            ),
        )

    def is_tool_enabled(
        self,
        tool_name: str,
        profile_name: str | None = None,
    ) -> bool:
        """
        Return whether a tool is enabled.
        """

        return self.get_tool_config(
            tool_name,
            profile_name,
        ).enabled

    def get_tool_options(
        self,
        tool_name: str,
        profile_name: str | None = None,
    ) -> dict[str, Any]:
        """
        Return configured options for a tool.
        """

        return self.get_tool_config(
            tool_name,
            profile_name,
        ).options.copy()

    def as_dict(self) -> dict[str, Any]:
        """
        Serialize the complete configuration.
        """

        return {
            "default_profile": self.default_profile,
            "output_base_dir": str(
                self.output_base_dir
            ),
            "request_rate_limit": (
                self.request_rate_limit
            ),
            "command_timeout": (
                self.command_timeout
            ),
            "continue_on_error": (
                self.continue_on_error
            ),
            "require_confirmation_for_aggressive": (
                self.require_confirmation_for_aggressive
            ),
            "profiles": {
                name: profile.as_dict()
                for name, profile in self.profiles.items()
            },
        }


###############################################################################
# Default Profile Definitions
###############################################################################


def _tool(
    enabled: bool = True,
    **options: Any,
) -> ToolConfig:
    """
    Convenience constructor for tool configuration.
    """

    return ToolConfig(
        enabled=enabled,
        options=options,
    )


def _build_default_profiles() -> dict[str, ProfileConfig]:
    """
    Build the canonical FAST/STANDARD/FULL profiles.

    The profiles intentionally reference only the final ScopeForgeX core
    tool set agreed upon by the architecture.
    """

    ###########################################################################
    # FAST
    ###########################################################################

    fast_tools = {
        "amass": _tool(
            passive=True,
        ),
        "subhunt": _tool(
            threads=50,
        ),
        "nmap": _tool(
            service_detection=True,
            os_detection=False,
            timing="T3",
            nse_profile="safe",
        ),
        "dig": _tool(
            record_types=[
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "NS",
                "TXT",
                "SOA",
            ],
        ),
        "httpx": _tool(
            status_code=True,
            title=True,
            server=True,
            technology=True,
        ),
        "katana": _tool(
            depth=2,
            concurrency=10,
        ),
        "whatweb": _tool(),
        "nuclei": _tool(
            severity=(
                "critical",
                "high",
            ),
        ),
        "testssl.sh": _tool(
            enabled=False,
        ),
        "nikto": _tool(
            enabled=False,
        ),
        "ffuf": _tool(
            enabled=False,
        ),
        "kiterunner": _tool(
            enabled=False,
        ),
        "jsluice": _tool(
            enabled=False,
        ),
        "sqlmap": _tool(
            enabled=False,
        ),
        "dalfox": _tool(
            enabled=False,
        ),
        "jwt_tool": _tool(
            enabled=False,
        ),
        "sstimap": _tool(
            enabled=False,
        ),
        "hydra": _tool(
            enabled=False,
        ),
        "hashcat": _tool(
            enabled=False,
        ),
    }

    ###########################################################################
    # STANDARD
    ###########################################################################

    standard_tools = {
        "amass": _tool(
            passive=True,
            active=True,
        ),
        "subhunt": _tool(
            threads=50,
        ),
        "nmap": _tool(
            service_detection=True,
            os_detection=False,
            timing="T3",
            nse_profile="safe",
        ),
        "dig": _tool(
            record_types=[
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "NS",
                "TXT",
                "SOA",
            ],
        ),
        "httpx": _tool(
            status_code=True,
            title=True,
            server=True,
            technology=True,
        ),
        "katana": _tool(
            depth=3,
            concurrency=10,
        ),
        "ffuf": _tool(
            enabled=True,
        ),
        "whatweb": _tool(),
        "kiterunner": _tool(
            enabled=True,
        ),
        "jsluice": _tool(
            enabled=True,
        ),
        "nuclei": _tool(
            severity=(
                "critical",
                "high",
                "medium",
            ),
        ),
        "nikto": _tool(),
        "testssl.sh": _tool(),
        "sqlmap": _tool(
            enabled=False,
        ),
        "dalfox": _tool(
            enabled=False,
        ),
        "jwt_tool": _tool(
            enabled=False,
        ),
        "sstimap": _tool(
            enabled=False,
        ),
        "hydra": _tool(
            enabled=False,
        ),
        "hashcat": _tool(
            enabled=False,
        ),
    }

    ###########################################################################
    # FULL
    ###########################################################################

    full_tools = {
        "amass": _tool(
            passive=True,
            active=True,
            bruteforce=False,
        ),
        "subhunt": _tool(
            threads=50,
        ),
        "nmap": _tool(
            service_detection=True,
            os_detection=True,
            timing="T3",
            nse_profile="safe",
        ),
        "dig": _tool(
            record_types=[
                "A",
                "AAAA",
                "CNAME",
                "MX",
                "NS",
                "TXT",
                "SOA",
            ],
        ),
        "httpx": _tool(
            status_code=True,
            title=True,
            server=True,
            technology=True,
        ),
        "katana": _tool(
            depth=5,
            concurrency=10,
        ),
        "ffuf": _tool(),
        "whatweb": _tool(),
        "kiterunner": _tool(),
        "jsluice": _tool(),
        "nuclei": _tool(
            severity=(
                "critical",
                "high",
                "medium",
                "low",
                "info",
            ),
        ),
        "nikto": _tool(),
        "testssl.sh": _tool(),
        "sqlmap": _tool(
            enabled=False,
        ),
        "dalfox": _tool(
            enabled=False,
        ),
        "jwt_tool": _tool(
            enabled=False,
        ),
        "sstimap": _tool(
            enabled=False,
        ),
        "hydra": _tool(
            enabled=False,
        ),
        "hashcat": _tool(
            enabled=False,
        ),
    }

    return {
        PROFILE_FAST: ProfileConfig(
            name=PROFILE_FAST,
            description=(
                "Minimal high-value assessment with low request volume."
            ),
            tools=fast_tools,
            settings={
                "request_rate_limit": 10,
                "command_timeout": 300,
                "continue_on_error": True,
            },
        ),
        PROFILE_STANDARD: ProfileConfig(
            name=PROFILE_STANDARD,
            description=(
                "Normal professional security assessment."
            ),
            tools=standard_tools,
            settings={
                "request_rate_limit": 25,
                "command_timeout": 600,
                "continue_on_error": True,
            },
        ),
        PROFILE_FULL: ProfileConfig(
            name=PROFILE_FULL,
            description=(
                "Maximum configured assessment coverage."
            ),
            tools=full_tools,
            settings={
                "request_rate_limit": 50,
                "command_timeout": 1200,
                "continue_on_error": True,
            },
        ),
    }


###############################################################################
# Validation
###############################################################################


def _validate_tool_config(
    tool_name: str,
    config: ToolConfig,
) -> None:
    """
    Validate one tool configuration.
    """

    if not isinstance(
        config.enabled,
        bool,
    ):
        raise ConfigurationError(
            f"{tool_name}: enabled must be boolean."
        )

    if not isinstance(
        config.options,
        dict,
    ):
        raise ConfigurationError(
            f"{tool_name}: options must be a mapping."
        )


def validate_config(
    config: ScopeForgeXConfig,
) -> ScopeForgeXConfig:
    """
    Validate and return configuration.

    Raises:
        ConfigurationError:
            When configuration violates canonical constraints.
    """

    profile_name = (
        config.default_profile.strip().lower()
    )

    if profile_name not in SUPPORTED_PROFILES:
        raise ConfigurationError(
            "default_profile must be one of: "
            + ", ".join(
                SUPPORTED_PROFILES
            )
        )

    config.default_profile = profile_name

    if config.command_timeout <= 0:
        raise ConfigurationError(
            "command_timeout must be greater than zero."
        )

    if (
        config.request_rate_limit is not None
        and config.request_rate_limit <= 0
    ):
        raise ConfigurationError(
            "request_rate_limit must be greater than zero."
        )

    for name, profile in config.profiles.items():

        normalized = (
            name.strip().lower()
        )

        if normalized not in SUPPORTED_PROFILES:
            raise ConfigurationError(
                f"Unsupported profile: {name}"
            )

        for tool_name, tool_config in (
            profile.tools.items()
        ):
            _validate_tool_config(
                tool_name,
                tool_config,
            )

    return config


###############################################################################
# YAML Loading
###############################################################################


def _mapping(
    value: Any,
) -> dict[str, Any]:
    """
    Return a dictionary for a YAML mapping.
    """

    if isinstance(
        value,
        Mapping,
    ):
        return dict(value)

    return {}


def _parse_tool_config(
    value: Any,
) -> ToolConfig:
    """
    Convert a YAML tool definition into ToolConfig.
    """

    if isinstance(
        value,
        bool,
    ):
        return ToolConfig(
            enabled=value
        )

    data = _mapping(
        value
    )

    enabled = data.pop(
        "enabled",
        True,
    )

    if not isinstance(
        enabled,
        bool,
    ):
        raise ConfigurationError(
            "Tool 'enabled' value must be boolean."
        )

    options = data.pop(
        "options",
        data,
    )

    if not isinstance(
        options,
        Mapping,
    ):
        raise ConfigurationError(
            "Tool options must be a mapping."
        )

    return ToolConfig(
        enabled=enabled,
        options=dict(
            options
        ),
    )


def _load_yaml(
    path: Path,
) -> dict[str, Any]:
    """
    Load one YAML mapping.
    """

    if not path.exists():
        return {}

    try:
        with path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(
                file
            )

    except OSError as exc:
        raise ConfigurationError(
            f"Unable to read configuration: {path}"
        ) from exc

    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"Invalid YAML configuration: {path}"
        ) from exc

    return _mapping(
        data
    )


def load_config(
    config_dir: str | Path = "config",
) -> ScopeForgeXConfig:
    """
    Load ScopeForgeX configuration.

    The canonical profiles are always present. YAML files may override
    supported profile/tool values without changing the architecture.

    Supported files:

        config/default.yaml
        config/profiles.yaml
        config/tools.yaml
    """

    directory = Path(
        config_dir
    )

    default_data = _load_yaml(
        directory / "default.yaml"
    )

    profiles_data = _load_yaml(
        directory / "profiles.yaml"
    )

    tools_data = _load_yaml(
        directory / "tools.yaml"
    )

    profiles = _build_default_profiles()

    ###########################################################################
    # Global defaults
    ###########################################################################

    default_profile = str(
        _mapping(
            default_data.get(
                "profiles",
                {},
            )
        ).get(
            "default",
            PROFILE_STANDARD,
        )
    ).strip().lower()

    output_base_dir = Path(
        default_data.get(
            "output_base_dir",
            "outputs",
        )
    )

    modes = _mapping(
        default_data.get(
            "modes",
            {},
        )
    )

    require_confirmation = bool(
        modes.get(
            "confirm_before_aggressive",
            True,
        )
    )

    ###########################################################################
    # YAML profile overrides
    ###########################################################################

    yaml_profiles = _mapping(
        profiles_data.get(
            "profiles",
            {},
        )
    )

    for profile_name, raw_profile in (
        yaml_profiles.items()
    ):

        normalized_profile = (
            str(profile_name)
            .strip()
            .lower()
        )

        if normalized_profile not in profiles:
            continue

        profile = profiles[
            normalized_profile
        ]

        profile_data = _mapping(
            raw_profile
        )

        description = profile_data.get(
            "description"
        )

        if description:
            profile.description = str(
                description
            )

        settings = _mapping(
            profile_data.get(
                "settings",
                {},
            )
        )

        profile.settings.update(
            settings
        )

        yaml_tools = _mapping(
            profile_data.get(
                "tools",
                {},
            )
        )

        for tool_name, raw_tool in (
            yaml_tools.items()
        ):

            normalized_tool = (
                str(tool_name)
                .strip()
                .lower()
            )

            profile.tools[
                normalized_tool
            ] = _parse_tool_config(
                raw_tool
            )

    ###########################################################################
    # Tool executable overrides
    ###########################################################################

    # tools.yaml is intentionally interpreted as executable-name overrides.
    # Command construction remains the responsibility of each adapter.
    tool_executables = _mapping(
        tools_data.get(
            "tools",
            {},
        )
    )

    if tool_executables:
        for profile in profiles.values():

            for tool_name in profile.tools:

                if tool_name in tool_executables:
                    profile.tools[
                        tool_name
                    ].options.setdefault(
                        "executable",
                        str(
                            tool_executables[
                                tool_name
                            ]
                        ),
                    )

    ###########################################################################
    # Final configuration
    ###########################################################################

    config = ScopeForgeXConfig(
        default_profile=default_profile,
        output_base_dir=output_base_dir,
        command_timeout=600,
        continue_on_error=True,
        require_confirmation_for_aggressive=(
            require_confirmation
        ),
        profiles=profiles,
    )

    standard = config.profiles.get(
        PROFILE_STANDARD
    )

    if standard:
        config.request_rate_limit = standard.settings.get(
            "request_rate_limit"
        )
        config.command_timeout = standard.settings.get(
            "command_timeout",
            config.command_timeout,
        )
        config.continue_on_error = standard.settings.get(
            "continue_on_error",
            config.continue_on_error,
        )

    return validate_config(
        config
    )


###############################################################################
# Profile Resolution
###############################################################################


def resolve_profile(
    profile_name: str | None = None,
    config: ScopeForgeXConfig | None = None,
) -> ProfileConfig:
    """
    Resolve an assessment profile.

    Args:
        profile_name:
            FAST, STANDARD or FULL. Case-insensitive.

        config:
            Optional pre-loaded configuration.
    """

    active_config = (
        config
        or load_config()
    )

    return active_config.get_profile(
        profile_name
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
    "ToolConfig",
    "ProfileConfig",
    "ScopeForgeXConfig",
    "validate_config",
    "load_config",
    "resolve_profile",
]

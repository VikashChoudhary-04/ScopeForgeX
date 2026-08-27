"""
ScopeForgeX Configuration System
=================================

Canonical configuration layer for ScopeForgeX assessment profiles.

The configuration system defines:

- Assessment profiles
- Profile defaults
- Per-tool enablement
- Per-tool option overrides
- Configuration validation
- Safe merging of profile and user configuration

Design Principles
-----------------
- Profiles define defaults, not hard limits.
- Users can override individual tool settings.
- Tool-specific command construction remains inside tool adapters.
- The workflow engine consumes configuration and never constructs commands.
- Configuration is independent of CLI/UI presentation.
- Unknown tools and unsupported options are rejected early.
- No tool is enabled merely because it exists in the registry.

Canonical profiles
------------------
FAST
    Minimal high-value assessment with low request volume.

STANDARD
    Normal professional assessment with broad coverage.

FULL
    Maximum configured coverage with extended checks.

v1.2.0
"""

from __future__ import annotations

from copy import deepcopy
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

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
class ToolConfiguration:
    """
    Configuration for one registered ScopeForgeX tool.
    """

    enabled: bool = True

    options: dict[str, Any] = field(
        default_factory=dict
    )

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
        }


###############################################################################
# Assessment Profile
###############################################################################


@dataclass(slots=True)
class AssessmentProfile:
    """
    Canonical assessment profile.

    Profiles control defaults for tool selection and configuration. They do
    not contain tool-specific command construction.
    """

    name: str

    description: str

    tools: dict[str, ToolConfiguration] = field(
        default_factory=dict
    )

    def is_enabled(
        self,
        tool_name: str,
    ) -> bool:
        """
        Return whether a tool is enabled.
        """

        configuration = self.tools.get(
            tool_name
        )

        if configuration is None:
            return False

        return configuration.enabled

    def get_options(
        self,
        tool_name: str,
    ) -> dict[str, Any]:
        """
        Return configured options for a tool.
        """

        configuration = self.tools.get(
            tool_name
        )

        if configuration is None:
            return {}

        return deepcopy(
            configuration.options
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return a serializable representation.
        """

        return {
            "name": self.name,
            "description": self.description,
            "tools": {
                name: configuration.as_dict()
                for name, configuration
                in self.tools.items()
            },
        }


###############################################################################
# ScopeForgeX Configuration
###############################################################################


@dataclass(slots=True)
class ScopeForgeXConfig:
    """
    Complete ScopeForgeX runtime configuration.
    """

    output_base_dir: str = "outputs"

    default_profile: str = PROFILE_STANDARD

    profiles: dict[str, AssessmentProfile] = field(
        default_factory=dict
    )

    tool_overrides: dict[str, ToolConfiguration] = field(
        default_factory=dict
    )

    metadata: dict[str, Any] = field(
        default_factory=dict
    )

    def get_profile(
        self,
        profile_name: str | None = None,
    ) -> AssessmentProfile:
        """
        Return the requested assessment profile.
        """

        name = (
            profile_name
            or self.default_profile
        ).strip().lower()

        if name not in self.profiles:
            raise ConfigurationError(
                f"Unknown ScopeForgeX profile: {name}"
            )

        return self.profiles[name]

    def get_tool_configuration(
        self,
        tool_name: str,
        profile_name: str | None = None,
    ) -> ToolConfiguration:
        """
        Return effective configuration for a tool.

        Profile configuration is loaded first, followed by explicit
        user-level tool overrides.
        """

        profile = self.get_profile(
            profile_name
        )

        profile_configuration = profile.tools.get(
            tool_name,
            ToolConfiguration(
                enabled=False
            ),
        )

        effective = ToolConfiguration(
            enabled=profile_configuration.enabled,
            options=deepcopy(
                profile_configuration.options
            ),
        )

        override = self.tool_overrides.get(
            tool_name
        )

        if override is not None:

            effective.enabled = (
                override.enabled
            )

            effective.options.update(
                deepcopy(
                    override.options
                )
            )

        return effective

    def enabled_tools(
        self,
        profile_name: str | None = None,
    ) -> tuple[str, ...]:
        """
        Return enabled tools for a profile.

        Explicit tool overrides are applied to the profile before the final
        list is returned.
        """

        profile = self.get_profile(
            profile_name
        )

        enabled: list[str] = []

        tool_names = set(
            profile.tools
        )

        tool_names.update(
            self.tool_overrides
        )

        for tool_name in sorted(
            tool_names
        ):

            configuration = (
                self.get_tool_configuration(
                    tool_name,
                    profile.name,
                )
            )

            if configuration.enabled:
                enabled.append(
                    tool_name
                )

        return tuple(
            enabled
        )

    def as_dict(
        self,
    ) -> dict[str, Any]:
        """
        Return the complete configuration as a dictionary.
        """

        return {
            "output_base_dir": self.output_base_dir,
            "default_profile": self.default_profile,
            "profiles": {
                name: profile.as_dict()
                for name, profile
                in self.profiles.items()
            },
            "tool_overrides": {
                name: configuration.as_dict()
                for name, configuration
                in self.tool_overrides.items()
            },
            "metadata": deepcopy(
                self.metadata
            ),
        }


###############################################################################
# Default Profiles
###############################################################################


def _default_profiles() -> dict[str, AssessmentProfile]:
    """
    Build the canonical ScopeForgeX profiles.

    The profile determines defaults, while users remain free to override
    individual tools through explicit configuration.
    """

    ###########################################################################
    # FAST
    ###########################################################################

    fast = AssessmentProfile(
        name=PROFILE_FAST,
        description=(
            "Minimal high-value assessment with low request volume."
        ),
        tools={
            "amass": ToolConfiguration(
                enabled=True,
                options={
                    "passive": True,
                },
            ),
            "subhunt": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "nmap": ToolConfiguration(
                enabled=True,
                options={
                    "service_detection": True,
                    "os_detection": False,
                    "timing": "T3",
                    "nse_profile": "safe",
                },
            ),
            "dig": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "httpx": ToolConfiguration(
                enabled=True,
                options={
                    "status_code": True,
                    "title": True,
                    "server": True,
                    "technology": True,
                },
            ),
            "katana": ToolConfiguration(
                enabled=True,
                options={
                    "depth": 2,
                },
            ),
            "ffuf": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "whatweb": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "kiterunner": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "jsluice": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "nuclei": ToolConfiguration(
                enabled=True,
                options={
                    "severity": (
                        "critical",
                        "high",
                    ),
                    "rate_limit": 30,
                    "timeout": 5,
                    "retries": 1,
                },
            ),
            "nikto": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "testssl.sh": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "sqlmap": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "dalfox": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "jwt_tool": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "sstimap": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "hydra": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "hashcat": ToolConfiguration(
                enabled=False,
                options={},
            ),
        },
    )

    ###########################################################################
    # STANDARD
    ###########################################################################

    standard = AssessmentProfile(
        name=PROFILE_STANDARD,
        description=(
            "Normal professional assessment with broad attack-surface "
            "enumeration and vulnerability assessment."
        ),
        tools={
            "amass": ToolConfiguration(
                enabled=True,
                options={
                    "passive": True,
                },
            ),
            "subhunt": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "nmap": ToolConfiguration(
                enabled=True,
                options={
                    "service_detection": True,
                    "os_detection": False,
                    "timing": "T3",
                    "nse_profile": "safe",
                },
            ),
            "dig": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "httpx": ToolConfiguration(
                enabled=True,
                options={
                    "status_code": True,
                    "title": True,
                    "server": True,
                    "technology": True,
                },
            ),
            "katana": ToolConfiguration(
                enabled=True,
                options={
                    "depth": 3,
                },
            ),
            "ffuf": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "whatweb": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "kiterunner": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "jsluice": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "nuclei": ToolConfiguration(
                enabled=True,
                options={
                    "severity": (
                        "critical",
                        "high",
                        "medium",
                    ),
                    "rate_limit": 30,
                    "timeout": 5,
                    "retries": 1,
                },
            ),
            "nikto": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "testssl.sh": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "sqlmap": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "dalfox": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "jwt_tool": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "sstimap": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "hydra": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "hashcat": ToolConfiguration(
                enabled=False,
                options={},
            ),
        },
    )

    ###########################################################################
    # FULL
    ###########################################################################

    full = AssessmentProfile(
        name=PROFILE_FULL,
        description=(
            "Maximum configured coverage with extended enumeration and "
            "target-dependent validation."
        ),
        tools={
            "amass": ToolConfiguration(
                enabled=True,
                options={
                    "passive": True,
                },
            ),
            "subhunt": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "nmap": ToolConfiguration(
                enabled=True,
                options={
                    "service_detection": True,
                    "os_detection": True,
                    "timing": "T3",
                    "nse_profile": "safe",
                },
            ),
            "dig": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "httpx": ToolConfiguration(
                enabled=True,
                options={
                    "status_code": True,
                    "title": True,
                    "server": True,
                    "technology": True,
                },
            ),
            "katana": ToolConfiguration(
                enabled=True,
                options={
                    "depth": 5,
                },
            ),
            "ffuf": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "whatweb": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "kiterunner": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "jsluice": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "nuclei": ToolConfiguration(
                enabled=True,
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
                },
            ),
            "nikto": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "testssl.sh": ToolConfiguration(
                enabled=True,
                options={},
            ),
            "sqlmap": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "dalfox": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "jwt_tool": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "sstimap": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "hydra": ToolConfiguration(
                enabled=False,
                options={},
            ),
            "hashcat": ToolConfiguration(
                enabled=False,
                options={},
            ),
        },
    )

    return {
        PROFILE_FAST: fast,
        PROFILE_STANDARD: standard,
        PROFILE_FULL: full,
    }


###############################################################################
# Configuration Loading
###############################################################################


def _load_yaml(
    path: str | Path,
) -> dict[str, Any]:
    """
    Load a YAML file.

    Missing files produce an empty dictionary.
    """

    file_path = Path(
        path
    )

    if not file_path.exists():
        return {}

    try:
        with file_path.open(
            "r",
            encoding="utf-8",
        ) as file:
            data = yaml.safe_load(
                file
            )

    except OSError as exc:
        raise ConfigurationError(
            f"Unable to read configuration file: {file_path}"
        ) from exc

    except yaml.YAMLError as exc:
        raise ConfigurationError(
            f"Invalid YAML configuration: {file_path}"
        ) from exc

    if data is None:
        return {}

    if not isinstance(
        data,
        dict,
    ):
        raise ConfigurationError(
            f"Configuration root must be a mapping: {file_path}"
        )

    return data


###############################################################################
# Configuration Conversion
###############################################################################


def _tool_configuration_from_mapping(
    data: Any,
) -> ToolConfiguration:
    """
    Convert a mapping into ToolConfiguration.
    """

    if data is None:
        return ToolConfiguration()

    if not isinstance(
        data,
        dict,
    ):
        raise ConfigurationError(
            "Tool configuration must be a mapping."
        )

    enabled = data.get(
        "enabled",
        True,
    )

    if not isinstance(
        enabled,
        bool,
    ):
        raise ConfigurationError(
            "'enabled' must be a boolean."
        )

    options = data.get(
        "options",
        {},
    )

    if not isinstance(
        options,
        dict,
    ):
        raise ConfigurationError(
            "'options' must be a mapping."
        )

    return ToolConfiguration(
        enabled=enabled,
        options=deepcopy(
            options
        ),
    )


def _profiles_from_mapping(
    data: Any,
) -> dict[str, AssessmentProfile]:
    """
    Convert profile configuration into AssessmentProfile objects.
    """

    profiles = _default_profiles()

    if data is None:
        return profiles

    if not isinstance(
        data,
        dict,
    ):
        raise ConfigurationError(
            "'profiles' must be a mapping."
        )

    for profile_name, profile_data in data.items():

        name = str(
            profile_name
        ).strip().lower()

        if name not in SUPPORTED_PROFILES:
            raise ConfigurationError(
                f"Unsupported ScopeForgeX profile: {name}"
            )

        if not isinstance(
            profile_data,
            dict,
        ):
            raise ConfigurationError(
                f"Profile '{name}' must be a mapping."
            )

        profile = profiles[name]

        if "description" in profile_data:
            profile.description = str(
                profile_data["description"]
            )

        configured_tools = profile_data.get(
            "tools"
        )

        if configured_tools is None:
            continue

        if not isinstance(
            configured_tools,
            dict,
        ):
            raise ConfigurationError(
                f"Profile '{name}' tools must be a mapping."
            )

        for tool_name, tool_data in configured_tools.items():

            tool = str(
                tool_name
            ).strip()

            profile.tools[tool] = (
                _tool_configuration_from_mapping(
                    tool_data
                )
            )

    return profiles


def _overrides_from_mapping(
    data: Any,
) -> dict[str, ToolConfiguration]:
    """
    Convert explicit tool overrides into ToolConfiguration objects.
    """

    if data is None:
        return {}

    if not isinstance(
        data,
        dict,
    ):
        raise ConfigurationError(
            "'tool_overrides' must be a mapping."
        )

    return {
        str(tool_name).strip():
            _tool_configuration_from_mapping(
                tool_data
            )
        for tool_name, tool_data
        in data.items()
    }


###############################################################################
# Public Loader
###############################################################################


def load_configuration(
    config_dir: str | Path = "config",
) -> ScopeForgeXConfig:
    """
    Load the canonical ScopeForgeX configuration.

    Expected files:

        config/default.yaml
        config/profiles.yaml

    ``config/tools.yaml`` remains a legacy executable-name configuration
    source and is intentionally not used for tool selection. The canonical
    tool registry owns tool identity and metadata.
    """

    directory = Path(
        config_dir
    )

    default_data = _load_yaml(
        directory / "default.yaml"
    )

    profile_data = _load_yaml(
        directory / "profiles.yaml"
    )

    output_base_dir = str(
        default_data.get(
            "output_base_dir",
            "outputs",
        )
    )

    default_profile = str(
        default_data.get(
            "default_profile",
            PROFILE_STANDARD,
        )
    ).strip().lower()

    if default_profile not in SUPPORTED_PROFILES:
        raise ConfigurationError(
            f"Unsupported default profile: {default_profile}"
        )

    profiles = _profiles_from_mapping(
        profile_data.get(
            "profiles",
            {},
        )
    )

    config = ScopeForgeXConfig(
        output_base_dir=output_base_dir,
        default_profile=default_profile,
        profiles=profiles,
        metadata={
            "config_dir": str(
                directory
            )
        },
    )

    return config


###############################################################################
# Registry Validation
###############################################################################


def validate_configuration(
    config: ScopeForgeXConfig,
) -> None:
    """
    Validate configured tools against the canonical tool registry.

    The registry is imported lazily to prevent configuration/registry
    import cycles.
    """

    try:
        from scopeforgex.registry.tool_registry import (
            get_registered_tools,
        )

        registered_tools = set(
            get_registered_tools()
        )

    except ImportError:
        # Registry validation can be deferred when the registry itself is
        # being initialized.
        return

    configured_tools: set[str] = set()

    for profile in config.profiles.values():
        configured_tools.update(
            profile.tools
        )

    configured_tools.update(
        config.tool_overrides
    )

    unknown = sorted(
        configured_tools
        - registered_tools
    )

    if unknown:
        raise ConfigurationError(
            "Unknown ScopeForgeX tools in configuration: "
            + ", ".join(
                unknown
            )
        )

    ###########################################################################
    # Validate per-tool options through the adapter abstraction.
    ###########################################################################

    for profile in config.profiles.values():

        for tool_name, tool_configuration in profile.tools.items():

            try:
                from scopeforgex.registry.tool_registry import (
                    create_tool_adapter,
                )

                adapter = create_tool_adapter(
                    tool_name
                )

                adapter.validate_options(
                    tool_configuration.options
                )

            except KeyError as exc:
                raise ConfigurationError(
                    f"Unknown ScopeForgeX tool: {tool_name}"
                ) from exc

            except ValueError as exc:
                raise ConfigurationError(
                    f"Invalid options for '{tool_name}' "
                    f"in profile '{profile.name}': {exc}"
                ) from exc

    for tool_name, tool_configuration in config.tool_overrides.items():

        try:
            from scopeforgex.registry.tool_registry import (
                create_tool_adapter,
            )

            adapter = create_tool_adapter(
                tool_name
            )

            adapter.validate_options(
                tool_configuration.options
            )

        except KeyError as exc:
            raise ConfigurationError(
                f"Unknown ScopeForgeX tool: {tool_name}"
            ) from exc

        except ValueError as exc:
            raise ConfigurationError(
                f"Invalid options for '{tool_name}' override: {exc}"
            ) from exc


###############################################################################
# Convenience API
###############################################################################


def get_default_configuration() -> ScopeForgeXConfig:
    """
    Return an in-memory canonical configuration.

    This is useful for tests and programmatic execution without YAML files.
    """

    return ScopeForgeXConfig(
        output_base_dir="outputs",
        default_profile=PROFILE_STANDARD,
        profiles=_default_profiles(),
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
    "load_configuration",
    "validate_configuration",
    "get_default_configuration",
]

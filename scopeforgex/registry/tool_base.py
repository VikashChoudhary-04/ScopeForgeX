"""
ScopeForgeX Tool Framework
==========================

Base classes shared by all ScopeForgeX tools.

Every executable tool should inherit from ToolBase and return a
ToolResult from its run() method.

v0.4.0
"""

from abc import ABC, abstractmethod
from dataclasses import dataclass, field


@dataclass(slots=True)
class ToolResult:
    """
    Standard result returned by every tool.
    """

    name: str
    ran: bool
    output_files: list[str] = field(default_factory=list)
    notes: str = ""


class ToolBase(ABC):
    """
    Abstract base class for every ScopeForgeX tool.
    """

    # Human-readable tool name.
    name: str = "tool"

    # Pipeline stage.
    stage: int = 0

    # Short description shown to the user.
    description: str = ""

    # low | medium | high
    risk: str = "low"

    @abstractmethod
    def run(self, ctx: dict) -> ToolResult:
        """
        Execute the tool.

        Args:
            ctx: Shared execution context.

        Returns:
            ToolResult describing the execution outcome.
        """
        raise NotImplementedError

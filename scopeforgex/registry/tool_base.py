"""
ScopeForgeX Tool Framework

Base class shared by all ScopeForgeX tools.

Every executable tool returns an ExecutionResult.
"""

from abc import ABC, abstractmethod

from scopeforgex.models.execution_result import ExecutionResult


class ToolBase(ABC):
    """
    Abstract base class for every ScopeForgeX tool.
    """

    name: str = "tool"

    stage: int = 0

    description: str = ""

    risk: str = "low"


    @abstractmethod
    def run(
        self,
        ctx: dict,
    ) -> ExecutionResult:
        """
        Execute the tool.

        Returns:
            ExecutionResult
        """

        raise NotImplementedError


__all__ = [
    "ToolBase",
]

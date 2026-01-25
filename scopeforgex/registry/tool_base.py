from dataclasses import dataclass

@dataclass
class ToolResult:
    name: str
    ran: bool
    output_files: list[str]
    notes: str = ""

class ToolBase:
    name: str = "tool"
    stage: int = 0
    description: str = ""
    risk: str = "low"

    def run(self, ctx: dict) -> ToolResult:
        raise NotImplementedError

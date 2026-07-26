import os

import questionary

from scopeforgex.registry.tool_base import ToolBase, ToolResult
from scopeforgex.ui import ok


def write_prepared_command(path: str, title: str, command: str):
    """
    Append a prepared post-exploitation command to the shared command file.
    """

    os.makedirs(os.path.dirname(path), exist_ok=True)

    with open(path, "a", encoding="utf-8") as outfile:
        outfile.write("\n")
        outfile.write("=" * 80 + "\n")
        outfile.write(f"{title}\n")
        outfile.write("-" * 80 + "\n")
        outfile.write(command.strip())
        outfile.write("\n")


class PostPrepTool(ToolBase):
    """
    Generates post-exploitation commands for manual execution.

    ScopeForgeX intentionally prepares commands instead of executing
    post-exploitation tools automatically.
    """

    stage = 5
    risk = "high"

    def __init__(
        self,
        name: str,
        description: str,
        template_cmd: str,
    ):
        self.name = name
        self.description = description
        self.template_cmd = template_cmd

    def run(self, ctx: dict) -> ToolResult:
        post_dir = os.path.join(
            ctx["outdir"],
            "post",
        )

        os.makedirs(post_dir, exist_ok=True)

        output_file = os.path.join(
            post_dir,
            "prepared_commands.txt",
        )

        if not questionary.confirm(
            f"Prepare command for: {self.name}?"
        ).ask():
            return ToolResult(
                self.name,
                False,
                [],
                "Skipped",
            )

        command = self.template_cmd.format(
            target=ctx.get("target", "TARGET")
        )

        write_prepared_command(
            output_file,
            f"{self.name} — {self.description}",
            command,
        )

        ok(f"Prepared command saved for {self.name}")

        return ToolResult(
            self.name,
            True,
            [output_file],
            "Prepared command saved",
        )


ALL_STAGE5_POST_TOOLS = [
    PostPrepTool(
        "chisel",
        "Pivoting / tunneling",
        "chisel server --reverse -p 8080",
    ),
    PostPrepTool(
        "ssh",
        "SOCKS proxy tunnel",
        "ssh -D 1080 user@TARGET_IP",
    ),
    PostPrepTool(
        "hydra",
        "Credential attack (rate-limit required)",
        "hydra -l admin -P /path/to/passwords.txt "
        "{target} "
        "http-post-form "
        "\"/login:username=^USER^&password=^PASS^:Invalid\"",
    ),
    PostPrepTool(
        "medusa",
        "Credential attack (rate-limit required)",
        "medusa -h {target} -u admin "
        "-P /path/to/passwords.txt -M http",
    ),
    PostPrepTool(
        "hashcat",
        "Offline hash cracking",
        "hashcat -m 0 -a 0 hashes.txt /path/to/wordlist.txt",
    ),
    PostPrepTool(
        "john",
        "Offline password cracking",
        "john --wordlist=/path/to/wordlist.txt hashes.txt",
    ),
]

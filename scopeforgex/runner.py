import subprocess
from scopeforgex.ui import info, warn


def run_cmd(cmd: str, outfile: str | None = None):
    """
    Runs a shell command and captures output.

    - If outfile is provided: writes BOTH stdout + stderr into the file
      (so even errors are saved and you never get a "blank file with no clue").
    - If outfile is None: prints output normally to the terminal.
    """
    info(f"Running: {cmd}")

    try:
        if outfile:
            with open(outfile, "w", encoding="utf-8") as f:
                subprocess.run(
                    cmd,
                    shell=True,
                    stdout=f,
                    stderr=subprocess.STDOUT,
                    text=True,
                    check=False,
                )
        else:
            subprocess.run(
                cmd,
                shell=True,
                check=False,
            )

    except Exception as e:
        warn(f"Command failed: {e}")

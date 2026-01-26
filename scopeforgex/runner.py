import subprocess
from scopeforgex.ui import info, warn


def run_cmd(cmd: str, outfile: str | None = None, timeout: int = 900):
    """
    Runs a shell command and captures output.

    - outfile provided -> writes stdout+stderr to that file
    - timeout default = 900 seconds (15 minutes)
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
                    timeout=timeout,
                )
        else:
            subprocess.run(
                cmd,
                shell=True,
                check=False,
                timeout=timeout,
            )

    except subprocess.TimeoutExpired:
        warn(f"Timeout reached ({timeout}s). Command stopped.")
        if outfile:
            with open(outfile, "a", encoding="utf-8") as f:
                f.write(f"\n\n[ScopeForgeX] Timeout reached ({timeout}s). Command stopped.\n")
    except Exception as e:
        warn(f"Command failed: {e}")

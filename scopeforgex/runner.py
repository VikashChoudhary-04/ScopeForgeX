import subprocess
from scopeforgex.ui import info, warn

def run_cmd(cmd: str, outfile: str = None):
    info(f"Running: {cmd}")
    try:
        if outfile:
            with open(outfile, "w", encoding="utf-8") as f:
                subprocess.run(cmd, shell=True, stdout=f, stderr=subprocess.STDOUT, text=True, check=False)
        else:
            subprocess.run(cmd, shell=True, check=False)
    except Exception as e:
        warn(f"Command failed: {e}")

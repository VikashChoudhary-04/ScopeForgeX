import os
from scopeforgex.utils import ensure_dir


def init_output_dirs(base_dir: str, target_name: str):
    outdir = os.path.join(base_dir, target_name)

    ensure_dir(outdir)
    ensure_dir(os.path.join(outdir, "recon"))
    ensure_dir(os.path.join(outdir, "enum"))
    ensure_dir(os.path.join(outdir, "vuln"))
    ensure_dir(os.path.join(outdir, "exploit"))
    ensure_dir(os.path.join(outdir, "post"))

    return outdir


def pipeline_paths(outdir: str) -> dict:
    """
    Single source of truth paths.
    Every stage/tool should read/write these.
    """
    recon = os.path.join(outdir, "recon")

    return {
        "hosts_raw": os.path.join(recon, "hosts_raw.txt"),
        "hosts_alive": os.path.join(recon, "hosts_alive.txt"),
        "hosts_final": os.path.join(recon, "hosts_final.txt"),
        "urls_raw": os.path.join(recon, "urls_raw.txt"),
        "urls_final": os.path.join(recon, "urls_final.txt"),
    }

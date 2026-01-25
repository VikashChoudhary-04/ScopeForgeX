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

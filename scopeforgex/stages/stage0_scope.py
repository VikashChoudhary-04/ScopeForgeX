import questionary
from scopeforgex.ui import stage, err, ok
from scopeforgex.utils import load_yaml
from scopeforgex.stages.shared import init_output_dirs
from scopeforgex.validators import is_valid_domain, is_valid_ip_or_cidr

def stage0_scope(ctx: dict):
    stage("STAGE 0 — SCOPE & LEGAL CHECK", "blue")

    authorized = questionary.confirm("Do you have written authorization?").ask()
    if not authorized:
        err("STOP: Written authorization required.")
        raise SystemExit(1)

    ttype = questionary.select(
        "Choose target type:",
        choices=["Web / Domain", "Network / IP Range"]
    ).ask()

    config = load_yaml("config/default.yaml")
    base_dir = config.get("output_base_dir", "outputs")

    if "Web" in ttype:
        target = questionary.text("Enter domain (example.com):").ask()
        if not is_valid_domain(target):
            err("Invalid domain format.")
            raise SystemExit(1)

        ctx["target_type"] = "web"
        ctx["target"] = target.strip()
        ctx["outdir"] = init_output_dirs(base_dir, ctx["target"].replace(".", "_"))
        ok(f"Target set: {ctx['target']}")
    else:
        target = questionary.text("Enter IP / range (e.g. 10.10.10.0/24):").ask()
        if not is_valid_ip_or_cidr(target):
            err("Invalid IP/range.")
            raise SystemExit(1)

        ctx["target_type"] = "network"
        ctx["target"] = target.strip()
        ctx["outdir"] = init_output_dirs(base_dir, "network_target")
        ok(f"Target set: {ctx['target']}")

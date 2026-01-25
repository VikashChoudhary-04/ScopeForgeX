import questionary
from scopeforgex.ui import stage, ok

def stage6_reporting(ctx: dict):
    stage("STAGE 6 — REPORTING & CLEANUP", "cyan")

    evidence = questionary.confirm("Is evidence captured?").ask()
    cleanup = questionary.confirm("Cleanup done?").ask()

    report_path = f"{ctx['outdir']}/report.md"
    with open(report_path, "w", encoding="utf-8") as f:
        f.write("# ScopeForgeX Report\n\n")
        f.write(f"Target: {ctx['target']}\n")
        f.write(f"Evidence captured: {evidence}\n")
        f.write(f"Cleanup done: {cleanup}\n")

    ok(f"Report saved: {report_path}")

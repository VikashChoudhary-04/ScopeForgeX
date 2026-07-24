import questionary
from scopeforgex.ui import stage, ok, warn, summary_table
from scopeforgex.workflow import run_profile
from scopeforgex.installer import install_tools
from scopeforgex.state import load_last_run

def dashboard():
    while True:
        stage("ScopeForgeX Dashboard", "green")

        choice = questionary.select(
            "Choose an action:",
            choices=[
                "Run FAST Profile",
                "Run FULL_SAFE Profile",
                "Install Tools",
                "View Last Run",
                "Exit"
            ],
        ).ask()

        if choice == "Run FAST Profile":
            run_profile("fast")

        elif choice == "Run FULL_SAFE Profile":
            run_profile("full_safe")

        elif choice == "Install Tools":
            install_tools()

        elif choice == "View Last Run":
            last = load_last_run()
            if not last:
                warn("No previous run found.")
            else:
                ok("Loaded last run ✅")
                summary_table(
                    "Last Run",
                    [
                        ("Target Type", str(last.get("target_type"))),
                        ("Target", str(last.get("target"))),
                        ("Output Directory", str(last.get("outdir"))),
                    ],
                )

        else:
            ok("Goodbye ✅")
            break

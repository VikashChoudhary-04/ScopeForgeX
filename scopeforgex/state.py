import json
import os

STATE_FILE = os.path.join("outputs", ".last_run.json")

def save_last_run(ctx: dict):
    os.makedirs("outputs", exist_ok=True)
    data = {
        "target_type": ctx.get("target_type"),
        "target": ctx.get("target"),
        "outdir": ctx.get("outdir"),
    }
    with open(STATE_FILE, "w", encoding="utf-8") as f:
        json.dump(data, f, indent=2)

def load_last_run() -> dict | None:
    if not os.path.exists(STATE_FILE):
        return None
    try:
        with open(STATE_FILE, "r", encoding="utf-8") as f:
            return json.load(f)
    except Exception:
        return None

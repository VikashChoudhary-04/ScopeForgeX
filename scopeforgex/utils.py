import os
import yaml
from datetime import datetime


def load_yaml(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return yaml.safe_load(f)


def ensure_dir(path: str):
    os.makedirs(path, exist_ok=True)


def timestamp():
    return datetime.now().strftime("%Y-%m-%d_%H-%M-%S")


def read_file_safe(path: str, max_bytes: int = 200_000) -> str:
    """
    Read a log file safely (limited size) to analyze common errors.
    """
    if not os.path.exists(path):
        return ""
    try:
        with open(path, "rb") as f:
            data = f.read(max_bytes)
        return data.decode("utf-8", errors="ignore")
    except Exception:
        return ""


def analyze_common_blocks(log_text: str) -> list[str]:
    """
    Detect undesired situations like 403, 401, 429, WAF blocks, TLS errors, etc.
    Returns a list of human-readable warnings.
    """
    t = (log_text or "").lower()
    warnings = []

    # HTTP codes / blocks
    if " 403" in t or "forbidden" in t:
        warnings.append("403 Forbidden detected (likely WAF/blocking).")
    if " 401" in t or "unauthorized" in t:
        warnings.append("401 Unauthorized detected (authentication required).")
    if " 429" in t or "too many requests" in t:
        warnings.append("429 Too Many Requests detected (rate limiting).")
    if "access denied" in t:
        warnings.append("Access denied detected (blocked by server/WAF).")

    # Cloudflare / WAF indicators
    if "cloudflare" in t and ("captcha" in t or "attention required" in t):
        warnings.append("Cloudflare protection detected (captcha/WAF).")
    if "waf" in t and ("detected" in t or "blocked" in t):
        warnings.append("WAF blocking detected.")

    # TLS / Network issues
    if "ssl" in t and ("error" in t or "handshake" in t or "certificate" in t):
        warnings.append("SSL/TLS error detected (certificate/handshake issue).")
    if "connection refused" in t:
        warnings.append("Connection refused (target not accepting connections).")
    if "timed out" in t or "timeout" in t:
        warnings.append("Timeout detected (slow target/network filtering).")
    if "no route to host" in t:
        warnings.append("No route to host (network unreachable).")
    if "name or service not known" in t or "temporary failure in name resolution" in t:
        warnings.append("DNS resolution failure detected.")

    # Tool specific
    if "indexerror" in t and "sublist3r" in t:
        warnings.append("Sublist3r crashed (source blocking/page change).")

    return warnings


def build_notes_from_log(log_path: str, base_note: str = "") -> str:
    """
    Creates a clean 'notes' message for UI based on log analysis.
    """
    text = read_file_safe(log_path)
    issues = analyze_common_blocks(text)

    if not issues:
        return base_note.strip() if base_note else "Completed."

    note = base_note.strip() if base_note else "Completed with warnings."
    note += " | " + " ".join([f"[{w}]" for w in issues])
    return note

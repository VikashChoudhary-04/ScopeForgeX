import os

def read_lines(path: str) -> list[str]:
    if not os.path.exists(path):
        return []
    with open(path, "r", encoding="utf-8", errors="ignore") as f:
        return [line.strip() for line in f.readlines() if line.strip()]

def merge_targets(output_path: str, *input_paths: str) -> int:
    seen = set()
    merged = []

    for p in input_paths:
        for line in read_lines(p):
            if line and line not in seen:
                seen.add(line)
                merged.append(line)

    os.makedirs(os.path.dirname(output_path), exist_ok=True)
    with open(output_path, "w", encoding="utf-8") as f:
        f.write("\n".join(merged) + ("\n" if merged else ""))

    return len(merged)

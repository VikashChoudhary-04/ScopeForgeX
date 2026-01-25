import shutil

def is_tool_installed(tool_name: str) -> bool:
    return shutil.which(tool_name) is not None

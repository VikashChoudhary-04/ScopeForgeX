

def test_is_command_available_uses_canonical_executable_resolution(
    monkeypatch,
):
    from scopeforgex.runner import is_command_available

    monkeypatch.setattr(
        "scopeforgex.runner.resolve_executable",
        lambda executable: (
            "/home/kali/go/bin/httpx"
            if executable == "httpx"
            else None
        ),
    )

    assert is_command_available(
        "httpx -status-code"
    ) is True

    assert is_command_available(
        "missing-tool"
    ) is False

def test_nonempty_stderr_is_preserved_without_becoming_warning(monkeypatch):
    from scopeforgex import runner

    class Completed:
        stdout = "clean stdout\n"
        stderr = "progress/status output\n"
        returncode = 0

    monkeypatch.setattr(
        runner.subprocess,
        "run",
        lambda *args, **kwargs: Completed(),
    )

    result = runner.run_command(
        tool="subhunt",
        capability="subdomain_discovery",
        cmd=["subhunt", "-d", "example.com", "--quiet"],
        timeout=10,
    )

    assert result.success is True
    assert result.stdout == "clean stdout\n"
    assert result.stderr == "progress/status output\n"
    assert result.warnings == []

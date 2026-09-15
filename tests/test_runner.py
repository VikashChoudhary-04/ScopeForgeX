

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

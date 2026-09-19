from pathlib import Path


def test_resolver_prefers_go_binary_over_path(monkeypatch):
    from scopeforgex.executable import resolve_executable

    monkeypatch.setenv(
        "PATH",
        "/does/not/exist",
    )

    expected = Path.home() / "go" / "bin" / "httpx"

    assert resolve_executable("httpx") == str(expected)


def test_resolver_uses_supplied_path_when_go_binary_is_absent(
    tmp_path,
):
    from scopeforgex.executable import resolve_executable

    fake_bin = tmp_path / "fake-tool"
    fake_bin.write_text("#!/bin/sh\n")
    fake_bin.chmod(0o755)

    assert resolve_executable(
        "fake-tool",
        env={"PATH": str(tmp_path)},
    ) == str(fake_bin)


def test_resolver_rejects_non_executable_explicit_path(
    tmp_path,
):
    from scopeforgex.executable import resolve_executable

    fake_bin = tmp_path / "fake-tool"
    fake_bin.write_text("not executable\n")
    fake_bin.chmod(0o644)

    assert resolve_executable(
        str(fake_bin)
    ) is None


def test_resolver_prefers_invoking_users_go_binary_under_sudo(
    monkeypatch,
):
    from scopeforgex.executable import resolve_executable

    monkeypatch.setenv(
        "HOME",
        "/root",
    )
    monkeypatch.setenv(
        "SUDO_USER",
        "kali",
    )
    monkeypatch.setenv(
        "PATH",
        "/usr/local/bin:/usr/bin:/bin",
    )

    expected = Path(
        "/home/kali/go/bin/httpx"
    )

    assert resolve_executable(
        "httpx"
    ) == str(expected)


def test_resolver_uses_sudo_user_from_supplied_environment(
    monkeypatch,
):
    from scopeforgex.executable import resolve_executable

    monkeypatch.setenv(
        "HOME",
        "/root",
    )
    monkeypatch.delenv(
        "SUDO_USER",
        raising=False,
    )

    expected = Path(
        "/home/kali/go/bin/katana"
    )

    assert resolve_executable(
        "katana",
        env={
            "HOME": "/root",
            "SUDO_USER": "kali",
            "PATH": "/usr/local/bin:/usr/bin:/bin",
        },
    ) == str(expected)

from pathlib import Path

from scopeforgex.collectors.subhunt import SubhuntCollector
from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage1_recon_web import SubhuntTool


def _context(
    target: str = "https://example.com/",
    options: dict | None = None,
) -> ToolContext:
    return ToolContext(
        target=target,
        output_dir=Path("/tmp/scopeforgex-subhunt-test"),
        options=options or {},
    )


def _execution_result(stdout: str) -> ExecutionResult:
    return ExecutionResult.success_result(
        tool="subhunt",
        capability="subdomain_discovery",
        stdout=stdout,
        stderr="",
        artifacts=[],
    )


def test_subhunt_adapter_always_uses_long_quiet_flag():
    arguments = SubhuntTool(
        _context()
    ).build_arguments()

    assert "--quiet" in arguments
    assert arguments.count("--quiet") == 1
    assert "-quiet" not in arguments


def test_subhunt_adapter_preserves_optional_execution_arguments(tmp_path):
    wordlist = tmp_path / "subdomains.txt"
    wordlist.write_text(
        "api\n"
        "mail\n"
        "admin\n",
        encoding="utf-8",
    )

    arguments = SubhuntTool(
        _context(
            options={
                "wordlist": str(wordlist),
                "threads": 20,
                "timeout": 15,
            }
        )
    ).build_arguments()

    assert arguments == [
        "-d",
        "example.com",
        "--bruteforce",
        str(wordlist),
        "--quiet",
        "--threads",
        "20",
        "--timeout",
        "15",
    ]


def test_subhunt_collector_removes_plus_marker_and_creates_subdomain_finding():
    collector = SubhuntCollector()

    result = collector.collect(
        _execution_result(
            "[+] api.example.com\n"
        )
    )

    observations = result.observations

    assert len(observations) == 1

    observation = observations[0].as_dict()

    assert observation["observation_type"] == "subdomain"
    assert observation["value"] == "api.example.com"


def test_subhunt_collector_accepts_clean_quiet_output():
    collector = SubhuntCollector()

    result = collector.collect(
        _execution_result(
            "api.example.com\n"
            "mail.example.com\n"
            "admin.example.com\n"
        )
    )

    observations = result.observations

    assert [
        observation.as_dict()["value"]
        for observation in observations
    ] == [
        "api.example.com",
        "mail.example.com",
        "admin.example.com",
    ]

    assert all(
        observation.as_dict()["observation_type"] == "subdomain"
        for observation in observations
    )


def test_subhunt_collector_ignores_status_lines_but_keeps_discovered_subdomains():
    collector = SubhuntCollector()

    result = collector.collect(
        _execution_result(
            "Starting Subhunt\n"
            "Progress: 25%\n"
            "[+] api.example.com\n"
            "Testing: example.com\n"
            "[+] admin.example.com\n"
            "Completed\n"
        )
    )

    observations = result.observations

    assert [
        observation.as_dict()["value"]
        for observation in observations
    ] == [
        "api.example.com",
        "admin.example.com",
    ]


def test_subhunt_collector_deduplicates_marked_and_clean_results():
    collector = SubhuntCollector()

    result = collector.collect(
        _execution_result(
            "[+] api.example.com\n"
            "api.example.com\n"
            "[+] API.EXAMPLE.COM\n"
        )
    )

    observations = result.observations

    assert len(observations) == 1
    assert observations[0].as_dict()["value"] == "api.example.com"

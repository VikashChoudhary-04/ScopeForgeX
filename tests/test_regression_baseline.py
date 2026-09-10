from __future__ import annotations

import inspect
import json
from pathlib import Path
from shlex import split as shlex_split

from scopeforgex.analyzers import NativeAnalyzerEngine
from scopeforgex.collectors.registry import (
    create_collector,
    get_collector_class,
    get_registered_collectors,
)
from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.registry.tool_registry import (
    get_registered_tools,
    get_tool_definition,
)
from scopeforgex.workflow import WorkflowEngine, _load_profile


EXPECTED_TOOLS = {
    "amass",
    "subhunt",
    "nmap",
    "dig",
    "httpx",
    "katana",
    "ffuf",
    "whatweb",
    "kiterunner",
    "jsluice",
    "nuclei",
    "nikto",
    "testssl.sh",
    "sqlmap",
    "dalfox",
    "jwt_tool",
    "sstimap",
    "hydra",
    "hashcat",
}

EXPECTED_COLLECTORS = {
    "amass",
    "subhunt",
    "nmap",
    "dig",
    "httpx",
    "katana",
    "ffuf",
    "whatweb",
    "kiterunner",
    "jsluice",
    "nuclei",
    "nikto",
    "testssl",
    "sqlmap",
    "dalfox",
    "jwt_tool",
    "sstimap",
    "hydra",
    "hashcat",
}

EXPECTED_ANALYZERS = {
    "http_security_headers",
    "cookies",
    "cors",
    "http_methods",
    "sensitive_information",
    "api",
    "software_identity",
}

SMOKE_OUTPUTS = {
    "amass": "api.example.com\n",
    "dalfox": (
        "[POC] [https://example.com/?q=test] payload\n"
    ),
    "dig": "example.com. 300 IN A 93.184.216.34\n",
    "ffuf": (
        "[http://example.com/admin] [Status: 200]\n"
    ),
    "hashcat": "hash:password\n",
    "httpx": (
        '{"url":"https://example.com","status_code":200}\n'
    ),
    "hydra": (
        "[443][https] host: example.com login: admin password: test\n"
    ),
    "jsluice": (
        '{"type":"url","url":"https://example.com/api"}\n'
    ),
    "jwt_tool": "Vulnerability: algorithm confusion\n",
    "katana": "https://example.com/api\n",
    "kiterunner": "https://example.com/api [200]\n",
    "nikto": "+ Server: nginx\n",
    "nmap": "80/tcp open http\n",
    "nuclei": "[medium] test [http] [https://example.com]\n",
    "sqlmap": "Parameter: id (GET)\n",
    "sstimap": "parameter is vulnerable\n",
    "subhunt": "api.example.com\n",
    "testssl": "HTTP Strict Transport Security: NOT offered\n",
    "whatweb": "https://example.com [200 OK]\n",
}


def _execution_result(
    tool: str,
    stdout: str,
) -> ExecutionResult:
    return ExecutionResult.success_result(
        tool=tool,
        capability=f"test_{tool}",
        stdout=stdout,
        stderr="",
        artifacts=[],
    )


def _collector_context(
    tool: str,
) -> dict[str, object]:
    return {
        "target": "example.com",
        "tool": tool,
        "tool_options": {},
        "options": {},
        "command": [],
    }


def _mock_run_command(
    *args: object,
    **kwargs: object,
) -> ExecutionResult:
    """
    Return deterministic smoke output instead of launching an external tool.

    The real workflow, ToolExecutor, collectors, native analyzers and
    reporting layers remain active. Only the external process-execution
    boundary is replaced for regression testing.
    """

    command = kwargs.get("cmd")

    if command is None and args:
        command = args[0]

    if isinstance(command, (list, tuple)):
        argv = [
            str(value)
            for value in command
        ]

    elif isinstance(command, str):
        argv = shlex_split(command)

    else:
        argv = []

    executable = (
        Path(argv[0]).name.lower()
        if argv
        else ""
    )

    if executable == "httpx":
        tool = "httpx"

    elif executable == "nuclei":
        tool = "nuclei"

    elif executable == "subhunt":
        tool = "subhunt"

    else:
        tool = executable

    stdout = SMOKE_OUTPUTS.get(
        tool,
        "",
    )

    return _execution_result(
        tool,
        stdout,
    )


def _run_fast_workflow_without_external_tools(
    monkeypatch,
    tmp_path: Path,
) -> dict[str, object]:
    """
    Execute the real fast workflow with all external process execution mocked.

    Fast-profile adapters may either delegate through ToolExecutor or own a
    custom ``run()`` implementation. Patch both execution boundaries so the
    test cannot launch real external processes.
    """

    import scopeforgex.runner as runner
    import scopeforgex.tools.stage1_recon_web as stage1_recon_web
    import scopeforgex.tools.stage3_vuln as stage3_vuln

    monkeypatch.setattr(
        runner,
        "run_command",
        _mock_run_command,
    )

    monkeypatch.setattr(
        stage1_recon_web,
        "run_command",
        _mock_run_command,
    )

    monkeypatch.setattr(
        stage1_recon_web,
        "is_tool_installed",
        lambda *_args, **_kwargs: True,
    )

    monkeypatch.setattr(
        stage3_vuln,
        "run_command",
        _mock_run_command,
    )

    monkeypatch.setattr(
        stage3_vuln,
        "is_tool_installed",
        lambda *_args, **_kwargs: True,
    )

    engine = WorkflowEngine(
        "fast"
    )

    engine.ctx.update(
        {
            "non_interactive": True,
            "authorization_confirmed": True,
            "target": "example.com",
            "target_type": "web",
            "outdir": str(tmp_path),
        }
    )

    return engine.run()


def test_tool_registry_places_katana_before_httpx() -> None:
    names = list(
        get_registered_tools()
    )

    assert names.index("katana") < names.index("httpx")


def test_tool_registry_contains_expected_tools() -> None:
    tools = set(
        get_registered_tools()
    )

    assert tools == EXPECTED_TOOLS
    assert len(tools) == 19

    for name in sorted(tools):
        definition = get_tool_definition(
            name
        )

        assert definition.name == name
        assert definition.factory is not None
        assert definition.capability
        assert definition.phase
        assert definition.input_type
        assert definition.output_type


def test_all_collectors_are_registered_and_instantiable() -> None:
    collectors = set(
        get_registered_collectors()
    )

    assert collectors == EXPECTED_COLLECTORS
    assert len(collectors) == 19

    for name in sorted(collectors):
        collector_class = get_collector_class(
            name
        )

        assert not inspect.isabstract(
            collector_class
        )

        assert callable(
            getattr(
                collector_class,
                "parse",
                None,
            )
        )

        assert callable(
            getattr(
                collector_class,
                "collect",
                None,
            )
        )

        collector = create_collector(
            name
        )

        assert collector is not None

        assert callable(
            getattr(
                collector,
                "parse",
                None,
            )
        )

        assert callable(
            getattr(
                collector,
                "collect",
                None,
            )
        )


def test_testssl_alias_resolves_to_canonical_collector() -> None:
    canonical = get_collector_class(
        "testssl"
    )

    executable_alias = get_collector_class(
        "testssl.sh"
    )

    assert executable_alias is canonical

    canonical_instance = create_collector(
        "testssl"
    )

    alias_instance = create_collector(
        "testssl.sh"
    )

    assert type(
        alias_instance
    ) is type(
        canonical_instance
    )


def test_all_collectors_expose_canonical_parse_signature() -> None:
    for name in sorted(
        get_registered_collectors()
    ):
        collector = create_collector(
            name
        )

        signature = inspect.signature(
            collector.parse
        )

        parameters = list(
            signature.parameters.values()
        )

        assert len(parameters) == 2
        assert parameters[0].name == "execution_result"
        assert parameters[1].name == "ctx"


def test_all_collectors_parse_smoke_inputs() -> None:
    failures: list[
        tuple[str, str, str]
    ] = []

    for name, stdout in SMOKE_OUTPUTS.items():
        try:
            collector = create_collector(
                name
            )

            result = _execution_result(
                name,
                stdout,
            )

            observations = collector.parse(
                result,
                _collector_context(
                    name
                ),
            )

            assert isinstance(
                observations,
                list,
            )

            for observation in observations:
                assert hasattr(
                    observation,
                    "as_dict",
                )

                data = observation.as_dict()

                assert isinstance(
                    data,
                    dict,
                )

                assert (
                    "observation_type"
                    in data
                )

                assert (
                    "source_tool"
                    in data
                )

                assert (
                    "evidence"
                    in data
                )

        except Exception as exc:
            failures.append(
                (
                    name,
                    type(exc).__name__,
                    str(exc),
                )
            )

    assert not failures, failures


def test_native_analyzer_engine_contains_exactly_seven_analyzers() -> None:
    engine = NativeAnalyzerEngine()

    names = set(
        engine.analyzer_names()
    )

    assert names == EXPECTED_ANALYZERS
    assert len(names) == 7


def test_native_analyzer_profile_selection() -> None:
    workflow = WorkflowEngine(
        "fast"
    )

    enabled = (
        workflow.executor._native_analyzers_enabled(
            workflow.ctx
        )
    )

    assert enabled == EXPECTED_ANALYZERS

    filtered = (
        workflow.executor._native_analyzer_engine(
            workflow.executor.native_analyzer_engine,
            workflow.ctx,
        )
    )

    assert set(
        filtered.analyzer_names()
    ) == EXPECTED_ANALYZERS

    assert len(
        filtered.analyzer_names()
    ) == 7


def test_all_profiles_enable_seven_native_analyzers() -> None:
    for profile_name in (
        "fast",
        "standard",
        "full",
    ):
        profile = _load_profile(
            profile_name
        )

        native = profile.get(
            "native_analyzers"
        )

        assert isinstance(
            native,
            dict,
        )

        assert len(native) == 7

        for name in (
            "security_headers",
            "cookies",
            "cors",
            "http_methods",
            "sensitive_files",
            "api",
            "software_identity",
        ):
            assert name in native
            assert isinstance(
                native[name],
                dict,
            )
            assert (
                native[name].get(
                    "enabled"
                )
                is True
            )


def test_native_analyzer_smoke_produces_findings() -> None:
    engine = NativeAnalyzerEngine()

    evidence = {
        "target": "https://example.com/",
        "url": "https://example.com/",
        "host": "example.com",
        "headers": {
            "Set-Cookie": (
                "session=secret; Path=/"
            ),
            "Access-Control-Allow-Origin": "*",
            "Access-Control-Allow-Credentials": (
                "true"
            ),
            "Allow": "GET, POST, TRACE",
        },
        "set_cookie": (
            "session=secret; Path=/"
        ),
        "methods": [
            "GET",
            "POST",
            "TRACE",
        ],
        "request_headers": {
            "Origin": (
                "https://attacker.example"
            ),
        },
    }

    results = engine.analyze_with_results(
        evidence
    )

    assert len(results) == 7

    assert all(
        result.success
        for result in results
    )

    finding_count = sum(
        len(result.findings)
        for result in results
    )

    assert finding_count > 0


def test_workflow_native_state_for_fast_profile(
    monkeypatch,
    tmp_path: Path,
) -> None:
    result = _run_fast_workflow_without_external_tools(
        monkeypatch,
        tmp_path,
    )

    execution_results = result[
        "execution_results"
    ]

    collector_results = result[
        "collector_results"
    ]

    native_results = result.get(
        "native_analyzer_results"
    )

    assert len(
        execution_results
    ) == 3

    assert len(
        collector_results
    ) == 3

    assert isinstance(
        native_results,
        list,
    )

    assert len(
        native_results
    ) == 21

    assert {
        item.tool
        for item in execution_results
    } == {
        "subhunt",
        "httpx",
        "nuclei",
    }

    for item in execution_results:
        metadata = item.metadata

        assert "collector" in metadata
        assert "collector_result" in metadata
        assert "native_analyzers" in metadata

        native = metadata[
            "native_analyzers"
        ]

        assert native[
            "analyzer_count"
        ] == 7

        assert len(
            native["results"]
        ) == 7

        for analyzer_result in native[
            "results"
        ]:
            assert "analyzer" in analyzer_result
            assert "success" in analyzer_result
            assert "findings" in analyzer_result
            assert "errors" in analyzer_result

            assert (
                analyzer_result[
                    "success"
                ]
                is True
            )

    assert {
        item.analyzer
        for item in native_results
    } == EXPECTED_ANALYZERS


def test_fast_workflow_generates_valid_reports(
    monkeypatch,
    tmp_path: Path,
) -> None:
    result = _run_fast_workflow_without_external_tools(
        monkeypatch,
        tmp_path,
    )

    report_paths = result[
        "report_paths"
    ]

    markdown_path = Path(
        report_paths["markdown"]
    )

    json_path = Path(
        report_paths["json"]
    )

    assert markdown_path.is_file()
    assert json_path.is_file()

    report = json.loads(
        json_path.read_text(
            encoding="utf-8"
        )
    )

    assert report[
        "target"
    ] == "example.com"

    assert report[
        "profile"
    ] == "fast"

    assert report[
        "target_type"
    ] == "web"

    assert len(
        report[
            "execution_results"
        ]
    ) == 3

    assert len(
        report[
            "collector_results"
        ]
    ) == 3

    assert "findings" in report
    assert "statistics" in report

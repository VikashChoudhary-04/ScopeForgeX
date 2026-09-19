from pathlib import Path

from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage3_vuln import (
    NiktoTool,
    _execution_timeout,
)
from scopeforgex.workflow import _create_tool_context


def test_create_nikto_context_injects_execution_timeout(tmp_path):
    ctx = {
        "target": "example.com",
        "outdir": str(tmp_path),
        "profile": "standard",
    }

    profile = {
        "vulnerability": {
            "nikto": {
                "enabled": True,
                "options": {
                    "timeout": 10,
                    "tuning": "123",
                },
            },
        },
    }

    context = _create_tool_context(
        ctx,
        NiktoTool.definition,
        profile,
        execution_timeout=600,
    )

    assert isinstance(context, ToolContext)
    assert context.options["timeout"] == 10
    assert context.options["tool_timeout"] == 600
    assert context.options["tuning"] == "123"

def test_create_nikto_context_preserves_explicit_tool_timeout(tmp_path):
    ctx = {
        "target": "example.com",
        "outdir": str(tmp_path),
        "profile": "standard",
    }

    profile = {
        "vulnerability": {
            "nikto": {
                "enabled": True,
                "options": {
                    "timeout": 10,
                    "tool_timeout": 900,
                },
            },
        },
    }

    context = _create_tool_context(
        ctx,
        NiktoTool.definition,
        profile,
        execution_timeout=600,
    )

    assert context.options["timeout"] == 10
    assert context.options["tool_timeout"] == 900

def test_execution_timeout_uses_tool_timeout():
    context = ToolContext(
        target="example.com",
        output_dir=Path("."),
        options={
            "timeout": 10,
            "tool_timeout": 600,
        },
    )

    assert _execution_timeout(context, 600) == 600


def test_execution_timeout_falls_back_without_tool_timeout():
    context = ToolContext(
        target="example.com",
        output_dir=Path("."),
        options={
            "timeout": 10,
        },
    )

    assert _execution_timeout(context, 600) == 600


def test_workflow_engine_uses_profile_execution_timeout():
    from scopeforgex.workflow import WorkflowEngine

    expected = {
        "fast": 300,
        "standard": 600,
        "full": 1200,
    }

    for profile_name, timeout in expected.items():
        engine = WorkflowEngine(profile_name)

        assert engine.executor.default_timeout == timeout
        assert engine.profile["execution"]["timeout"] == timeout


def test_workflow_engine_rejects_invalid_profile_execution_timeout(
    monkeypatch,
):
    from scopeforgex import workflow

    invalid_profile = {
        "execution": {
            "continue_on_error": True,
            "timeout": 0,
        },
        "vulnerability_intelligence": {
            "allow_network": False,
        },
    }

    monkeypatch.setattr(
        workflow,
        "_load_profile",
        lambda profile_name: invalid_profile,
    )

    try:
        workflow.WorkflowEngine("standard")
    except SystemExit as exc:
        assert "Invalid execution timeout" in str(exc)
    else:
        raise AssertionError(
            "WorkflowEngine accepted a non-positive execution timeout."
        )

from pathlib import Path

from scopeforgex.registry.tool_base import ToolContext
from scopeforgex.tools.stage3_vuln import (
    NucleiTool,
    _execution_timeout,
)
from scopeforgex.workflow import _create_tool_context


def test_create_nuclei_context_injects_execution_timeout(tmp_path):
    ctx = {
        "target": "example.com",
        "outdir": str(tmp_path),
        "profile": "standard",
    }

    profile = {
        "vulnerability": {
            "nuclei": {
                "enabled": True,
                "options": {
                    "severity": [
                        "info",
                        "low",
                        "medium",
                        "high",
                        "critical",
                    ],
                    "rate_limit": 100,
                    "timeout": 10,
                    "retries": 2,
                },
            },
        },
    }

    context = _create_tool_context(
        ctx,
        NucleiTool.definition,
        profile,
        execution_timeout=600,
    )

    assert isinstance(context, ToolContext)
    assert context.options["timeout"] == 10
    assert context.options["tool_timeout"] == 600
    assert context.options["rate_limit"] == 100
    assert context.options["retries"] == 2
    assert context.options["severity"] == [
        "info",
        "low",
        "medium",
        "high",
        "critical",
    ]


def test_create_nuclei_context_preserves_explicit_tool_timeout(tmp_path):
    ctx = {
        "target": "example.com",
        "outdir": str(tmp_path),
        "profile": "standard",
    }

    profile = {
        "vulnerability": {
            "nuclei": {
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
        NucleiTool.definition,
        profile,
        execution_timeout=600,
    )

    assert context.options["timeout"] == 10
    assert context.options["tool_timeout"] == 900


def test_nuclei_execution_timeout_uses_tool_timeout():
    context = ToolContext(
        target="example.com",
        output_dir=Path("."),
        options={
            "timeout": 10,
            "tool_timeout": 600,
        },
    )

    assert _execution_timeout(context, 600) == 600


def test_nuclei_execution_timeout_falls_back_without_tool_timeout():
    context = ToolContext(
        target="example.com",
        output_dir=Path("."),
        options={
            "timeout": 10,
        },
    )

    assert _execution_timeout(context, 600) == 600

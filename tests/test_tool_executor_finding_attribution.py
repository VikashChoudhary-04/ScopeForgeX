from __future__ import annotations

from scopeforgex.findings.model import Finding
from scopeforgex.models.execution_result import ExecutionResult
from scopeforgex.runtime.tool_executor import ToolExecutor


def _finding(
    *,
    title: str,
    category: str,
    host: str = "example.test",
    source_tool: str = "test-tool",
) -> Finding:
    return Finding.from_mapping(
        {
            "title": title,
            "category": category,
            "description": f"{title} description",
            "severity": "Low",
            "confidence": "High",
            "status": "Pending",
            "host": host,
            "source_tool": source_tool,
            "detection_method": "test",
        }
    )


def test_execution_findings_do_not_inherit_previous_assessment_findings():
    executor = ToolExecutor()

    first = _finding(
        title="First finding",
        category="FIRST_TEST_FINDING",
        source_tool="tool-one",
    )

    second = _finding(
        title="Second finding",
        category="SECOND_TEST_FINDING",
        source_tool="tool-two",
    )

    first_result = ExecutionResult(
        tool="tool-one",
        capability="test",
        success=True,
    )

    second_result = ExecutionResult(
        tool="tool-two",
        capability="test",
        success=True,
    )

    first_context = {
        "findings": [],
        "correlation_groups": [],
        "analysis_result": {},
        "analysis": {},
    }

    first_analysis = executor._analyze_observations(
        [first],
        context=first_context,
    )

    executor._attach_analysis_result(
        first_result,
        first_analysis,
        first_context,
        execution_observations=[first],
    )

    assert len(first_result.findings) == 1
    assert first_result.findings[0].category == "FIRST_TEST_FINDING"

    second_analysis = executor._analyze_observations(
        [second],
        context=first_context,
    )

    executor._attach_analysis_result(
        second_result,
        second_analysis,
        first_context,
        execution_observations=[second],
    )

    assert len(second_result.findings) == 1
    assert second_result.findings[0].category == "SECOND_TEST_FINDING"

    assert all(
        finding.category != "FIRST_TEST_FINDING"
        for finding in second_result.findings
    )

    assert len(first_context["findings"]) == 2
    assert {
        finding.category
        for finding in first_context["findings"]
    } == {
        "FIRST_TEST_FINDING",
        "SECOND_TEST_FINDING",
    }


def test_cross_tool_duplicate_maps_to_same_canonical_finding():
    executor = ToolExecutor()

    first = _finding(
        title="Shared finding",
        category="SHARED_TEST_FINDING",
        source_tool="tool-one",
    )

    duplicate = _finding(
        title="Shared finding",
        category="SHARED_TEST_FINDING",
        source_tool="tool-two",
    )

    first_result = ExecutionResult(
        tool="tool-one",
        capability="test",
        success=True,
    )

    second_result = ExecutionResult(
        tool="tool-two",
        capability="test",
        success=True,
    )

    context = {
        "findings": [],
        "correlation_groups": [],
        "analysis_result": {},
        "analysis": {},
    }

    first_analysis = executor._analyze_observations(
        [first],
        context=context,
    )

    executor._attach_analysis_result(
        first_result,
        first_analysis,
        context,
        execution_observations=[first],
    )

    second_analysis = executor._analyze_observations(
        [duplicate],
        context=context,
    )

    executor._attach_analysis_result(
        second_result,
        second_analysis,
        context,
        execution_observations=[duplicate],
    )

    assert len(context["findings"]) == 1
    assert len(first_result.findings) == 1
    assert len(second_result.findings) == 1

    assert (
        first_result.findings[0]
        is second_result.findings[0]
    )

    assert (
        first_result.findings[0]
        is context["findings"][0]
    )


def test_execution_finding_metadata_is_local_while_analysis_is_assessment_wide():
    executor = ToolExecutor()

    first = _finding(
        title="First finding",
        category="FIRST_METADATA_TEST",
        source_tool="tool-one",
    )

    second = _finding(
        title="Second finding",
        category="SECOND_METADATA_TEST",
        source_tool="tool-two",
    )

    result = ExecutionResult(
        tool="tool-two",
        capability="test",
        success=True,
    )

    context = {
        "findings": [],
        "correlation_groups": [],
        "analysis_result": {},
        "analysis": {},
    }

    executor._analyze_observations(
        [first],
        context=context,
    )

    analysis = executor._analyze_observations(
        [second],
        context=context,
    )

    executor._attach_analysis_result(
        result,
        analysis,
        context,
        execution_observations=[second],
    )

    assert {
        finding.category
        for finding in context["findings"]
    } == {
        "FIRST_METADATA_TEST",
        "SECOND_METADATA_TEST",
    }

    assert [
        finding["category"]
        for finding in result.metadata["findings"]
    ] == [
        "SECOND_METADATA_TEST"
    ]

    assert [
        finding["category"]
        for finding in result.metadata["analysis"]["findings"]
    ] == [
        "SECOND_METADATA_TEST"
    ]
